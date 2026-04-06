// Package capture provides HTTP traffic recording and replay for attestation
// verification. RecordingTransport wraps an http.RoundTripper to record every
// request/response pair. ReplayTransport serves saved responses for
// re-verification. Save/Load handle the on-disk format.
package capture

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/13rac1/teep/internal/jsonstrict"
)

// RecordedEntry holds metadata for one HTTP request/response pair.
// Body is saved separately as a .body file (not JSON-encoded).
type RecordedEntry struct {
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	Status     int         `json:"status"`
	Proto      string      `json:"proto,omitempty"`
	TLSVersion string      `json:"tls_version,omitempty"`
	TLSCipher  string      `json:"tls_cipher,omitempty"`
	Headers    http.Header `json:"headers"`
	ReqBody    []byte      `json:"req_body_base64,omitempty"`
	Body       []byte      `json:"-"`
}

// E2EEOutcome records the result of a live E2EE test for capture/replay.
// This is a serializable mirror of attestation.E2EETestResult (which contains
// an error interface and lives in a different package).
type E2EEOutcome struct {
	Attempted bool   `json:"attempted"`
	NoAPIKey  bool   `json:"no_api_key,omitempty"`
	APIKeyEnv string `json:"api_key_env,omitempty"`
	Failed    bool   `json:"failed,omitempty"`
	ErrMsg    string `json:"error,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Manifest holds top-level metadata for a capture directory.
type Manifest struct {
	Provider   string       `json:"provider"`
	Model      string       `json:"model"`
	NonceHex   string       `json:"nonce_hex"`
	CapturedAt time.Time    `json:"captured_at"`
	E2EE       *E2EEOutcome `json:"e2ee,omitempty"`
}

// RecordingTransport wraps a base RoundTripper and records all request/response pairs.
type RecordingTransport struct {
	Base    http.RoundTripper
	mu      sync.Mutex
	Entries []RecordedEntry
}

// WrapRecording wraps base with a RecordingTransport.
func WrapRecording(base http.RoundTripper) *RecordingTransport {
	return &RecordingTransport{Base: base}
}

const maxRecordBody = 10 << 20 // 10 MiB

// RoundTrip executes the request via the base transport and records the exchange.
func (t *RecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Read request body for recording (small POST bodies only).
	var reqBody []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		reqBody, err = io.ReadAll(io.LimitReader(req.Body, maxRecordBody))
		if err != nil {
			return nil, err
		}
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
	}

	resp, err := t.Base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Read response body for recording, then replace with a new reader.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRecordBody))
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))

	entry := RecordedEntry{
		Method:  req.Method,
		URL:     req.URL.String(),
		Status:  resp.StatusCode,
		Proto:   resp.Proto,
		Headers: resp.Header.Clone(),
		ReqBody: reqBody,
		Body:    body,
	}
	if resp.TLS != nil {
		entry.TLSVersion = tlsVersionName(resp.TLS.Version)
		entry.TLSCipher = tls.CipherSuiteName(resp.TLS.CipherSuite)
	}

	t.mu.Lock()
	t.Entries = append(t.Entries, entry)
	t.mu.Unlock()

	return resp, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// ReplayTransport serves saved HTTP responses. Matches by method+URL.
// POST requests also match by request body SHA-256. Unmatched requests
// return an error (fail-closed).
type replayTransport struct {
	entries []RecordedEntry
}

// NewReplayTransport creates a transport that serves saved responses.
func NewReplayTransport(entries []RecordedEntry) http.RoundTripper {
	return &replayTransport{entries: entries}
}

func (t *replayTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var reqBody []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		// Use maxRecordBody (not maxCaptureFile) because request bodies in replay
		// originate from the same recording pipeline and share its size limit.
		reqBody, err = io.ReadAll(io.LimitReader(req.Body, maxRecordBody))
		if err != nil {
			return nil, err
		}
		req.Body.Close()
	}

	for i := range t.entries {
		e := &t.entries[i]
		if e.Method != req.Method || e.URL != req.URL.String() {
			continue
		}
		if req.Method == http.MethodPost {
			switch {
			case len(e.ReqBody) == 0 && len(reqBody) == 0:
				slog.WarnContext(req.Context(), "replay: POST match with both bodies empty",
					"url", e.URL)
			case len(e.ReqBody) == 0 || len(reqBody) == 0:
				continue // Asymmetric body — not a match.
			default:
				a, b := sha256.Sum256(e.ReqBody), sha256.Sum256(reqBody)
				if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
					continue
				}
			}
		}
		slog.DebugContext(req.Context(), "replay hit",
			"method", e.Method,
			"url", e.URL,
			"status", e.Status,
			"body_len", len(e.Body),
		)
		return &http.Response{
			StatusCode:    e.Status,
			Status:        fmt.Sprintf("%d %s", e.Status, http.StatusText(e.Status)),
			Proto:         e.Proto,
			Header:        e.Headers.Clone(),
			Body:          io.NopCloser(bytes.NewReader(e.Body)),
			ContentLength: int64(len(e.Body)),
		}, nil
	}
	return nil, fmt.Errorf("replay: no matching entry for %s %s", req.Method, req.URL)
}

// Save writes a capture to dir, creating a timestamped subdirectory.
// Returns the path to the created subdirectory.
func Save(dir string, m *Manifest, reportText string, entries []RecordedEntry) (string, error) {
	slug := slugify(m.Model)
	ts := m.CapturedAt.Format("20060102_150405")
	subdir := filepath.Join(dir, fmt.Sprintf("%s_%s_%s", m.Provider, slug, ts))

	respDir := filepath.Join(subdir, "responses")
	if err := os.MkdirAll(respDir, 0o750); err != nil {
		return "", fmt.Errorf("create capture dir: %w", err)
	}

	// Write manifest.
	mJSON, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "manifest.json"), mJSON, 0o600); err != nil {
		return "", fmt.Errorf("write manifest: %w", err)
	}

	// Write report.
	if err := os.WriteFile(filepath.Join(subdir, "report.txt"), []byte(reportText), 0o600); err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}

	// Write each response as a .json metadata + .body pair.
	for i := range entries {
		e := &entries[i]
		basename := fmt.Sprintf("%04d_%s", i+1, hostSlug(e.URL))

		// Metadata JSON (without body).
		metaJSON, err := json.MarshalIndent(entryMeta{
			Method:     e.Method,
			URL:        e.URL,
			Status:     e.Status,
			Proto:      e.Proto,
			TLSVersion: e.TLSVersion,
			TLSCipher:  e.TLSCipher,
			Headers:    e.Headers,
			ReqBody:    base64Encode(e.ReqBody),
		}, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshal entry %d: %w", i, err)
		}
		if err := os.WriteFile(filepath.Join(respDir, basename+".json"), metaJSON, 0o600); err != nil {
			return "", fmt.Errorf("write entry %d metadata: %w", i, err)
		}

		// Raw body bytes.
		if err := os.WriteFile(filepath.Join(respDir, basename+".body"), e.Body, 0o600); err != nil {
			return "", fmt.Errorf("write entry %d body: %w", i, err)
		}
	}

	return subdir, nil
}

// entryMeta is the JSON-serialized metadata for one response.
type entryMeta struct {
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	Status     int         `json:"status"`
	Proto      string      `json:"proto,omitempty"`
	TLSVersion string      `json:"tls_version,omitempty"`
	TLSCipher  string      `json:"tls_cipher,omitempty"`
	Headers    http.Header `json:"headers"`
	ReqBody    string      `json:"req_body_base64,omitempty"`
}

func base64Encode(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// maxCaptureFile is the maximum size for any single file read from a capture
// directory. This prevents OOM from a maliciously large file on disk.
const maxCaptureFile = 10 << 20 // 10 MiB

// readFileBounded reads a file up to maxCaptureFile bytes. Returns an error
// if the file exceeds the limit.
func readFileBounded(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // user-provided capture path, bounded by LimitReader below
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxCaptureFile+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxCaptureFile {
		return nil, fmt.Errorf("%s: file exceeds %d-byte limit", path, maxCaptureFile)
	}
	return data, nil
}

// Load reads a capture directory and returns the manifest and recorded entries.
func Load(dir string) (Manifest, []RecordedEntry, error) {
	mData, err := readFileBounded(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("read manifest: %w", err)
	}
	var m Manifest
	if err := jsonstrict.UnmarshalWarn(mData, &m, "capture manifest"); err != nil {
		return Manifest{}, nil, fmt.Errorf("parse manifest: %w", err)
	}

	respDir := filepath.Join(dir, "responses")
	jsonFiles, err := filepath.Glob(filepath.Join(respDir, "*.json"))
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("glob responses: %w", err)
	}
	// Lexicographic sort matches numeric order because entries use zero-padded
	// four-digit prefixes (0001_, 0002_, ...).
	sort.Strings(jsonFiles)

	var entries []RecordedEntry
	for _, jf := range jsonFiles {
		metaData, err := readFileBounded(jf)
		if err != nil {
			return Manifest{}, nil, fmt.Errorf("read %s: %w", jf, err)
		}
		var meta entryMeta
		if err := jsonstrict.UnmarshalWarn(metaData, &meta, "capture entry"); err != nil {
			return Manifest{}, nil, fmt.Errorf("parse %s: %w", jf, err)
		}

		bodyFile := strings.TrimSuffix(jf, ".json") + ".body"
		body, err := readFileBounded(bodyFile)
		if err != nil {
			return Manifest{}, nil, fmt.Errorf("read %s: %w", bodyFile, err)
		}

		var reqBody []byte
		if meta.ReqBody != "" {
			reqBody, err = base64.StdEncoding.DecodeString(meta.ReqBody)
			if err != nil {
				return Manifest{}, nil, fmt.Errorf("decode req_body in %s: %w", jf, err)
			}
		}

		entries = append(entries, RecordedEntry{
			Method:     meta.Method,
			URL:        meta.URL,
			Status:     meta.Status,
			Proto:      meta.Proto,
			TLSVersion: meta.TLSVersion,
			TLSCipher:  meta.TLSCipher,
			Headers:    meta.Headers,
			ReqBody:    reqBody,
			Body:       body,
		})
	}

	return m, entries, nil
}

// slugify converts a model name to a filesystem-safe slug.
func slugify(s string) string {
	s = strings.ToLower(s)
	s = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
			return r
		}
		return '_'
	}, s)
	return s
}

// LoadReport reads the report.txt file from a capture directory.
func LoadReport(dir string) (string, error) {
	data, err := readFileBounded(filepath.Join(dir, "report.txt"))
	if err != nil {
		return "", fmt.Errorf("read report: %w", err)
	}
	return string(data), nil
}

// hostSlug extracts a short filesystem-safe name from a URL.
func hostSlug(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		h := sha256.Sum256([]byte(rawURL))
		return hex.EncodeToString(h[:8])
	}
	host := u.Hostname()
	path := strings.Trim(u.Path, "/")
	path = strings.ReplaceAll(path, "/", "_")
	slug := host
	if path != "" {
		slug += "_" + path
	}
	// Truncate to keep filenames reasonable.
	if len(slug) > 80 {
		slug = slug[:80]
	}
	return slug
}
