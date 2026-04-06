package capture

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecordingTransport(t *testing.T) {
	want := []byte(`{"attestation":"data","nonce":"abc123"}`)
	base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Proto:      "HTTP/2.0",
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(want)),
		}, nil
	})

	rec := WrapRecording(base)
	reqBody := []byte(`{"nonce":"abc123"}`)
	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/attest", bytes.NewReader(reqBody))
	resp, err := rec.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Response body should still be readable by the caller.
	got, _ := io.ReadAll(resp.Body)
	t.Logf("response body: %s", got)
	if !bytes.Equal(got, want) {
		t.Errorf("response body = %q, want %q", got, want)
	}

	// Verify recorded entry.
	if len(rec.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(rec.Entries))
	}
	e := rec.Entries[0]
	t.Logf("entry: method=%s url=%s status=%d proto=%s", e.Method, e.URL, e.Status, e.Proto)
	if e.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", e.Method)
	}
	if e.URL != "https://api.example.com/attest" {
		t.Errorf("url = %q, want https://api.example.com/attest", e.URL)
	}
	if e.Status != http.StatusOK {
		t.Errorf("status = %d, want 200", e.Status)
	}
	if !bytes.Equal(e.Body, want) {
		t.Errorf("recorded body = %q, want %q", e.Body, want)
	}
	if !bytes.Equal(e.ReqBody, reqBody) {
		t.Errorf("recorded req body = %q, want %q", e.ReqBody, reqBody)
	}
}

func TestReplayTransport_Match(t *testing.T) {
	entries := []RecordedEntry{
		{
			Method:  http.MethodGet,
			URL:     "https://api.example.com/collateral",
			Status:  200,
			Proto:   "HTTP/1.1",
			Headers: http.Header{"Content-Type": {"application/json"}},
			Body:    []byte(`{"collateral":"data"}`),
		},
		{
			Method:  http.MethodPost,
			URL:     "https://api.example.com/attest",
			Status:  200,
			Proto:   "HTTP/2.0",
			Headers: http.Header{"Content-Type": {"application/json"}},
			ReqBody: []byte(`{"nonce":"abc"}`),
			Body:    []byte(`{"attestation":"result"}`),
		},
	}

	rt := NewReplayTransport(entries)

	// GET match.
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/collateral", http.NoBody)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("GET response: status=%d body=%s", resp.StatusCode, body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET status = %d, want 200", resp.StatusCode)
	}
	if string(body) != `{"collateral":"data"}` {
		t.Errorf("GET body = %q", body)
	}

	// POST match with matching body.
	req, _ = http.NewRequest(http.MethodPost, "https://api.example.com/attest", bytes.NewReader([]byte(`{"nonce":"abc"}`)))
	resp, err = rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("POST response: status=%d body=%s", resp.StatusCode, body)
	if string(body) != `{"attestation":"result"}` {
		t.Errorf("POST body = %q", body)
	}
}

func TestReplayTransport_NoMatch(t *testing.T) {
	rt := NewReplayTransport([]RecordedEntry{
		{
			Method: http.MethodGet,
			URL:    "https://api.example.com/known",
			Status: http.StatusOK,
			Body:   []byte("ok"),
		},
	})

	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/unknown", http.NoBody)
	resp, err := rt.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	t.Logf("unmatched request error: %v", err)
	if err == nil {
		t.Fatal("expected error for unmatched request")
	}
	if !strings.Contains(err.Error(), "no matching entry") {
		t.Errorf("error = %q, want 'no matching entry'", err)
	}
}

func TestReplayTransport_PostBodyMismatch(t *testing.T) {
	rt := NewReplayTransport([]RecordedEntry{
		{
			Method:  http.MethodPost,
			URL:     "https://api.example.com/attest",
			Status:  http.StatusOK,
			ReqBody: []byte(`{"nonce":"aaa"}`),
			Body:    []byte("response"),
		},
	})

	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/attest", bytes.NewReader([]byte(`{"nonce":"bbb"}`)))
	resp, err := rt.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	t.Logf("POST body mismatch error: %v", err)
	if err == nil {
		t.Fatal("expected error for POST body mismatch")
	}
}

func TestReplayTransport_PostAsymmetricBody(t *testing.T) {
	// Recorded entry has a body, but replay request has none — must not match.
	rt := NewReplayTransport([]RecordedEntry{
		{
			Method:  http.MethodPost,
			URL:     "https://api.example.com/attest",
			Status:  http.StatusOK,
			ReqBody: []byte(`{"nonce":"abc"}`),
			Body:    []byte("response"),
		},
	})

	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/attest", http.NoBody)
	resp, err := rt.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	t.Logf("asymmetric body (recorded has body, request empty) error: %v", err)
	if err == nil {
		t.Fatal("expected error for POST with asymmetric body (recorded has body, request empty)")
	}
	if !strings.Contains(err.Error(), "no matching entry") {
		t.Errorf("error = %q, want 'no matching entry'", err)
	}

	// Opposite direction: recorded entry has no body, but replay request has one.
	rt = NewReplayTransport([]RecordedEntry{
		{
			Method: http.MethodPost,
			URL:    "https://api.example.com/attest",
			Status: http.StatusOK,
			Body:   []byte("response"),
		},
	})

	req, _ = http.NewRequest(http.MethodPost, "https://api.example.com/attest", bytes.NewReader([]byte(`{"nonce":"abc"}`)))
	resp, err = rt.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	t.Logf("asymmetric body (recorded empty, request has body) error: %v", err)
	if err == nil {
		t.Fatal("expected error for POST with asymmetric body (recorded empty, request has body)")
	}
	if !strings.Contains(err.Error(), "no matching entry") {
		t.Errorf("error = %q, want 'no matching entry'", err)
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()

	m := &Manifest{
		Provider:   "venice",
		Model:      "deepseek-r1-0528",
		NonceHex:   "abcdef0123456789",
		CapturedAt: time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC),
		E2EE: &E2EEOutcome{
			Attempted: true,
			Detail:    "E2EE venice: 733 encrypted fields decrypted across 736 chunks",
		},
	}
	reportText := "=== Verification Report ===\nAll checks passed.\n"
	entries := []RecordedEntry{
		{
			Method:     http.MethodPost,
			URL:        "https://api.venice.ai/tee/attestation",
			Status:     200,
			Proto:      "HTTP/2.0",
			TLSVersion: "TLS 1.3",
			TLSCipher:  "TLS_AES_128_GCM_SHA256",
			Headers:    http.Header{"Content-Type": {"application/json"}},
			ReqBody:    []byte(`{"nonce":"abcdef0123456789"}`),
			Body:       []byte(`{"attestation":"raw-evidence-data","quote":"base64..."}`),
		},
		{
			Method:  http.MethodGet,
			URL:     "https://api.trustedservices.intel.com/tcb",
			Status:  200,
			Proto:   "HTTP/1.1",
			Headers: http.Header{"Content-Type": {"application/json"}},
			Body:    []byte(`{"tcbInfo":"collateral-data"}`),
		},
	}

	subdir, err := Save(dir, m, reportText, entries)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("saved to: %s", subdir)

	// Verify directory name.
	if !strings.Contains(subdir, "venice_deepseek-r1-0528_20260404_120000") {
		t.Errorf("subdir = %q, expected venice_deepseek-r1-0528_20260404_120000 in path", subdir)
	}

	// Load it back.
	loadedM, loadedEntries, err := Load(subdir)
	if err != nil {
		t.Fatal(err)
	}

	// Verify manifest.
	t.Logf("loaded manifest: provider=%s model=%s nonce=%s", loadedM.Provider, loadedM.Model, loadedM.NonceHex)
	if loadedM.Provider != m.Provider {
		t.Errorf("provider = %q, want %q", loadedM.Provider, m.Provider)
	}
	if loadedM.Model != m.Model {
		t.Errorf("model = %q, want %q", loadedM.Model, m.Model)
	}
	if loadedM.NonceHex != m.NonceHex {
		t.Errorf("nonce = %q, want %q", loadedM.NonceHex, m.NonceHex)
	}
	if loadedM.E2EE == nil {
		t.Fatal("E2EE is nil after round-trip")
	}
	t.Logf("loaded E2EE: attempted=%v detail=%q", loadedM.E2EE.Attempted, loadedM.E2EE.Detail)
	if !loadedM.E2EE.Attempted {
		t.Error("E2EE.Attempted = false, want true")
	}
	if loadedM.E2EE.Detail != m.E2EE.Detail {
		t.Errorf("E2EE.Detail = %q, want %q", loadedM.E2EE.Detail, m.E2EE.Detail)
	}

	// Verify entries.
	if len(loadedEntries) != len(entries) {
		t.Fatalf("entries = %d, want %d", len(loadedEntries), len(entries))
	}
	for i, got := range loadedEntries {
		want := entries[i]
		t.Logf("entry %d: method=%s url=%s status=%d bodyLen=%d", i, got.Method, got.URL, got.Status, len(got.Body))
		if got.Method != want.Method {
			t.Errorf("entry %d method = %q, want %q", i, got.Method, want.Method)
		}
		if got.URL != want.URL {
			t.Errorf("entry %d URL = %q, want %q", i, got.URL, want.URL)
		}
		if got.Status != want.Status {
			t.Errorf("entry %d status = %d, want %d", i, got.Status, want.Status)
		}
		if !bytes.Equal(got.Body, want.Body) {
			t.Errorf("entry %d body mismatch: got %q, want %q", i, got.Body, want.Body)
		}
		if !bytes.Equal(got.ReqBody, want.ReqBody) {
			t.Errorf("entry %d req body mismatch", i)
		}
		if got.TLSVersion != want.TLSVersion {
			t.Errorf("entry %d TLS version = %q, want %q", i, got.TLSVersion, want.TLSVersion)
		}
	}
}

func TestSlugify(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"deepseek-r1-0528", "deepseek-r1-0528"},
		{"Llama-3.1/70B", "llama-3.1_70b"},
		{"model with spaces", "model_with_spaces"},
	}
	for _, tt := range tests {
		got := slugify(tt.input)
		t.Logf("slugify(%q) = %q", tt.input, got)
		if got != tt.want {
			t.Errorf("slugify(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestHostSlug(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"https://api.venice.ai/tee/attestation", "api.venice.ai_tee_attestation"},
		{"https://api.trustedservices.intel.com/tcb", "api.trustedservices.intel.com_tcb"},
		{"https://nras.attestation.nvidia.com/v3/attest/gpu", "nras.attestation.nvidia.com_v3_attest_gpu"},
	}
	for _, tt := range tests {
		got := hostSlug(tt.input)
		t.Logf("hostSlug(%q) = %q", tt.input, got)
		if got != tt.want {
			t.Errorf("hostSlug(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSaveAndLoad_NilE2EE(t *testing.T) {
	dir := t.TempDir()

	m := &Manifest{
		Provider:   "neardirect",
		Model:      "test-model",
		NonceHex:   "0123456789abcdef",
		CapturedAt: time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC),
		// E2EE nil — provider without E2EE (e.g. neardirect).
	}

	subdir, err := Save(dir, m, "report\n", nil)
	if err != nil {
		t.Fatal(err)
	}

	loaded, _, err := Load(subdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("loaded E2EE: %v", loaded.E2EE)
	if loaded.E2EE != nil {
		t.Errorf("E2EE should be nil for capture without E2EE, got %+v", loaded.E2EE)
	}
}

func TestSaveAndLoad_E2EEFailed(t *testing.T) {
	dir := t.TempDir()

	m := &Manifest{
		Provider:   "venice",
		Model:      "test-model",
		NonceHex:   "0123456789abcdef",
		CapturedAt: time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC),
		E2EE: &E2EEOutcome{
			Attempted: true,
			Failed:    true,
			ErrMsg:    "HTTP 500: internal server error",
		},
	}

	subdir, err := Save(dir, m, "report\n", nil)
	if err != nil {
		t.Fatal(err)
	}

	loaded, _, err := Load(subdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("loaded E2EE: attempted=%v failed=%v err=%q", loaded.E2EE.Attempted, loaded.E2EE.Failed, loaded.E2EE.ErrMsg)
	if !loaded.E2EE.Failed {
		t.Error("E2EE.Failed = false, want true")
	}
	if loaded.E2EE.ErrMsg != m.E2EE.ErrMsg {
		t.Errorf("E2EE.ErrMsg = %q, want %q", loaded.E2EE.ErrMsg, m.E2EE.ErrMsg)
	}
}

func TestLoadReport(t *testing.T) {
	dir := t.TempDir()

	m := &Manifest{
		Provider:   "venice",
		Model:      "test-model",
		NonceHex:   "0123456789abcdef",
		CapturedAt: time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC),
	}
	reportText := "=== Report ===\nScore: 24/29 passed\n"

	subdir, err := Save(dir, m, reportText, nil)
	if err != nil {
		t.Fatal(err)
	}

	got, err := LoadReport(subdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("loaded report: %q", got)
	if got != reportText {
		t.Errorf("LoadReport = %q, want %q", got, reportText)
	}
}

func TestLoadReport_Missing(t *testing.T) {
	_, err := LoadReport(t.TempDir())
	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for missing report.txt")
	}
}

func TestReplayTransport_PostBothBodiesEmpty(t *testing.T) {
	rt := NewReplayTransport([]RecordedEntry{
		{
			Method: http.MethodPost,
			URL:    "https://api.example.com/attest",
			Status: http.StatusOK,
			Body:   []byte(`{"result":"ok"}`),
		},
	})

	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/attest", http.NoBody)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected match for both-empty POST bodies, got error: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("both-empty POST: status=%d body=%s", resp.StatusCode, body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestReadFileBounded_Oversized(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(path, make([]byte, maxCaptureFile+1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readFileBounded(path)
	t.Logf("readFileBounded oversized error: %v", err)
	if err == nil {
		t.Fatal("expected error for oversized file")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("error = %q, want message containing 'limit'", err)
	}
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
