package neardirect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct"
	"golang.org/x/sync/singleflight"
)

// errAlreadyCached is returned by the singleflight callback when another
// goroutine already populated the SPKI cache. Callers check errors.Is.
var errAlreadyCached = errors.New("already cached")

const (
	// dialTimeout is the TCP+TLS handshake timeout for backend connections.
	dialTimeout = 30 * time.Second

	// readTimeout is the overall read timeout for attestation responses.
	readTimeout = 30 * time.Second
)

// DomainResolver maps a model name to a backend host:port address.
type DomainResolver interface {
	Resolve(ctx context.Context, model string) (string, error)
}

// PinnedHandler implements provider.PinnedHandler for NEAR AI. It opens a raw
// tls.Conn to the resolved backend domain, checks the SPKI cache, fetches
// attestation on the same connection if needed, then sends the chat request
// and returns the raw response.
type PinnedHandler struct {
	resolver    DomainResolver
	spkiCache   *attestation.SPKICache
	apiKey      string
	offline     bool
	allowFail   []string
	policy      attestation.MeasurementPolicy
	rdVerifier  provider.ReportDataVerifier
	rekorClient *attestation.RekorClient
	ctChecker   *CTChecker
	dialFn      func(ctx context.Context, domain string) (*tls.Conn, error) // nil → use default tlsDial

	verifySF singleflight.Group
}

// NewPinnedHandler returns a PinnedHandler for NEAR AI.
func NewPinnedHandler(
	resolver DomainResolver,
	spkiCache *attestation.SPKICache,
	apiKey string,
	offline bool,
	allowFail []string,
	policy attestation.MeasurementPolicy,
	rdVerifier provider.ReportDataVerifier,
	rekorClient *attestation.RekorClient,
) *PinnedHandler {
	checker := NewCTChecker()
	checker.SetEnabled(!offline)

	return &PinnedHandler{
		resolver:    resolver,
		spkiCache:   spkiCache,
		apiKey:      apiKey,
		offline:     offline,
		allowFail:   allowFail,
		policy:      policy,
		rdVerifier:  rdVerifier,
		rekorClient: rekorClient,
		ctChecker:   checker,
	}
}

// SetCTChecker overrides the certificate transparency checker.
// Intended for tests.
func (h *PinnedHandler) SetCTChecker(checker *CTChecker) {
	h.ctChecker = checker
}

// HandlePinned opens a TLS connection to the backend, verifies its certificate
// via TDX attestation (or SPKI cache), sends the chat request, and returns the
// raw HTTP response. The caller is responsible for closing PinnedResponse.Body.
func (h *PinnedHandler) HandlePinned(ctx context.Context, req *provider.PinnedRequest) (_ *provider.PinnedResponse, err error) {
	// 1. Resolve model → backend domain.
	domain, err := h.resolver.Resolve(ctx, req.Model)
	if err != nil {
		return nil, fmt.Errorf("resolve domain: %w", err)
	}

	// 2. TLS dial — cert is verified via CA chain and attestation-based SPKI pinning.
	dialFn := h.tlsDial
	if h.dialFn != nil {
		dialFn = h.dialFn
	}
	conn, err := dialFn(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("TLS dial %s: %w", domain, err)
	}

	// On any error after this point, close the connection.
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	// 3. Extract SPKI hash from the peer certificate.
	liveSPKI, err := h.extractSPKI(conn)
	if err != nil {
		return nil, fmt.Errorf("extract SPKI: %w", err)
	}
	if h.ctChecker != nil {
		state := conn.ConnectionState()
		if err := h.ctChecker.CheckTLSState(ctx, domain, &state); err != nil {
			return nil, fmt.Errorf("certificate transparency check failed: %w", err)
		}
	}

	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)

	// 4. Check SPKI cache. On miss, collapse concurrent attestation fetches
	//    for the same domain via singleflight (prevents thundering herd).
	var report *attestation.VerificationReport
	if !h.spkiCache.Contains(domain, liveSPKI) {
		slog.InfoContext(ctx, "SPKI cache miss, fetching attestation", "domain", domain, "spki", liveSPKI[:16]+"...")
		v, sfErr, _ := h.verifySF.Do(domain+"\x00"+liveSPKI, func() (any, error) {
			// Double-check after winning the singleflight race.
			if h.spkiCache.Contains(domain, liveSPKI) {
				return nil, errAlreadyCached
			}
			r, err := h.attestOnConn(ctx, conn, br, bw, domain, liveSPKI, req.Model)
			if err != nil {
				return nil, err
			}
			if r.Blocked() {
				blocked := r.BlockedFactors()
				names := make([]string, len(blocked))
				for i, f := range blocked {
					names[i] = f.Name
				}
				slog.WarnContext(ctx, "attestation blocked by policy, refusing to cache SPKI",
					"domain", domain,
					"model", req.Model,
					"blocked_factors", names,
				)
				for _, f := range blocked {
					slog.DebugContext(ctx, "blocked factor detail",
						"factor", f.Name,
						"detail", f.Detail,
						"tier", f.Tier,
					)
				}
				return r, nil
			}
			h.spkiCache.Add(domain, liveSPKI)
			slog.InfoContext(ctx, "SPKI verified and cached", "domain", domain, "spki", liveSPKI[:16]+"...")
			return r, nil
		})
		if sfErr != nil && !errors.Is(sfErr, errAlreadyCached) {
			return nil, fmt.Errorf("attestation on %s: %w", domain, sfErr)
		}
		if v != nil {
			var ok bool
			report, ok = v.(*attestation.VerificationReport)
			if !ok {
				return nil, fmt.Errorf("singleflight returned unexpected type %T", v)
			}
		}
	} else {
		slog.DebugContext(ctx, "SPKI cache hit, skipping attestation", "domain", domain, "spki", liveSPKI[:16]+"...")
	}

	if report != nil && report.Blocked() {
		return &provider.PinnedResponse{
			StatusCode: http.StatusBadGateway,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(nil)),
			Report:     report,
		}, nil
	}

	// 5. Send the actual chat request on the same connection.
	headers := req.Headers.Clone()
	headers.Set("Host", domain)
	headers.Set("Authorization", "Bearer "+h.apiKey)
	headers.Set("Connection", "close")

	if err := WriteHTTPRequest(bw, req.Method, req.Path, headers, req.Body); err != nil {
		return nil, fmt.Errorf("write chat request: %w", err)
	}

	// 6. Read the response.
	resp, err := readChatResponse(br) //nolint:bodyclose // body ownership transfers to NewConnClosingReader
	if err != nil {
		return nil, fmt.Errorf("read chat response: %w", err)
	}

	return &provider.PinnedResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       NewConnClosingReader(resp.Body, conn),
		Report:     report,
	}, nil
}

// setDialer overrides the TLS dial function used by HandlePinned. Only
// accessible from tests within this package — unexported to prevent
// supply-chain redirection of backend connections in production.
func (h *PinnedHandler) setDialer(fn func(ctx context.Context, domain string) (*tls.Conn, error)) {
	h.dialFn = fn
}

// tlsDial opens a TLS connection to domain:443.
// The certificate is verified via both standard CA validation and TDX
// attestation-based SPKI pinning.
func (h *PinnedHandler) tlsDial(ctx context.Context, domain string) (*tls.Conn, error) {
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: dialTimeout},
		Config: &tls.Config{
			ServerName: domain,
			MinVersion: tls.VersionTLS13,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", domain+":443")
	if err != nil {
		return nil, err
	}
	tc, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("tls.Dialer returned %T, expected *tls.Conn", conn)
	}
	return tc, nil
}

// extractSPKI computes the SPKI hash of the peer certificate from a TLS connection.
func (h *PinnedHandler) extractSPKI(conn *tls.Conn) (string, error) {
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("no peer certificate from server")
	}
	return attestation.ComputeSPKIHash(state.PeerCertificates[0].Raw)
}

// attestOnConn fetches and verifies TDX attestation on an existing connection.
// Returns a VerificationReport on success.
func (h *PinnedHandler) attestOnConn(
	ctx context.Context,
	conn *tls.Conn,
	br *bufio.Reader,
	bw *bufio.Writer,
	domain, liveSPKI, model string,
) (*attestation.VerificationReport, error) {
	nonce := attestation.NewNonce()
	slog.DebugContext(ctx, "neardirect attestation nonce generated",
		"nonce_prefix", nonce.HexPrefix(),
		"domain", domain,
		"model", model,
	)

	raw, err := h.sendAttestationRequest(conn, br, bw, domain, model, nonce)
	if err != nil {
		return nil, err
	}

	tdxResult := h.verifyTDX(ctx, raw, nonce)
	nvidiaResult, nrasResult := h.verifyNVIDIA(ctx, raw, nonce)
	pocResult := h.checkPoC(ctx, raw.IntelQuote)

	// Verify live SPKI matches the attested TLS fingerprint.
	// Connection trust anchor — MUST remain inline and fatal.
	if raw.TLSFingerprint == "" {
		return nil, errors.New("attestation response missing tls_cert_fingerprint")
	}
	match, err := ConstantTimeHexEqual(liveSPKI, raw.TLSFingerprint)
	if err != nil {
		return nil, fmt.Errorf("compare live SPKI vs attested TLS fingerprint: %w", err)
	}
	if !match {
		return nil, fmt.Errorf("live SPKI %s != attested TLS fingerprint %s", provider.Truncate(liveSPKI, 16), provider.Truncate(raw.TLSFingerprint, 16))
	}

	composeResult, imageRepos, digestToRepo, sigstoreResults, rekorResults :=
		h.verifySupplyChain(ctx, raw, tdxResult)

	allowFail := h.allowFail
	if h.offline {
		allowFail = attestation.WithOfflineAllowFail(allowFail)
	}

	report := attestation.BuildReport(&attestation.ReportInput{
		Provider:          "neardirect",
		Model:             model,
		Raw:               raw,
		Nonce:             nonce,
		AllowFail:         allowFail,
		Policy:            h.policy,
		SupplyChainPolicy: SupplyChainPolicy(),
		ImageRepos:        imageRepos,
		DigestToRepo:      digestToRepo,
		TDX:               tdxResult,
		Nvidia:            nvidiaResult,
		NvidiaNRAS:        nrasResult,
		PoC:               pocResult,
		Compose:           composeResult,
		Sigstore:          sigstoreResults,
		Rekor:             rekorResults,
	})
	return report, nil
}

// sendAttestationRequest writes the attestation HTTP request and reads the
// response. On error, the caller must close the connection.
func (h *PinnedHandler) sendAttestationRequest(
	conn *tls.Conn, br *bufio.Reader, bw *bufio.Writer,
	domain, model string, nonce attestation.Nonce,
) (*attestation.RawAttestation, error) {
	path := attestationPath +
		"?include_tls_fingerprint=true" +
		"&nonce=" + nonce.Hex() +
		"&signing_algo=ecdsa"

	attestHeaders := make(http.Header)
	attestHeaders.Set("Host", domain)
	attestHeaders.Set("Authorization", "Bearer "+h.apiKey)
	attestHeaders.Set("Connection", "keep-alive")
	if err := WriteHTTPRequest(bw, http.MethodGet, path, attestHeaders, nil); err != nil {
		return nil, fmt.Errorf("write attestation request: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}

	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("read attestation response: %w", err)
	}
	defer resp.Body.Close()

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear read deadline: %w", err)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read attestation body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attestation HTTP %d: %s", resp.StatusCode, provider.Truncate(string(body), 256))
	}

	return ParseAttestationResponse(body, model)
}

// verifyTDX runs TDX quote verification and report data binding.
// Returns nil if no intel_quote is present.
func (h *PinnedHandler) verifyTDX(
	ctx context.Context, raw *attestation.RawAttestation, nonce attestation.Nonce,
) *attestation.TDXVerifyResult {
	if raw.IntelQuote == "" {
		return nil
	}
	tdxResult := attestation.VerifyTDXQuote(ctx, raw.IntelQuote, nonce, h.offline)
	if h.rdVerifier != nil && tdxResult.ParseErr == nil {
		detail, rdErr := h.rdVerifier.VerifyReportData(tdxResult.ReportData, raw, nonce)
		tdxResult.ReportDataBindingErr = rdErr
		tdxResult.ReportDataBindingDetail = detail
	}
	return tdxResult
}

// verifyNVIDIA runs NVIDIA EAT and NRAS verification.
// Returns nil for either if not applicable.
func (h *PinnedHandler) verifyNVIDIA(
	ctx context.Context, raw *attestation.RawAttestation, nonce attestation.Nonce,
) (eat, nras *attestation.NvidiaVerifyResult) {
	if raw.NvidiaPayload != "" {
		slog.DebugContext(ctx, "verifying NVIDIA payload with nonce",
			"nonce_prefix", nonce.HexPrefix(),
		)
		eat = attestation.VerifyNVIDIAPayload(ctx, raw.NvidiaPayload, nonce)
	}
	if !h.offline && raw.NvidiaPayload != "" && raw.NvidiaPayload[0] == '{' {
		nras = attestation.VerifyNVIDIANRAS(ctx, raw.NvidiaPayload, tlsct.NewHTTPClient(30*time.Second))
	}
	return eat, nras
}

// checkPoC runs a Proof of Cloud check for the given intel_quote.
// Returns nil if offline or quote is empty.
func (h *PinnedHandler) checkPoC(ctx context.Context, quote string) *attestation.PoCResult {
	if h.offline || quote == "" {
		return nil
	}
	poc := attestation.NewPoCClient(attestation.PoCPeers, attestation.PoCQuorum, tlsct.NewHTTPClient(30*time.Second))
	return poc.CheckQuote(ctx, quote)
}

// verifySupplyChain runs compose binding, sigstore, and rekor verification.
// Returns nil results if compose is empty or TDX verification failed.
func (h *PinnedHandler) verifySupplyChain(
	ctx context.Context, raw *attestation.RawAttestation, tdxResult *attestation.TDXVerifyResult,
) (
	compose *attestation.ComposeBindingResult,
	imageRepos []string,
	digestToRepo map[string]string,
	sigstore []attestation.SigstoreResult,
	rekor []attestation.RekorProvenance,
) {
	if raw.AppCompose == "" || tdxResult == nil || tdxResult.ParseErr != nil {
		return nil, nil, nil, nil, nil
	}

	compose = &attestation.ComposeBindingResult{Checked: true}
	compose.Err = attestation.VerifyComposeBinding(raw.AppCompose, tdxResult.MRConfigID)
	if compose.Err != nil {
		return compose, nil, nil, nil, nil
	}

	cd := attestation.ExtractComposeDigests(raw.AppCompose)
	imageRepos = cd.Repos
	digestToRepo = cd.DigestToRepo

	if len(cd.Digests) > 0 && !h.offline && h.rekorClient != nil {
		sigstore = h.rekorClient.CheckSigstoreDigests(ctx, cd.Digests)
		for _, sr := range sigstore {
			if sr.OK {
				rekor = append(rekor, h.rekorClient.FetchRekorProvenance(ctx, sr.Digest))
			}
		}
	}

	return compose, imageRepos, digestToRepo, sigstore, rekor
}

// readChatResponse reads an HTTP response from a buffered reader. The caller
// is responsible for closing resp.Body (typically via NewConnClosingReader).
func readChatResponse(br *bufio.Reader) (*http.Response, error) {
	return http.ReadResponse(br, nil)
}

// WriteHTTPRequest writes an HTTP/1.1 request (request line + headers + body)
// to w. Used instead of http.Request.Write to maintain control over the exact
// connection (no connection pooling, no automatic redirects).
//
// Host is derived from headers; Content-Length is derived from body.
func WriteHTTPRequest(w *bufio.Writer, method, path string, headers http.Header, body []byte) error {
	// Request line.
	if _, err := fmt.Fprintf(w, "%s %s HTTP/1.1\r\n", method, path); err != nil {
		return err
	}

	// Host must come first per RFC 7230 §5.4.
	host := headers.Get("Host")
	if host == "" {
		return errors.New("headers missing required Host field")
	}
	if strings.ContainsAny(host, "\r\n") {
		return errors.New("host header contains invalid CR/LF characters")
	}
	if _, err := fmt.Fprintf(w, "Host: %s\r\n", host); err != nil {
		return err
	}

	// Content-Length derived from body; caller must not also set it.
	if body != nil {
		if _, err := fmt.Fprintf(w, "Content-Length: %d\r\n", len(body)); err != nil {
			return err
		}
	}

	// Other headers.
	for key, vals := range headers {
		if key == "Host" || key == "Content-Length" {
			continue
		}
		for _, val := range vals {
			if strings.ContainsAny(val, "\r\n") {
				return fmt.Errorf("header %q contains invalid CR/LF characters", key)
			}
			if _, err := fmt.Fprintf(w, "%s: %s\r\n", key, val); err != nil {
				return err
			}
		}
	}

	// End of headers.
	if _, err := fmt.Fprintf(w, "\r\n"); err != nil {
		return err
	}

	// Body.
	if body != nil {
		if _, err := w.Write(body); err != nil {
			return err
		}
	}

	return w.Flush()
}

// ConstantTimeHexEqual compares two hex strings in constant time.
func ConstantTimeHexEqual(a, b string) (bool, error) {
	aBytes, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(a)), "0x"))
	if err != nil {
		return false, fmt.Errorf("first value is not valid hex: %w", err)
	}
	bBytes, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(b)), "0x"))
	if err != nil {
		return false, fmt.Errorf("second value is not valid hex: %w", err)
	}
	if len(aBytes) != len(bBytes) {
		return false, nil
	}
	return subtle.ConstantTimeCompare(aBytes, bBytes) == 1, nil
}

// ConnClosingReader wraps an io.ReadCloser so that closing it also closes the
// underlying net.Conn. Used to tie the response body lifetime to the connection.
type ConnClosingReader struct {
	io.ReadCloser
	conn net.Conn
}

// NewConnClosingReader returns a ConnClosingReader wrapping rc and conn.
func NewConnClosingReader(rc io.ReadCloser, conn net.Conn) *ConnClosingReader {
	return &ConnClosingReader{ReadCloser: rc, conn: conn}
}

// Close closes both the wrapped ReadCloser and the underlying net.Conn.
func (r *ConnClosingReader) Close() error {
	err := r.ReadCloser.Close()
	connErr := r.conn.Close()
	if err != nil {
		return err
	}
	return connErr
}
