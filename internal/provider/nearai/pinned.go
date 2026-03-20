package nearai

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
	"golang.org/x/sync/singleflight"
)

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
	resolver   DomainResolver
	spkiCache  *attestation.SPKICache
	apiKey     string
	offline    bool
	enforced   []string
	rdVerifier provider.ReportDataVerifier
	dialFn     func(ctx context.Context, domain string) (*tls.Conn, error) // nil → use default tlsDial

	verifySF singleflight.Group
}

// NewPinnedHandler returns a PinnedHandler for NEAR AI.
func NewPinnedHandler(
	resolver DomainResolver,
	spkiCache *attestation.SPKICache,
	apiKey string,
	offline bool,
	enforced []string,
	rdVerifier provider.ReportDataVerifier,
) *PinnedHandler {
	return &PinnedHandler{
		resolver:   resolver,
		spkiCache:  spkiCache,
		apiKey:     apiKey,
		offline:    offline,
		enforced:   enforced,
		rdVerifier: rdVerifier,
	}
}

// SetDialer overrides the TLS dial function used by HandlePinned. This is
// intended for testing only — it allows connecting to test servers instead
// of resolving real domains.
func (h *PinnedHandler) SetDialer(fn func(ctx context.Context, domain string) (*tls.Conn, error)) {
	h.dialFn = fn
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

	// 2. TLS dial with InsecureSkipVerify — cert is verified via attestation.
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

	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)

	// 4. Check SPKI cache. On miss, collapse concurrent attestation fetches
	//    for the same domain via singleflight (prevents thundering herd).
	var report *attestation.VerificationReport
	if !h.spkiCache.Contains(domain, liveSPKI) {
		slog.Info("SPKI cache miss, fetching attestation", "domain", domain, "spki", liveSPKI[:16]+"...")
		v, sfErr, _ := h.verifySF.Do(domain+"\x00"+liveSPKI, func() (any, error) {
			// Double-check after winning the singleflight race.
			if h.spkiCache.Contains(domain, liveSPKI) {
				return nil, nil //nolint:nilnil // singleflight: nil,nil means cache was already populated
			}
			r, err := h.attestOnConn(ctx, conn, br, bw, domain, liveSPKI, req.Model)
			if err != nil {
				return nil, err
			}
			h.spkiCache.Add(domain, liveSPKI)
			slog.Info("SPKI verified and cached", "domain", domain, "spki", liveSPKI[:16]+"...")
			return r, nil
		})
		if sfErr != nil {
			return nil, fmt.Errorf("attestation on %s: %w", domain, sfErr)
		}
		if v != nil {
			report = v.(*attestation.VerificationReport) //nolint:forcetypeassert // singleflight callback only returns *VerificationReport
		}
	} else {
		slog.Debug("SPKI cache hit, skipping attestation", "domain", domain, "spki", liveSPKI[:16]+"...")
	}

	// 5. Send the actual chat request on the same connection.
	headers := req.Headers.Clone()
	headers.Set("Host", domain)
	headers.Set("Authorization", "Bearer "+h.apiKey)
	headers.Set("Connection", "close")

	if err := writeHTTPRequest(bw, req.Method, req.Path, headers, req.Body); err != nil {
		return nil, fmt.Errorf("write chat request: %w", err)
	}

	// 6. Read the response.
	resp, err := http.ReadResponse(br, nil) //nolint:bodyclose // body is closed via connClosingReader wrapping below
	if err != nil {
		return nil, fmt.Errorf("read chat response: %w", err)
	}

	// Wrap the response body so closing it also closes the underlying connection.
	wrappedBody := &connClosingReader{ReadCloser: resp.Body, conn: conn}

	return &provider.PinnedResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       wrappedBody,
		Report:     report,
	}, nil
}

// tlsDial opens a TLS connection to domain:443 with InsecureSkipVerify.
// The certificate is verified via TDX attestation, not the standard CA chain.
func (h *PinnedHandler) tlsDial(ctx context.Context, domain string) (*tls.Conn, error) {
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: dialTimeout},
		Config: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         domain,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", domain+":443")
	if err != nil {
		return nil, err
	}
	// tls.Dialer.DialContext always returns *tls.Conn when err == nil.
	return conn.(*tls.Conn), nil //nolint:forcetypeassert // tls.Dialer.DialContext guarantees *tls.Conn
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

	// Build the attestation request path with query parameters.
	path := attestationPath +
		"?include_tls_fingerprint=true" +
		"&nonce=" + nonce.Hex() +
		"&signing_algo=ecdsa"

	// Write the GET request on the existing connection.
	attestHeaders := make(http.Header)
	attestHeaders.Set("Host", domain)
	attestHeaders.Set("Authorization", "Bearer "+h.apiKey)
	attestHeaders.Set("Connection", "keep-alive")
	if err := writeHTTPRequest(bw, http.MethodGet, path, attestHeaders, nil); err != nil {
		return nil, fmt.Errorf("write attestation request: %w", err)
	}

	// Set a read deadline for the attestation response.
	if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}

	// Read the attestation response.
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("read attestation response: %w", err)
	}
	defer resp.Body.Close()

	// Clear read deadline for subsequent operations.
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear read deadline: %w", err)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read attestation body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attestation HTTP %d: %s", resp.StatusCode, truncate(string(body), 256))
	}

	// Parse the attestation response using shared parser.
	raw, err := parseAttestationResponse(body, model)
	if err != nil {
		return nil, err
	}

	// Verify TDX quote.
	var tdxResult *attestation.TDXVerifyResult
	if raw.IntelQuote != "" {
		tdxResult = attestation.VerifyTDXQuote(ctx, raw.IntelQuote, nonce, h.offline)
		if h.rdVerifier != nil && tdxResult.ParseErr == nil {
			detail, rdErr := h.rdVerifier.VerifyReportData(tdxResult.ReportData, raw, nonce)
			tdxResult.ReportDataBindingErr = rdErr
			tdxResult.ReportDataBindingDetail = detail
		}
	}

	// Verify live SPKI matches the attested TLS fingerprint.
	if raw.TLSFingerprint == "" {
		return nil, errors.New("attestation response missing tls_cert_fingerprint")
	}
	if liveSPKI != raw.TLSFingerprint {
		return nil, fmt.Errorf("live SPKI %s != attested TLS fingerprint %s", liveSPKI[:16]+"...", raw.TLSFingerprint[:16]+"...")
	}

	report := attestation.BuildReport("nearai", model, raw, nonce, h.enforced, tdxResult, nil, nil, nil)
	return report, nil
}

// writeHTTPRequest writes an HTTP/1.1 request (request line + headers + body)
// to w. Used instead of http.Request.Write to maintain control over the exact
// connection (no connection pooling, no automatic redirects).
//
// Host is derived from headers; Content-Length is derived from body.
func writeHTTPRequest(w *bufio.Writer, method, path string, headers http.Header, body []byte) error {
	// Request line.
	if _, err := fmt.Fprintf(w, "%s %s HTTP/1.1\r\n", method, path); err != nil {
		return err
	}

	// Host must come first per RFC 7230 §5.4.
	host := headers.Get("Host")
	if host == "" {
		return errors.New("headers missing required Host field")
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

// connClosingReader wraps an io.ReadCloser so that closing it also closes the
// underlying net.Conn. Used to tie the response body lifetime to the connection.
type connClosingReader struct {
	io.ReadCloser
	conn net.Conn
}

func (r *connClosingReader) Close() error {
	err := r.ReadCloser.Close()
	connErr := r.conn.Close()
	if err != nil {
		return err
	}
	return connErr
}
