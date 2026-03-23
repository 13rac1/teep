package nearcloud

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/tlsct"
	"golang.org/x/sync/singleflight"
)

const (
	dialTimeout = 30 * time.Second
	readTimeout = 60 * time.Second // longer than neardirect — two attestation requests
)

// PinnedHandler implements provider.PinnedHandler for the NEAR AI cloud
// gateway. All connections go to cloud-api.near.ai (no resolver). On SPKI
// cache miss, two attestation requests are sent on the same TLS connection:
// one for the gateway and one for the model.
type PinnedHandler struct {
	spkiCache  *attestation.SPKICache
	apiKey     string
	offline    bool
	enforced   []string
	policy     attestation.MeasurementPolicy
	rdVerifier provider.ReportDataVerifier
	ctChecker  *neardirect.CTChecker
	dialFn     func(ctx context.Context, domain string) (*tls.Conn, error)

	verifySF singleflight.Group
}

// NewPinnedHandler returns a PinnedHandler for nearcloud.
func NewPinnedHandler(
	spkiCache *attestation.SPKICache,
	apiKey string,
	offline bool,
	enforced []string,
	policy attestation.MeasurementPolicy,
	rdVerifier provider.ReportDataVerifier,
) *PinnedHandler {
	checker := neardirect.NewCTChecker()
	checker.SetEnabled(!offline)

	return &PinnedHandler{
		spkiCache:  spkiCache,
		apiKey:     apiKey,
		offline:    offline,
		enforced:   enforced,
		policy:     policy,
		rdVerifier: rdVerifier,
		ctChecker:  checker,
	}
}

// SetDialer overrides the TLS dial function. Intended for testing.
func (h *PinnedHandler) SetDialer(fn func(ctx context.Context, domain string) (*tls.Conn, error)) {
	h.dialFn = fn
}

// SetCTChecker overrides the certificate transparency checker. Intended for tests.
func (h *PinnedHandler) SetCTChecker(checker *neardirect.CTChecker) {
	h.ctChecker = checker
}

// HandlePinned opens a TLS connection to cloud-api.near.ai, verifies the
// gateway and model attestation, sends the chat request, and returns the
// raw HTTP response.
func (h *PinnedHandler) HandlePinned(ctx context.Context, req *provider.PinnedRequest) (_ *provider.PinnedResponse, err error) {
	domain := gatewayHost

	dialFn := h.tlsDial
	if h.dialFn != nil {
		dialFn = h.dialFn
	}
	conn, err := dialFn(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("TLS dial %s: %w", domain, err)
	}

	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	liveSPKI, err := extractSPKI(conn)
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

	var report *attestation.VerificationReport
	if !h.spkiCache.Contains(domain, liveSPKI) {
		slog.Info("SPKI cache miss, fetching gateway+model attestation", "domain", domain, "spki", liveSPKI[:16]+"...")
		v, sfErr, _ := h.verifySF.Do(domain+"\x00"+liveSPKI, func() (any, error) {
			if h.spkiCache.Contains(domain, liveSPKI) {
				return nil, nil //nolint:nilnil // singleflight: nil,nil means cache was already populated
			}
			r, err := h.attestOnConn(ctx, conn, br, bw, domain, liveSPKI, req.Model)
			if err != nil {
				return nil, err
			}
			if r.Blocked() {
				slog.Warn("attestation blocked by policy",
					"domain", domain,
					"model", req.Model,
				)
				return r, nil
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

	if report != nil && report.Blocked() {
		return &provider.PinnedResponse{
			StatusCode: http.StatusBadGateway,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(nil)),
			Report:     report,
		}, nil
	}

	// Send the chat request on the same connection.
	headers := req.Headers.Clone()
	headers.Set("Host", domain)
	headers.Set("Authorization", "Bearer "+h.apiKey)
	headers.Set("Connection", "close")

	if err := neardirect.WriteHTTPRequest(bw, req.Method, req.Path, headers, req.Body); err != nil {
		return nil, fmt.Errorf("write chat request: %w", err)
	}

	resp, err := http.ReadResponse(br, nil) //nolint:bodyclose // body is closed via ConnClosingReader wrapping below
	if err != nil {
		return nil, fmt.Errorf("read chat response: %w", err)
	}

	wrappedBody := neardirect.NewConnClosingReader(resp.Body, conn)

	return &provider.PinnedResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       wrappedBody,
		Report:     report,
	}, nil
}

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
	return conn.(*tls.Conn), nil //nolint:forcetypeassert // tls.Dialer.DialContext guarantees *tls.Conn
}

func extractSPKI(conn *tls.Conn) (string, error) {
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("no peer certificate from server")
	}
	return attestation.ComputeSPKIHash(state.PeerCertificates[0].Raw)
}

// attestOnConn sends a single attestation request on the TLS connection that
// returns both gateway and model attestation. The gateway and model share the
// same nonce — the client sends one nonce and both echo it back.
func (h *PinnedHandler) attestOnConn(
	ctx context.Context,
	conn *tls.Conn,
	br *bufio.Reader,
	bw *bufio.Writer,
	domain, liveSPKI, model string,
) (*attestation.VerificationReport, error) {
	modelNonce := attestation.NewNonce()

	// Single request — the gateway returns both gateway and model attestation.
	q := url.Values{}
	q.Set("model", model)
	q.Set("include_tls_fingerprint", "true")
	q.Set("nonce", modelNonce.Hex())
	q.Set("signing_algo", "ecdsa")
	path := attestationPath + "?" + q.Encode()

	attestHeaders := make(http.Header)
	attestHeaders.Set("Host", domain)
	attestHeaders.Set("Authorization", "Bearer "+h.apiKey)
	attestHeaders.Set("Connection", "keep-alive")
	if err := neardirect.WriteHTTPRequest(bw, http.MethodGet, path, attestHeaders, nil); err != nil {
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2 MiB
	if err != nil {
		return nil, fmt.Errorf("read attestation body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attestation HTTP %d: %s", resp.StatusCode, truncate(string(body), 256))
	}

	// Parse both gateway and model attestation from the combined response.
	gwRaw, raw, err := ParseGatewayResponse(body, model)
	if err != nil {
		return nil, err
	}

	// --- Verify model TDX ---
	var tdxResult *attestation.TDXVerifyResult
	if raw.IntelQuote != "" {
		tdxResult = attestation.VerifyTDXQuote(ctx, raw.IntelQuote, modelNonce, h.offline)
		if h.rdVerifier != nil && tdxResult.ParseErr == nil {
			detail, rdErr := h.rdVerifier.VerifyReportData(tdxResult.ReportData, raw, modelNonce)
			tdxResult.ReportDataBindingErr = rdErr
			tdxResult.ReportDataBindingDetail = detail
		}
	}

	var nvidiaResult *attestation.NvidiaVerifyResult
	if raw.NvidiaPayload != "" {
		nvidiaResult = attestation.VerifyNVIDIAPayload(raw.NvidiaPayload, modelNonce)
	}

	var nrasResult *attestation.NvidiaVerifyResult
	if !h.offline && raw.NvidiaPayload != "" && raw.NvidiaPayload[0] == '{' {
		nrasResult = attestation.VerifyNVIDIANRAS(ctx, raw.NvidiaPayload, tlsct.NewHTTPClient(30*time.Second))
	}

	var pocResult *attestation.PoCResult
	if !h.offline && raw.IntelQuote != "" {
		poc := attestation.NewPoCClient(attestation.PoCPeers, attestation.PoCQuorum, tlsct.NewHTTPClient(30*time.Second))
		pocResult = poc.CheckQuote(ctx, raw.IntelQuote)
	}

	// Verify model TLS fingerprint matches the live SPKI of the model backend.
	// Note: the model's tls_cert_fingerprint is for the model backend, which is
	// different from the gateway's. The live SPKI here is the gateway's, so we
	// verify the gateway's TLS fingerprint instead.
	if raw.TLSFingerprint != "" {
		slog.Debug("model tls_cert_fingerprint present (model backend SPKI, not gateway)",
			"model_fp", truncate(raw.TLSFingerprint, 16)+"...",
			"gateway_spki", truncate(liveSPKI, 16)+"...",
		)
	}

	// Model compose binding.
	var composeResult *attestation.ComposeBindingResult
	var sigstoreResults []attestation.SigstoreResult
	var imageRepos []string
	if raw.AppCompose != "" && tdxResult != nil && tdxResult.ParseErr == nil {
		composeResult = &attestation.ComposeBindingResult{Checked: true}
		composeResult.Err = attestation.VerifyComposeBinding(raw.AppCompose, tdxResult.MRConfigID)

		dockerCompose, err := attestation.ExtractDockerCompose(raw.AppCompose)
		if err != nil {
			slog.Debug("extract docker_compose_file failed", "domain", domain, "err", err)
		}
		if dockerCompose != "" {
			slog.Debug("attested docker compose manifest", "domain", domain, "content", dockerCompose)
		}
		source := dockerCompose
		if source == "" {
			source = raw.AppCompose
		}
		imageRepos = attestation.ExtractImageRepositories(source)
		digests := attestation.ExtractImageDigests(source)
		if len(digests) > 0 && !h.offline {
			sigstoreResults = attestation.CheckSigstoreDigests(ctx, digests, tlsct.NewHTTPClient(10*time.Second))
		}
	}

	var rekorResults []attestation.RekorProvenance
	if len(sigstoreResults) > 0 && !h.offline {
		for _, sr := range sigstoreResults {
			if sr.OK {
				rekorResults = append(rekorResults, attestation.FetchRekorProvenance(ctx, sr.Digest, tlsct.NewHTTPClient(10*time.Second)))
			}
		}
	}

	// --- Verify gateway TDX ---
	var gatewayTDX *attestation.TDXVerifyResult
	if gwRaw.IntelQuote != "" {
		gatewayTDX = attestation.VerifyTDXQuote(ctx, gwRaw.IntelQuote, modelNonce, h.offline)
		if gatewayTDX.ParseErr == nil {
			detail, rdErr := GatewayReportDataVerifier{}.Verify(
				gatewayTDX.ReportData, gwRaw.TLSCertFingerprint, modelNonce)
			gatewayTDX.ReportDataBindingErr = rdErr
			gatewayTDX.ReportDataBindingDetail = detail
		}
	}

	// Verify gateway TLS fingerprint matches live SPKI.
	if gwRaw.TLSCertFingerprint == "" {
		return nil, errors.New("gateway attestation response missing tls_cert_fingerprint")
	}
	match, matchErr := neardirect.ConstantTimeHexEqual(liveSPKI, gwRaw.TLSCertFingerprint)
	if matchErr != nil {
		return nil, fmt.Errorf("gateway SPKI comparison: %w", matchErr)
	}
	if !match {
		return nil, fmt.Errorf("gateway SPKI %s != attested tls_cert_fingerprint %s",
			truncate(liveSPKI, 16)+"...",
			truncate(gwRaw.TLSCertFingerprint, 16)+"...")
	}
	slog.Debug("gateway TLS fingerprint matches live SPKI",
		"spki", truncate(liveSPKI, 16)+"...",
		"fp", truncate(gwRaw.TLSCertFingerprint, 16)+"...",
	)

	// Gateway compose binding.
	var gatewayCompose *attestation.ComposeBindingResult
	if gwRaw.AppCompose != "" && gatewayTDX != nil && gatewayTDX.ParseErr == nil {
		gatewayCompose = &attestation.ComposeBindingResult{Checked: true}
		gatewayCompose.Err = attestation.VerifyComposeBinding(gwRaw.AppCompose, gatewayTDX.MRConfigID)
	}

	report := attestation.BuildReport(&attestation.ReportInput{
		Provider:        "nearcloud",
		Model:           model,
		Raw:             raw,
		Nonce:           modelNonce,
		Enforced:        h.enforced,
		Policy:          h.policy,
		ImageRepos:      imageRepos,
		TDX:             tdxResult,
		Nvidia:          nvidiaResult,
		NvidiaNRAS:      nrasResult,
		PoC:             pocResult,
		Compose:         composeResult,
		Sigstore:        sigstoreResults,
		Rekor:           rekorResults,
		GatewayTDX:      gatewayTDX,
		GatewayNonceHex: gwRaw.NonceHex,
		GatewayNonce:    modelNonce, // gateway echoes the same nonce
		GatewayCompose:  gatewayCompose,
		GatewayEventLog: gwRaw.EventLog,
	})
	return report, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
