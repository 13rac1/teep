package nearcloud

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/tlsct"
	"github.com/google/go-tdx-guest/verify/trust"
	"golang.org/x/sync/singleflight"
)

// errAlreadyCached is returned by the singleflight callback when another
// goroutine already populated the SPKI cache. Callers check errors.Is.
var errAlreadyCached = errors.New("already cached")

const (
	readTimeout = 60 * time.Second // longer than neardirect — two attestation requests
)

// PinnedHandler implements provider.PinnedHandler for the NEAR AI cloud
// gateway. All connections go to cloud-api.near.ai (no resolver). On SPKI
// cache miss, two attestation requests are sent on the same TLS connection:
// one for the gateway and one for the model.
type PinnedHandler struct {
	spkiCache     *attestation.SPKICache
	apiKey        string
	offline       bool
	allowFail     []string
	policy        attestation.MeasurementPolicy
	gatewayPolicy attestation.MeasurementPolicy
	rdVerifier     provider.ReportDataVerifier
	rekorClient    *attestation.RekorClient
	nvidiaVerifier *attestation.NVIDIAVerifier
	verifyQuote    attestation.TDXVerifier
	ctChecker      *tlsct.Checker
	dialFn         func(ctx context.Context, domain string) (*tlsct.Conn, error)

	verifySF singleflight.Group
}

// NewPinnedHandler returns a PinnedHandler for nearcloud.
func NewPinnedHandler(
	spkiCache *attestation.SPKICache,
	apiKey string,
	offline bool,
	allowFail []string,
	policy attestation.MeasurementPolicy,
	gatewayPolicy attestation.MeasurementPolicy,
	rdVerifier provider.ReportDataVerifier,
	rekorClient *attestation.RekorClient,
	nvidiaVerifier *attestation.NVIDIAVerifier,
	getter trust.HTTPSGetter,
) *PinnedHandler {
	checker := tlsct.NewChecker()
	checker.SetEnabled(!offline)

	return &PinnedHandler{
		spkiCache:      spkiCache,
		apiKey:         apiKey,
		offline:        offline,
		allowFail:      allowFail,
		policy:         policy,
		gatewayPolicy:  gatewayPolicy,
		rdVerifier:     rdVerifier,
		rekorClient:    rekorClient,
		nvidiaVerifier: nvidiaVerifier,
		verifyQuote:    attestation.NewTDXVerifier(offline, getter),
		ctChecker:      checker,
	}
}

// SetCTChecker overrides the certificate transparency checker. Intended for tests.
func (h *PinnedHandler) SetCTChecker(checker *tlsct.Checker) {
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

	liveSPKI := conn.SPKI()
	if err := h.ctChecker.CheckTLSState(ctx, domain, conn.TLSState()); err != nil {
		return nil, fmt.Errorf("certificate transparency check failed: %w", err)
	}

	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)

	report, signingKey, err := h.attestIfNeeded(ctx, conn, br, bw, domain, liveSPKI, req.Model)
	if err != nil {
		return nil, err
	}

	if report != nil && report.Blocked() {
		return &provider.PinnedResponse{
			StatusCode: http.StatusBadGateway,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(nil)),
			Report:     report,
			SigningKey: signingKey,
		}, nil
	}

	encBody, session, e2eeHeaders, err := h.encryptBody(req, report, signingKey)
	if err != nil {
		return nil, err
	}

	headers := req.Headers.Clone()
	headers.Set("Host", domain)
	headers.Set("Authorization", "Bearer "+h.apiKey)
	headers.Set("Connection", "close")
	for k := range e2eeHeaders {
		headers.Set(k, e2eeHeaders.Get(k))
	}

	if err := neardirect.WriteHTTPRequest(bw, req.Method, req.Path, headers, encBody); err != nil {
		if session != nil {
			session.Zero()
		}
		return nil, fmt.Errorf("write chat request: %w", err)
	}

	resp, err := http.ReadResponse(br, nil) //nolint:bodyclose // body ownership transfers to NewConnClosingReader
	if err != nil {
		return nil, fmt.Errorf("read chat response: %w", err)
	}

	return &provider.PinnedResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       neardirect.NewConnClosingReader(resp.Body, conn),
		Report:     report,
		SigningKey: signingKey,
		Session:    session,
	}, nil
}

// encryptBody handles NearCloud E2EE encryption, dispatching by endpoint path.
// On error, any allocated session is zeroed before returning. On success, the
// caller is responsible for zeroing the session on subsequent errors.
func (h *PinnedHandler) encryptBody(
	req *provider.PinnedRequest, report *attestation.VerificationReport, signingKey string,
) (encBody []byte, session e2ee.Decryptor, extraHeaders http.Header, err error) {
	if !req.E2EE {
		return req.Body, nil, nil, nil
	}

	// E2EE providers must never downgrade to plaintext.
	if report != nil && !report.ReportDataBindingPassed() {
		return nil, nil, nil, errors.New("E2EE required but tdx_reportdata_binding not passed; refusing plaintext")
	}

	sk := signingKey
	if sk == "" {
		// SPKI cache hit — use the caller-provided signing key.
		sk = req.SigningKey
	}
	if sk == "" {
		return nil, nil, nil, errors.New("E2EE requested but no signing key available")
	}

	raw := &attestation.RawAttestation{SigningKey: sk}
	enc := neardirect.NewE2EE()
	result, sess, _, err := enc.EncryptRequest(req.Body, raw, req.Path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("NearCloud E2EE encrypt: %w", err)
	}

	// NearCloud E2EE protocol headers per NEAR AI docs.
	// Note: X-Model-Pub-Key is intentionally omitted. The gateway uses it
	// to pin requests to a specific model instance by signing key, which
	// causes 502 "model unavailable" errors when the instance restarts or
	// scales. The official NEAR AI E2EE protocol does not require it.
	ncSess, ok := sess.(*e2ee.NearCloudSession)
	if !ok {
		sess.Zero()
		return nil, nil, nil, errors.New("NearCloud E2EE: unexpected session type")
	}
	hdrs := make(http.Header)
	hdrs.Set("X-Signing-Algo", "ed25519")
	hdrs.Set("X-Client-Pub-Key", ncSess.ClientEd25519PubHex())
	hdrs.Set("X-Encryption-Version", "2")

	return result, sess, hdrs, nil
}

// setDialer overrides the TLS dial function. Only accessible from tests
// within this package — unexported to prevent supply-chain redirection of
// gateway connections in production.
func (h *PinnedHandler) setDialer(fn func(ctx context.Context, domain string) (*tlsct.Conn, error)) {
	h.dialFn = fn
}

func (h *PinnedHandler) tlsDial(ctx context.Context, domain string) (*tlsct.Conn, error) {
	return tlsct.Dial(ctx, domain)
}

// attestResult bundles a verification report with its signing key for singleflight.
type attestResult struct {
	report     *attestation.VerificationReport
	signingKey string
}

// attestIfNeeded runs attestation on cache miss via singleflight. On cache hit,
// returns nil report and empty signing key.
func (h *PinnedHandler) attestIfNeeded(
	ctx context.Context,
	conn *tlsct.Conn, br *bufio.Reader, bw *bufio.Writer,
	domain, liveSPKI, model string,
) (*attestation.VerificationReport, string, error) {
	if h.spkiCache.Contains(domain, liveSPKI) {
		slog.DebugContext(ctx, "SPKI cache hit, skipping attestation", "domain", domain, "spki", liveSPKI[:16]+"...")
		return nil, "", nil
	}

	slog.InfoContext(ctx, "SPKI cache miss, fetching gateway+model attestation", "domain", domain, "spki", liveSPKI[:16]+"...")
	v, sfErr, _ := h.verifySF.Do(domain+"\x00"+liveSPKI, func() (any, error) {
		if h.spkiCache.Contains(domain, liveSPKI) {
			return nil, errAlreadyCached
		}
		r, key, err := h.attestOnConn(ctx, conn, br, bw, domain, liveSPKI, model)
		if err != nil {
			return nil, err
		}
		if r.Blocked() {
			blocked := r.BlockedFactors()
			names := make([]string, len(blocked))
			for i, f := range blocked {
				names[i] = f.Name
			}
			slog.WarnContext(ctx, "attestation blocked by policy",
				"domain", domain,
				"model", model,
				"blocked_factors", names,
			)
			for _, f := range blocked {
				slog.DebugContext(ctx, "blocked factor detail",
					"factor", f.Name,
					"detail", f.Detail,
					"tier", f.Tier,
				)
			}
			return attestResult{report: r, signingKey: key}, nil
		}
		h.spkiCache.Add(domain, liveSPKI)
		slog.InfoContext(ctx, "SPKI verified and cached", "domain", domain, "spki", liveSPKI[:16]+"...")
		return attestResult{report: r, signingKey: key}, nil
	})
	if sfErr != nil && !errors.Is(sfErr, errAlreadyCached) {
		return nil, "", fmt.Errorf("attestation on %s: %w", domain, sfErr)
	}
	if v == nil {
		return nil, "", nil
	}
	res, ok := v.(attestResult)
	if !ok {
		return nil, "", fmt.Errorf("singleflight returned unexpected type %T", v)
	}
	return res.report, res.signingKey, nil
}

// attestOnConn sends a single attestation request on the TLS connection that
// returns both gateway and model attestation. The gateway and model share the
// same nonce — the client sends one nonce and both echo it back.
func (h *PinnedHandler) attestOnConn(
	ctx context.Context,
	conn *tlsct.Conn,
	br *bufio.Reader,
	bw *bufio.Writer,
	domain, liveSPKI, model string,
) (*attestation.VerificationReport, string, error) {
	modelNonce := attestation.NewNonce()
	slog.DebugContext(ctx, "nearcloud attestation nonce generated",
		"nonce_prefix", modelNonce.HexPrefix(),
		"domain", domain,
		"model", model,
	)

	gwRaw, raw, err := h.sendAttestationRequest(ctx, conn, br, bw, domain, model, modelNonce)
	if err != nil {
		return nil, "", err
	}

	tdxResult := h.verifyModelTDX(ctx, raw, modelNonce)
	if raw.NvidiaPayload != "" {
		slog.DebugContext(ctx, "verifying NVIDIA payload with nonce",
			"nonce_prefix", modelNonce.HexPrefix(),
			"domain", domain,
			"model", model,
		)
	}
	nvidiaResult, nrasResult := h.verifyModelNVIDIA(ctx, raw, modelNonce)
	pocResult := h.checkPoC(ctx, raw.IntelQuote)

	// Model TLS fingerprint is for the model backend, not the gateway.
	if raw.TLSFingerprint != "" {
		slog.DebugContext(ctx, "model tls_cert_fingerprint present (model backend SPKI, not gateway)",
			"model_fp", provider.Truncate(raw.TLSFingerprint, 16),
			"gateway_spki", provider.Truncate(liveSPKI, 16),
		)
	}

	// Model compose binding.
	var composeResult *attestation.ComposeBindingResult
	if raw.AppCompose != "" && tdxResult != nil && tdxResult.ParseErr == nil {
		composeResult = &attestation.ComposeBindingResult{Checked: true}
		composeResult.Err = attestation.VerifyComposeBinding(raw.AppCompose, tdxResult.MRConfigID)
	}

	// Gateway TLS fingerprint — connection trust anchor. MUST remain inline/fatal.
	if gwRaw.TLSCertFingerprint == "" {
		return nil, "", errors.New("gateway attestation response missing tls_cert_fingerprint")
	}
	match, matchErr := neardirect.ConstantTimeHexEqual(liveSPKI, gwRaw.TLSCertFingerprint)
	if matchErr != nil {
		return nil, "", fmt.Errorf("gateway SPKI comparison: %w", matchErr)
	}
	if !match {
		return nil, "", fmt.Errorf("gateway SPKI %s != attested tls_cert_fingerprint %s",
			provider.Truncate(liveSPKI, 16),
			provider.Truncate(gwRaw.TLSCertFingerprint, 16))
	}
	slog.DebugContext(ctx, "gateway TLS fingerprint matches live SPKI",
		"spki", provider.Truncate(liveSPKI, 16),
		"fp", provider.Truncate(gwRaw.TLSCertFingerprint, 16),
	)

	gatewayTDX := h.verifyGatewayTDX(ctx, gwRaw, modelNonce)
	gatewayPoCResult := h.checkPoC(ctx, gwRaw.IntelQuote)

	// Gateway compose binding.
	var gatewayCompose *attestation.ComposeBindingResult
	if gwRaw.AppCompose != "" && gatewayTDX != nil && gatewayTDX.ParseErr == nil {
		gatewayCompose = &attestation.ComposeBindingResult{Checked: true}
		gatewayCompose.Err = attestation.VerifyComposeBinding(gwRaw.AppCompose, gatewayTDX.MRConfigID)
	}

	// Collect image digests ONLY from TDX-verified compose manifests.
	// Never extract digests from unverified manifests — that would create
	// a false chain of trust (sigstore results for unattested images).
	var modelCD, gatewayCD attestation.ComposeDigests
	if composeResult != nil && composeResult.Err == nil {
		modelCD = attestation.ExtractComposeDigests(raw.AppCompose)
	}
	if gatewayCompose != nil && gatewayCompose.Err == nil {
		gatewayCD = attestation.ExtractComposeDigests(gwRaw.AppCompose)
	}
	allDigests, digestToRepo := attestation.MergeComposeDigests(modelCD, gatewayCD)

	sigstoreResults, rekorResults := h.verifySigstore(ctx, allDigests)

	allowFail := h.allowFail
	if h.offline {
		allowFail = attestation.WithOfflineAllowFail(allowFail)
	}

	report := attestation.BuildReport(&attestation.ReportInput{
		Provider:          "nearcloud",
		Model:             model,
		Raw:               raw,
		Nonce:             modelNonce,
		AllowFail:         allowFail,
		Policy:            h.policy,
		SupplyChainPolicy: SupplyChainPolicy(),
		ImageRepos:        modelCD.Repos,
		GatewayImageRepos: gatewayCD.Repos,
		DigestToRepo:      digestToRepo,
		TDX:               tdxResult,
		Nvidia:            nvidiaResult,
		NvidiaNRAS:        nrasResult,
		PoC:               pocResult,
		Compose:           composeResult,
		Sigstore:          sigstoreResults,
		Rekor:             rekorResults,
		GatewayTDX:        gatewayTDX,
		GatewayPoC:        gatewayPoCResult,
		GatewayNonceHex:   gwRaw.NonceHex,
		GatewayNonce:      modelNonce, // gateway echoes the same nonce
		GatewayCompose:    gatewayCompose,
		GatewayEventLog:   gwRaw.EventLog,
		GatewayPolicy:     h.gatewayPolicy,
		E2EEConfigured:    true,
	})
	return report, raw.SigningKey, nil
}

// sendAttestationRequest writes the attestation HTTP request and reads the
// combined gateway+model response. On error, the caller must close the connection.
func (h *PinnedHandler) sendAttestationRequest(
	ctx context.Context, conn *tlsct.Conn, br *bufio.Reader, bw *bufio.Writer,
	domain, model string, nonce attestation.Nonce,
) (*GatewayRaw, *attestation.RawAttestation, error) {
	q := url.Values{}
	q.Set("model", model)
	q.Set("include_tls_fingerprint", "true")
	q.Set("nonce", nonce.Hex())
	// Intentionally request ed25519 (E2EEv2) — never allow the provider
	// to negotiate a weaker algorithm or regress to an older version.
	q.Set("signing_algo", "ed25519")
	path := attestationPath + "?" + q.Encode()

	attestHeaders := make(http.Header)
	attestHeaders.Set("Host", domain)
	attestHeaders.Set("Authorization", "Bearer "+h.apiKey)
	attestHeaders.Set("Connection", "keep-alive")
	if err := neardirect.WriteHTTPRequest(bw, http.MethodGet, path, attestHeaders, nil); err != nil {
		return nil, nil, fmt.Errorf("write attestation request: %w", err)
	}

	deadline := time.Now().Add(readTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, nil, fmt.Errorf("set read deadline: %w", err)
	}

	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("read attestation response: %w", err)
	}
	defer resp.Body.Close()

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, nil, fmt.Errorf("clear read deadline: %w", err)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2 MiB
	if err != nil {
		return nil, nil, fmt.Errorf("read attestation body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("attestation HTTP %d: %s", resp.StatusCode, provider.Truncate(string(body), 256))
	}

	return ParseGatewayResponse(ctx, body, model)
}

// verifyModelTDX runs TDX quote verification and report data binding for the model.
// Returns nil if no intel_quote is present.
func (h *PinnedHandler) verifyModelTDX(
	ctx context.Context, raw *attestation.RawAttestation, nonce attestation.Nonce,
) *attestation.TDXVerifyResult {
	if raw.IntelQuote == "" {
		return nil
	}
	tdxResult := h.verifyQuote(ctx, raw.IntelQuote)
	if h.rdVerifier != nil && tdxResult.ParseErr == nil {
		detail, rdErr := h.rdVerifier.VerifyReportData(tdxResult.ReportData, raw, nonce)
		tdxResult.ReportDataBindingErr = rdErr
		tdxResult.ReportDataBindingDetail = detail
	}
	return tdxResult
}

// verifyModelNVIDIA runs NVIDIA EAT and NRAS verification for the model.
// Returns nil for either if not applicable.
func (h *PinnedHandler) verifyModelNVIDIA(
	ctx context.Context, raw *attestation.RawAttestation, nonce attestation.Nonce,
) (eat, nras *attestation.NvidiaVerifyResult) {
	if raw.NvidiaPayload != "" {
		eat = attestation.VerifyNVIDIAPayload(ctx, raw.NvidiaPayload, nonce)
	}
	if !h.offline && raw.NvidiaPayload != "" && raw.NvidiaPayload[0] == '{' {
		nras = h.nvidiaVerifier.VerifyNRAS(ctx, raw.NvidiaPayload, tlsct.NewHTTPClient(30*time.Second))
	}
	return eat, nras
}

// verifyGatewayTDX runs TDX quote verification and report data binding for the gateway.
// Returns nil if no intel_quote is present.
func (h *PinnedHandler) verifyGatewayTDX(
	ctx context.Context, gwRaw *GatewayRaw, nonce attestation.Nonce,
) *attestation.TDXVerifyResult {
	if gwRaw.IntelQuote == "" {
		return nil
	}
	gatewayTDX := h.verifyQuote(ctx, gwRaw.IntelQuote)
	if gatewayTDX.ParseErr == nil {
		detail, rdErr := GatewayReportDataVerifier{}.Verify(
			gatewayTDX.ReportData, gwRaw.TLSCertFingerprint, nonce)
		gatewayTDX.ReportDataBindingErr = rdErr
		gatewayTDX.ReportDataBindingDetail = detail
	}
	return gatewayTDX
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

// verifySigstore checks sigstore digests and fetches Rekor provenance for matches.
func (h *PinnedHandler) verifySigstore(
	ctx context.Context, digests []string,
) ([]attestation.SigstoreResult, []attestation.RekorProvenance) {
	if len(digests) == 0 || h.offline || h.rekorClient == nil {
		return nil, nil
	}
	sigstoreResults := h.rekorClient.CheckSigstoreDigests(ctx, digests)
	var rekorResults []attestation.RekorProvenance
	for _, sr := range sigstoreResults {
		if sr.OK {
			rekorResults = append(rekorResults, h.rekorClient.FetchRekorProvenance(ctx, sr.Digest))
		}
	}
	return sigstoreResults, rekorResults
}
