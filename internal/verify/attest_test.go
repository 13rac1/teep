package verify

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
)

// --------------------------------------------------------------------------
// fetchAttestation
// --------------------------------------------------------------------------

type failAttester struct{}

func (failAttester) FetchAttestation(_ context.Context, _ string, _ attestation.Nonce) (*attestation.RawAttestation, error) {
	return nil, errors.New("mock fetch error")
}

type successAttester struct{ raw *attestation.RawAttestation }

func (a successAttester) FetchAttestation(_ context.Context, _ string, _ attestation.Nonce) (*attestation.RawAttestation, error) {
	return a.raw, nil
}

func TestFetchAttestation_Error(t *testing.T) {
	ctx := context.Background()
	nonce := attestation.NewNonce()

	var a provider.Attester = failAttester{}
	_, err := fetchAttestation(ctx, a, "test", "model", nonce)
	t.Logf("fetchAttestation error: %v", err)
	if err == nil {
		t.Fatal("expected error from failing attester")
	}
	if !strings.Contains(err.Error(), "mock fetch error") {
		t.Errorf("error should wrap the mock error: %v", err)
	}
}

func TestFetchAttestation_Success(t *testing.T) {
	ctx := context.Background()
	nonce := attestation.NewNonce()
	want := &attestation.RawAttestation{IntelQuote: "test-quote"}

	raw, err := fetchAttestation(ctx, successAttester{raw: want}, "test", "model", nonce)
	if err != nil {
		t.Fatalf("fetchAttestation unexpected error: %v", err)
	}
	if raw.IntelQuote != want.IntelQuote {
		t.Errorf("IntelQuote = %q, want %q", raw.IntelQuote, want.IntelQuote)
	}
}

// --------------------------------------------------------------------------
// verifyTDX nil-guard
// --------------------------------------------------------------------------

func TestVerifyTDX_EmptyQuote(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{IntelQuote: ""}
	result := verifyTDX(ctx, raw, attestation.Nonce{}, "venice", attestation.VerifyTDXQuoteOffline)
	if result != nil {
		t.Errorf("verifyTDX with empty quote: expected nil, got %v", result)
	}
}

// --------------------------------------------------------------------------
// verifyNVIDIA nil-guard
// --------------------------------------------------------------------------

func TestVerifyNVIDIA_EmptyPayload(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{} // no NvidiaPayload, no GPUEvidence
	eat, nras := verifyNVIDIA(ctx, raw, attestation.Nonce{}, nil, true, attestation.DefaultNVIDIAVerifier())
	if eat != nil {
		t.Errorf("verifyNVIDIA empty: eat = %v, want nil", eat)
	}
	if nras != nil {
		t.Errorf("verifyNVIDIA empty: nras = %v, want nil", nras)
	}
}

// --------------------------------------------------------------------------
// checkPoC nil-guard
// --------------------------------------------------------------------------

func TestCheckPoC_Offline(t *testing.T) {
	ctx := context.Background()
	result := checkPoC(ctx, "some-quote", nil, true)
	if result != nil {
		t.Errorf("checkPoC offline: expected nil, got %v", result)
	}
}

func TestCheckPoC_EmptyQuote(t *testing.T) {
	ctx := context.Background()
	result := checkPoC(ctx, "", nil, false)
	if result != nil {
		t.Errorf("checkPoC empty quote: expected nil, got %v", result)
	}
}

func TestCheckPoC_Online_CanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so PoC network calls fail fast
	// Exercises the non-nil path (offline=false, quote non-empty) without live network.
	result := checkPoC(ctx, "fake-quote", &http.Client{}, false)
	t.Logf("checkPoC canceled ctx result: %v", result)
	// result may be nil or non-nil depending on PoC quorum logic; we just ensure no panic.
}

// --------------------------------------------------------------------------
// verifyNearcloudGateway nil-guard
// --------------------------------------------------------------------------

func TestVerifyNearcloudGateway_NoQuote(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{GatewayIntelQuote: ""}
	tdx, compose, poc := verifyNearcloudGateway(ctx, raw, attestation.Nonce{}, nil, true, attestation.VerifyTDXQuoteOffline)
	if tdx != nil {
		t.Errorf("expected nil tdx, got %v", tdx)
	}
	if compose != nil {
		t.Errorf("expected nil compose, got %v", compose)
	}
	if poc != nil {
		t.Errorf("expected nil poc, got %v", poc)
	}
}

// --------------------------------------------------------------------------
// checkSigstore nil-guard
// --------------------------------------------------------------------------

func TestCheckSigstore_Empty(t *testing.T) {
	ctx := context.Background()
	sig, rekor := checkSigstore(ctx, []string{}, nil, false)
	if sig != nil {
		t.Errorf("expected nil sigstore results for empty digests, got %v", sig)
	}
	if rekor != nil {
		t.Errorf("expected nil rekor results for empty digests, got %v", rekor)
	}
}

// TestCheckSigstore_Online_CanceledContext exercises the main execution path
// (digests non-empty, offline=false) with an immediately-canceled context so
// that Rekor HTTP requests fail fast without real network access.
func TestCheckSigstore_Online_CanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sig, rekor := checkSigstore(ctx, []string{"deadbeefdeadbeefdeadbeef"}, &http.Client{}, false)
	t.Logf("checkSigstore canceled ctx: sig=%v rekor=%v", sig, rekor)
	// We don't assert specific values — just ensure no panic and code is exercised.
}

// rekorProxyTransport redirects all requests to targetHost (scheme+host of a
// test server), preserving path/query. Used to intercept the hardcoded
// https://rekor.sigstore.dev base URL inside checkSigstore.
type rekorProxyTransport struct {
	targetScheme string
	targetHost   string
	inner        http.RoundTripper
}

func (rt *rekorProxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = rt.targetScheme
	clone.URL.Host = rt.targetHost
	return rt.inner.RoundTrip(clone)
}

// TestCheckSigstore_Found exercises the r.OK=true slog branch (line 132) and
// the prov.Err!=nil slog branch (line 148) by mocking the Rekor index/retrieve
// endpoint to return a UUID while returning 500 for the entry fetch.
func TestCheckSigstore_Found_EntryFetchError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("mock rekor: %s %s", r.Method, r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/index/retrieve") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`["test-uuid-abc"]`))
			return
		}
		// Entry fetch → error so prov.Err != nil
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &rekorProxyTransport{
			targetScheme: "http",
			targetHost:   strings.TrimPrefix(ts.URL, "http://"),
			inner:        ts.Client().Transport,
		},
	}

	const digest = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
	sig, rekor := checkSigstore(context.Background(), []string{digest}, client, false)
	t.Logf("sig=%v rekor=%v", sig, rekor)
	if len(sig) != 1 {
		t.Fatalf("expected 1 sigstore result, got %d", len(sig))
	}
	if !sig[0].OK {
		t.Errorf("expected OK=true from mock that returns a UUID, got %v", sig[0])
	}
	// prov.Err != nil branch → rekorResults still appended (line 161)
	if len(rekor) != 1 {
		t.Errorf("expected 1 rekor result (appended even on error), got %d", len(rekor))
	}
}

// TestCheckSigstore_NotFound exercises the r.OK=false && r.Err==nil slog
// branch (line 136) — index/retrieve returns empty UUID list.
func TestCheckSigstore_NotFound_StatusOnly(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &rekorProxyTransport{
			targetScheme: "http",
			targetHost:   strings.TrimPrefix(ts.URL, "http://"),
			inner:        ts.Client().Transport,
		},
	}

	const digest = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
	sig, rekor := checkSigstore(context.Background(), []string{digest}, client, false)
	t.Logf("sig=%v rekor=%v", sig, rekor)
	if len(sig) != 1 {
		t.Fatalf("expected 1 sigstore result, got %d", len(sig))
	}
	if sig[0].OK {
		t.Errorf("expected OK=false for empty UUID list, got OK=true")
	}
	if sig[0].Err != nil {
		t.Errorf("expected nil Err for not-found (status only), got %v", sig[0].Err)
	}
	if rekor != nil {
		t.Errorf("expected nil rekor results for not-found, got %v", rekor)
	}
}

func TestCheckSigstore_Offline(t *testing.T) {
	ctx := context.Background()
	sig, rekor := checkSigstore(ctx, []string{"sha256:abc123"}, nil, true)
	if sig != nil {
		t.Errorf("expected nil sigstore results in offline mode, got %v", sig)
	}
	if rekor != nil {
		t.Errorf("expected nil rekor results in offline mode, got %v", rekor)
	}
}

// --------------------------------------------------------------------------
// verifyTDX — non-empty quote (parse error path)
// --------------------------------------------------------------------------

func TestVerifyTDX_WithQuote_ParseError(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{IntelQuote: "not-a-real-tdx-quote"}
	result := verifyTDX(ctx, raw, attestation.Nonce{}, "venice", attestation.VerifyTDXQuoteOffline)
	if result == nil {
		t.Fatal("verifyTDX with non-empty quote should return non-nil result")
	}
	t.Logf("verifyTDX parse error: %v", result.ParseErr)
}

func TestVerifyTDX_WithQuote_NoVerifier(t *testing.T) {
	ctx := context.Background()
	// "chutes" has no ReportDataVerifier — exercises the verifier==nil branch.
	raw := &attestation.RawAttestation{IntelQuote: "not-a-real-tdx-quote"}
	result := verifyTDX(ctx, raw, attestation.Nonce{}, "chutes", attestation.VerifyTDXQuoteOffline)
	if result == nil {
		t.Fatal("verifyTDX with non-empty quote should return non-nil result")
	}
}

// --------------------------------------------------------------------------
// verifyNVIDIA — payload and GPUEvidence paths
// --------------------------------------------------------------------------

func TestVerifyNVIDIA_WithPayload_Offline(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{NvidiaPayload: `{"version":"1.0"}`}
	eat, nras := verifyNVIDIA(ctx, raw, attestation.Nonce{}, nil, true, attestation.DefaultNVIDIAVerifier())
	// With offline=true NRAS is skipped; VerifyNVIDIAPayload runs but will error.
	if eat == nil {
		t.Fatal("expected non-nil EAT result for non-empty NvidiaPayload")
	}
	if nras != nil {
		t.Errorf("expected nil NRAS result in offline mode, got %v", nras)
	}
	t.Logf("verifyNVIDIA EAT err: %v", eat.SignatureErr)
}

func TestVerifyNVIDIA_WithPayload_NonJSON(t *testing.T) {
	ctx := context.Background()
	// Payload starts with non-'{' — NRAS call is skipped even when online.
	raw := &attestation.RawAttestation{NvidiaPayload: "deadbeef"}
	eat, nras := verifyNVIDIA(ctx, raw, attestation.Nonce{}, nil, false, attestation.DefaultNVIDIAVerifier())
	if eat == nil {
		t.Error("expected non-nil EAT result for non-empty NvidiaPayload")
	}
	if nras != nil {
		t.Errorf("expected nil NRAS result for non-JSON payload, got %v", nras)
	}
}

func TestVerifyNVIDIA_GPUEvidence_ValidNonce(t *testing.T) {
	ctx := context.Background()
	nonce := attestation.NewNonce()
	raw := &attestation.RawAttestation{
		GPUEvidence: []attestation.GPUEvidence{{
			Certificate: "fake-cert",
			Evidence:    "fake-evidence",
		}},
		Nonce: nonce.Hex(),
	}
	eat, nras := verifyNVIDIA(ctx, raw, nonce, nil, true, attestation.DefaultNVIDIAVerifier())
	// VerifyNVIDIAGPUDirect runs but fails on fake data; NRAS skipped (offline).
	if eat == nil {
		t.Fatal("expected non-nil EAT result for GPUEvidence with valid nonce")
	}
	if nras != nil {
		t.Errorf("expected nil NRAS in offline mode, got %v", nras)
	}
	t.Logf("verifyNVIDIA GPU valid nonce: SignatureErr=%v", eat.SignatureErr)
}

func TestVerifyNVIDIA_WithPayload_JSONOnline_CanceledCtx(t *testing.T) {
	// JSON payload that starts with '{' triggers the NRAS call path.
	// Canceled context makes the NRAS call fail fast without real network.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	raw := &attestation.RawAttestation{NvidiaPayload: `{"version":"1.0"}`}
	eat, nras := verifyNVIDIA(ctx, raw, attestation.Nonce{}, &http.Client{}, false, attestation.DefaultNVIDIAVerifier())
	if eat == nil {
		t.Fatal("expected non-nil EAT result for non-empty NvidiaPayload")
	}
	t.Logf("verifyNVIDIA NRAS path: eat.SignatureErr=%v, nras=%v", eat.SignatureErr, nras)
}

func TestVerifyNVIDIA_GPUEvidence_BadNonce(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{
		GPUEvidence: []attestation.GPUEvidence{{
			Certificate: "fake-cert",
			Evidence:    "fake-evidence",
		}},
		Nonce: "not-a-valid-hex-nonce",
	}
	eat, nras := verifyNVIDIA(ctx, raw, attestation.Nonce{}, nil, true, attestation.DefaultNVIDIAVerifier())
	if eat == nil {
		t.Fatal("expected non-nil EAT result for bad nonce")
	}
	if eat.SignatureErr == nil {
		t.Error("expected SignatureErr for bad server nonce")
	}
	if nras != nil {
		t.Errorf("expected nil NRAS result (early return), got %v", nras)
	}
	t.Logf("verifyNVIDIA bad nonce err: %v", eat.SignatureErr)
}

// --------------------------------------------------------------------------
// verifyNearcloudGateway — non-empty GatewayIntelQuote (parse error path)
// --------------------------------------------------------------------------

func TestVerifyNVIDIA_GPUEvidence_Online_CanceledCtx(t *testing.T) {
	// Exercises the GPUEvidence online NRAS path (!offline && len(raw.GPUEvidence) > 0).
	// Canceled context makes NRAS call fail fast without real network.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	nonce := attestation.NewNonce()
	raw := &attestation.RawAttestation{
		GPUEvidence: []attestation.GPUEvidence{{
			Certificate: "fake-cert",
			Evidence:    "fake-evidence",
		}},
		Nonce: nonce.Hex(),
	}
	eat, _ := verifyNVIDIA(ctx, raw, nonce, &http.Client{}, false, attestation.DefaultNVIDIAVerifier())
	t.Logf("verifyNVIDIA GPU online canceled: eat=%v", eat)
	// We only verify no panic; eat may be nil or non-nil depending on parsing.
}

// --------------------------------------------------------------------------
// verifySEV
// --------------------------------------------------------------------------

func TestVerifySEV_EmptyReport(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{SEVReportBytes: nil}
	result := verifySEV(ctx, raw, attestation.Nonce{}, "tinfoil_v3_cloud", attestation.VerifySEVReportOffline)
	if result != nil {
		t.Errorf("verifySEV with nil report: expected nil, got %v", result)
	}
}

func TestVerifySEV_WithReport_ParseError(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{SEVReportBytes: []byte("not-a-real-sev-report")}
	result := verifySEV(ctx, raw, attestation.Nonce{}, "tinfoil_v3_cloud", attestation.VerifySEVReportOffline)
	if result == nil {
		t.Fatal("verifySEV with non-empty report should return non-nil result")
	}
	t.Logf("verifySEV parse error: %v", result.ParseErr)
}

func TestVerifySEV_WithReport_HasRDVerifier(t *testing.T) {
	ctx := context.Background()
	// A valid-length (but invalid content) SEV report — 1184 bytes.
	report := make([]byte, 1184)
	raw := &attestation.RawAttestation{SEVReportBytes: report}
	result := verifySEV(ctx, raw, attestation.Nonce{}, "tinfoil_v3_cloud", attestation.VerifySEVReportOffline)
	if result == nil {
		t.Fatal("verifySEV with 1184-byte report should return non-nil result")
	}
	// The report data is zeroed, so REPORTDATA binding will fail, but verifySEV should still run.
	t.Logf("verifySEV result: ParseErr=%v, SignatureErr=%v", result.ParseErr, result.SignatureErr)
}

// --------------------------------------------------------------------------
// verifyTinfoilSupplyChain
// --------------------------------------------------------------------------

func TestVerifyTinfoilSupplyChain_NonTinfoilFormat(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{BackendFormat: attestation.FormatDstack}
	result := verifyTinfoilSupplyChain(ctx, raw, nil, nil, "tinfoil_v3_direct", "model",
		attestation.MeasurementPolicy{}, true)
	if result != nil {
		t.Errorf("verifyTinfoilSupplyChain for non-Tinfoil format: expected nil, got %v", result)
	}
}

func TestVerifyTinfoilSupplyChain_TinfoilFormat_Offline(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{BackendFormat: attestation.FormatTinfoil}
	result := verifyTinfoilSupplyChain(ctx, raw, nil, nil, "tinfoil_v3_direct", "llama3-3-70b",
		attestation.MeasurementPolicy{}, true)
	if result == nil {
		t.Fatal("verifyTinfoilSupplyChain offline: expected non-nil result")
	}
	// In offline mode, Sigstore fetch is skipped but GPUHashBound etc. are still set.
	t.Logf("offline result: GPUHashBound=%v, SigstoreVerified=%v", result.GPUHashBound, result.SigstoreVerified)
}

func TestVerifyTinfoilSupplyChain_GPUBindingFromSEV(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{BackendFormat: attestation.FormatTinfoil}
	sev := &attestation.SEVVerifyResult{
		ReportDataBindingDetail: "gpu_bound=true, nvswitch_bound=true",
	}
	result := verifyTinfoilSupplyChain(ctx, raw, nil, sev, "tinfoil_v3_direct", "test-model",
		attestation.MeasurementPolicy{}, true)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.GPUHashBound {
		t.Error("expected GPUHashBound=true from SEV binding detail")
	}
	if !result.NVSwitchHashBound {
		t.Error("expected NVSwitchHashBound=true from SEV binding detail")
	}
}

func TestVerifyTinfoilSupplyChain_GPUBindingFromTDX(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{BackendFormat: attestation.FormatTinfoil}
	tdx := &attestation.TDXVerifyResult{
		ReportDataBindingDetail: "gpu_bound=true",
		ParseErr:                errors.New("not a real TDX quote"), // prevent TDX policy checks
	}
	result := verifyTinfoilSupplyChain(ctx, raw, tdx, nil, "tinfoil_v3_direct", "test-model",
		attestation.MeasurementPolicy{}, true)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.GPUHashBound {
		t.Error("expected GPUHashBound=true from TDX binding detail")
	}
	if result.NVSwitchHashBound {
		t.Error("expected NVSwitchHashBound=false (not in TDX binding detail)")
	}
}

// --------------------------------------------------------------------------
// truncTo
// --------------------------------------------------------------------------

func TestTruncTo(t *testing.T) {
	if got := truncTo("abcdef", 4); got != "abcd" {
		t.Errorf("truncTo(abcdef,4) = %q, want abcd", got)
	}
	if got := truncTo("ab", 10); got != "ab" {
		t.Errorf("truncTo(ab,10) = %q, want ab", got)
	}
	if got := truncTo("", 5); got != "" {
		t.Errorf("truncTo('',5) = %q, want ''", got)
	}
}

func TestVerifyNearcloudGateway_WithQuote_ParseError(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{GatewayIntelQuote: "not-a-real-tdx-quote"}
	tdx, compose, poc := verifyNearcloudGateway(ctx, raw, attestation.Nonce{}, nil, true, attestation.VerifyTDXQuoteOffline)
	if tdx == nil {
		t.Fatal("expected non-nil TDX result for non-empty GatewayIntelQuote")
	}
	t.Logf("gateway TDX parse error: %v", tdx.ParseErr)
	// ParseErr != nil → compose skipped, poc skipped (offline=true).
	if compose != nil {
		t.Errorf("expected nil compose when TDX parse fails, got %v", compose)
	}
	if poc != nil {
		t.Errorf("expected nil poc in offline mode, got %v", poc)
	}
}

// --------------------------------------------------------------------------
// stub TDX/SEV verifiers for coverage of report-data binding paths
// --------------------------------------------------------------------------

func stubTDXVerifier(result *attestation.TDXVerifyResult) attestation.TDXVerifier {
	return func(_ context.Context, _ string) *attestation.TDXVerifyResult {
		return result
	}
}

func stubSEVVerifier(result *attestation.SEVVerifyResult) attestation.SEVVerifier {
	return func(_ context.Context, _ []byte) *attestation.SEVVerifyResult {
		return result
	}
}

// --------------------------------------------------------------------------
// verifyTDX — report data binding paths with ParseErr == nil
// --------------------------------------------------------------------------

func TestVerifyTDX_ParseOK_Tinfoil(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{
		IntelQuote:    "fakequote",
		BackendFormat: attestation.FormatTinfoil,
	}
	tdxResult := &attestation.TDXVerifyResult{} // ParseErr == nil
	result := verifyTDX(ctx, raw, attestation.Nonce{}, "tinfoil_v3_cloud", stubTDXVerifier(tdxResult))
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	// Tinfoil has a ReportDataVerifier. With a zeroed ReportData + zeroed Nonce,
	// the binding check will likely fail — that's fine, we're covering the code path.
	t.Logf("verifyTDX(tinfoil, ParseOK): ReportDataBindingErr=%v Detail=%q",
		result.ReportDataBindingErr, result.ReportDataBindingDetail)
}

func TestVerifyTDX_ParseOK_Venice(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{
		IntelQuote:    "fakequote",
		BackendFormat: attestation.FormatDstack,
	}
	tdxResult := &attestation.TDXVerifyResult{} // ParseErr == nil
	result := verifyTDX(ctx, raw, attestation.Nonce{}, "venice", stubTDXVerifier(tdxResult))
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	t.Logf("verifyTDX(venice, ParseOK): ReportDataBindingErr=%v Detail=%q",
		result.ReportDataBindingErr, result.ReportDataBindingDetail)
}

func TestVerifyTDX_ParseOK_NoVerifier(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{
		IntelQuote:    "fakequote",
		BackendFormat: attestation.FormatDstack,
	}
	tdxResult := &attestation.TDXVerifyResult{} // ParseErr == nil
	// "unknown_provider" has no ReportDataVerifier (returns nil from newReportDataVerifier).
	result := verifyTDX(ctx, raw, attestation.Nonce{}, "unknown_provider", stubTDXVerifier(tdxResult))
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.ReportDataBindingErr != nil {
		t.Errorf("expected nil ReportDataBindingErr for provider without verifier, got %v", result.ReportDataBindingErr)
	}
}

// --------------------------------------------------------------------------
// verifySEV — report data binding paths with ParseErr == nil
// --------------------------------------------------------------------------

func TestVerifySEV_ParseOK_Tinfoil(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{
		SEVReportBytes: make([]byte, 100),
		BackendFormat:  attestation.FormatTinfoil,
	}
	sevResult := &attestation.SEVVerifyResult{} // ParseErr == nil
	result := verifySEV(ctx, raw, attestation.Nonce{}, "tinfoil_v3_cloud", stubSEVVerifier(sevResult))
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	t.Logf("verifySEV(tinfoil, ParseOK): ReportDataBindingErr=%v Detail=%q",
		result.ReportDataBindingErr, result.ReportDataBindingDetail)
}

func TestVerifySEV_ParseOK_NoVerifier(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{
		SEVReportBytes: make([]byte, 100),
		BackendFormat:  attestation.FormatDstack,
	}
	sevResult := &attestation.SEVVerifyResult{} // ParseErr == nil
	// "unknown_provider" has no ReportDataVerifier (returns nil from newReportDataVerifier).
	result := verifySEV(ctx, raw, attestation.Nonce{}, "unknown_provider", stubSEVVerifier(sevResult))
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.ReportDataBindingErr != nil {
		t.Errorf("expected nil ReportDataBindingErr for provider without verifier, got %v", result.ReportDataBindingErr)
	}
}

// --------------------------------------------------------------------------
// verifyNearcloudGateway — ParseErr == nil paths
// --------------------------------------------------------------------------

func TestVerifyNearcloudGateway_ParseOK_NoCompose(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{GatewayIntelQuote: "fakequote"}
	tdxResult := &attestation.TDXVerifyResult{} // ParseErr == nil
	tdx, compose, _ := verifyNearcloudGateway(ctx, raw, attestation.Nonce{}, nil, true, stubTDXVerifier(tdxResult))
	if tdx == nil {
		t.Fatal("expected non-nil TDX result")
	}
	t.Logf("gateway ParseOK: ReportDataBindingErr=%v", tdx.ReportDataBindingErr)
	// No GatewayAppCompose → compose should be nil.
	if compose != nil {
		t.Errorf("expected nil compose when GatewayAppCompose is empty, got %v", compose)
	}
}

func TestVerifyNearcloudGateway_ParseOK_WithCompose(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{
		GatewayIntelQuote: "fakequote",
		GatewayAppCompose: `{"docker_compose_file":"services:\n  app:\n    image: myapp:latest\n"}`,
	}
	tdxResult := &attestation.TDXVerifyResult{} // ParseErr == nil, MRConfigID zero
	tdx, compose, _ := verifyNearcloudGateway(ctx, raw, attestation.Nonce{}, nil, true, stubTDXVerifier(tdxResult))
	if tdx == nil {
		t.Fatal("expected non-nil TDX result")
	}
	if compose == nil {
		t.Fatal("expected non-nil compose when GatewayAppCompose is set")
	}
	if !compose.Checked {
		t.Error("compose.Checked should be true")
	}
	// MRConfigID is zero → compose binding will fail.
	if compose.Err == nil {
		t.Error("expected compose binding error with zeroed MRConfigID")
	}
}

// --------------------------------------------------------------------------
// verifyTinfoilSupplyChain — TDX policy check path
// --------------------------------------------------------------------------

func TestVerifyTinfoilSupplyChain_TDXPolicyCheck(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{
		BackendFormat: attestation.FormatTinfoil,
	}
	tdxResult := &attestation.TDXVerifyResult{} // ParseErr == nil
	// Use a model name that maps to a known repo. RepoForModel("gemma4-31b")
	// returns "tinfoilsh/confidential-gemma4-31b".
	result := verifyTinfoilSupplyChain(ctx, raw, tdxResult, nil, "tinfoil_v3_direct", "gemma4-31b", attestation.MeasurementPolicy{}, true)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	// The result should have TDXPolicyDetail set (from CheckTDXPolicy).
	if result.TDXPolicyDetail == "" {
		t.Error("expected non-empty TDXPolicyDetail")
	}
	t.Logf("TDXPolicyDetail: %s", result.TDXPolicyDetail)
	t.Logf("TDXPolicyErr: %v", result.TDXPolicyErr)
}
