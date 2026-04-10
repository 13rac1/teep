package verify

import (
	"context"
	"errors"
	"net/http"
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
	result := verifyTDX(ctx, raw, attestation.Nonce{}, "venice", true)
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
	eat, nras := verifyNVIDIA(ctx, raw, attestation.Nonce{}, nil, true)
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
	tdx, compose, poc := verifyNearcloudGateway(ctx, raw, attestation.Nonce{}, nil, true)
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
	result := verifyTDX(ctx, raw, attestation.Nonce{}, "venice", true)
	if result == nil {
		t.Fatal("verifyTDX with non-empty quote should return non-nil result")
	}
	t.Logf("verifyTDX parse error: %v", result.ParseErr)
}

func TestVerifyTDX_WithQuote_NoVerifier(t *testing.T) {
	ctx := context.Background()
	// "chutes" has no ReportDataVerifier — exercises the verifier==nil branch.
	raw := &attestation.RawAttestation{IntelQuote: "not-a-real-tdx-quote"}
	result := verifyTDX(ctx, raw, attestation.Nonce{}, "chutes", true)
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
	eat, nras := verifyNVIDIA(ctx, raw, attestation.Nonce{}, nil, true)
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
	eat, nras := verifyNVIDIA(ctx, raw, attestation.Nonce{}, nil, false)
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
	eat, nras := verifyNVIDIA(ctx, raw, nonce, nil, true)
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
	eat, nras := verifyNVIDIA(ctx, raw, attestation.Nonce{}, &http.Client{}, false)
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
	eat, nras := verifyNVIDIA(ctx, raw, attestation.Nonce{}, nil, true)
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
	eat, _ := verifyNVIDIA(ctx, raw, nonce, &http.Client{}, false)
	t.Logf("verifyNVIDIA GPU online canceled: eat=%v", eat)
	// We only verify no panic; eat may be nil or non-nil depending on parsing.
}

func TestVerifyNearcloudGateway_WithQuote_ParseError(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{GatewayIntelQuote: "not-a-real-tdx-quote"}
	tdx, compose, poc := verifyNearcloudGateway(ctx, raw, attestation.Nonce{}, nil, true)
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
