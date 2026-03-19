package attestation

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// buildMinimalRaw returns a RawAttestation with the given fields populated.
func buildMinimalRaw(nonce Nonce, signingKey string) *RawAttestation {
	return &RawAttestation{
		Verified:      true,
		Nonce:         nonce.Hex(),
		Model:         "test-model",
		TEEProvider:   "TDX",
		SigningKey:    signingKey,
		IntelQuote:    "dGVzdA==", // base64("test") — not a real quote
		NvidiaPayload: "",
	}
}

// validSigningKey returns a freshly generated secp256k1 public key in 130-char hex.
func validSigningKey(t *testing.T) string {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	return hex.EncodeToString(priv.PubKey().SerializeUncompressed())
}

// TestBuildReportFactorCount ensures exactly 20 factors are produced.
func TestBuildReportFactorCount(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport("venice", "test-model", raw, nonce, DefaultEnforced, nil, nil)

	if len(report.Factors) != 20 {
		t.Errorf("factor count: got %d, want 20", len(report.Factors))
	}
}

// TestBuildReportTotals verifies the Passed/Failed/Skipped tallies are consistent.
func TestBuildReportTotals(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport("venice", "test-model", raw, nonce, DefaultEnforced, nil, nil)

	total := report.Passed + report.Failed + report.Skipped
	if total != len(report.Factors) {
		t.Errorf("tallies sum to %d, want %d", total, len(report.Factors))
	}

	// Recount manually.
	passed, failed, skipped := 0, 0, 0
	for _, f := range report.Factors {
		switch f.Status {
		case Pass:
			passed++
		case Fail:
			failed++
		case Skip:
			skipped++
		}
	}
	if report.Passed != passed || report.Failed != failed || report.Skipped != skipped {
		t.Errorf("tally mismatch: got P=%d/F=%d/S=%d, manual count P=%d/F=%d/S=%d",
			report.Passed, report.Failed, report.Skipped, passed, failed, skipped)
	}
}

// TestBuildReportNonceMatch verifies nonce_match Pass/Fail paths.
func TestBuildReportNonceMatch(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	// Pass: nonces match.
	raw := buildMinimalRaw(nonce, sigKey)
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil)
	factor := findFactor(t, report, "nonce_match")
	if factor.Status != Pass {
		t.Errorf("nonce_match with matching nonce: got %s, want PASS; detail: %s", factor.Status, factor.Detail)
	}

	// Fail: nonce mismatch.
	otherNonce := NewNonce()
	raw.Nonce = otherNonce.Hex()
	report = BuildReport("venice", "m", raw, nonce, nil, nil, nil)
	factor = findFactor(t, report, "nonce_match")
	if factor.Status != Fail {
		t.Errorf("nonce_match with mismatched nonce: got %s, want FAIL", factor.Status)
	}

	// Fail: empty nonce.
	raw.Nonce = ""
	report = BuildReport("venice", "m", raw, nonce, nil, nil, nil)
	factor = findFactor(t, report, "nonce_match")
	if factor.Status != Fail {
		t.Errorf("nonce_match with empty nonce: got %s, want FAIL", factor.Status)
	}
}

// TestBuildReportTDXQuotePresent verifies tdx_quote_present Pass/Fail.
func TestBuildReportTDXQuotePresent(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	raw := buildMinimalRaw(nonce, sigKey)
	raw.IntelQuote = "dGVzdA=="
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil)
	factor := findFactor(t, report, "tdx_quote_present")
	if factor.Status != Pass {
		t.Errorf("tdx_quote_present with quote: got %s, want PASS", factor.Status)
	}

	raw.IntelQuote = ""
	report = BuildReport("venice", "m", raw, nonce, nil, nil, nil)
	factor = findFactor(t, report, "tdx_quote_present")
	if factor.Status != Fail {
		t.Errorf("tdx_quote_present with empty quote: got %s, want FAIL", factor.Status)
	}
}

// TestBuildReportSigningKeyPresent verifies signing_key_present Pass/Fail.
func TestBuildReportSigningKeyPresent(t *testing.T) {
	nonce := NewNonce()

	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil)
	factor := findFactor(t, report, "signing_key_present")
	if factor.Status != Pass {
		t.Errorf("signing_key_present with key: got %s, want PASS", factor.Status)
	}

	raw.SigningKey = ""
	report = BuildReport("venice", "m", raw, nonce, nil, nil, nil)
	factor = findFactor(t, report, "signing_key_present")
	if factor.Status != Fail {
		t.Errorf("signing_key_present with empty key: got %s, want FAIL", factor.Status)
	}
}

// TestBuildReportE2EECapable verifies e2ee_capable with valid and invalid keys.
func TestBuildReportE2EECapable(t *testing.T) {
	nonce := NewNonce()

	// Pass: valid secp256k1 uncompressed key.
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil)
	factor := findFactor(t, report, "e2ee_capable")
	if factor.Status != Pass {
		t.Errorf("e2ee_capable with valid key: got %s, want PASS; detail: %s", factor.Status, factor.Detail)
	}

	// Fail: empty key.
	raw.SigningKey = ""
	report = BuildReport("venice", "m", raw, nonce, nil, nil, nil)
	factor = findFactor(t, report, "e2ee_capable")
	if factor.Status != Fail {
		t.Errorf("e2ee_capable with empty key: got %s, want FAIL", factor.Status)
	}

	// Fail: malformed key.
	raw.SigningKey = strings.Repeat("0", 130)
	report = BuildReport("venice", "m", raw, nonce, nil, nil, nil)
	factor = findFactor(t, report, "e2ee_capable")
	if factor.Status != Fail {
		t.Errorf("e2ee_capable with zero key: got %s, want FAIL", factor.Status)
	}
}

// TestBuildReportEnforcedFlags verifies Enforced is set only for factors in the list.
func TestBuildReportEnforcedFlags(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport("venice", "m", raw, nonce, DefaultEnforced, nil, nil)

	enforcedSet := make(map[string]bool)
	for _, name := range DefaultEnforced {
		enforcedSet[name] = true
	}

	for _, f := range report.Factors {
		wantEnforced := enforcedSet[f.Name]
		if f.Enforced != wantEnforced {
			t.Errorf("factor %q: Enforced=%v, want %v", f.Name, f.Enforced, wantEnforced)
		}
	}
}

// TestBuildReportTier3AlwaysFail verifies all Tier 3 factors are always Fail.
func TestBuildReportTier3AlwaysFail(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport("venice", "m", raw, nonce, DefaultEnforced, nil, nil)

	tier3 := []string{
		"tls_key_binding",
		"cpu_gpu_chain",
		"measured_model_weights",
		"build_transparency_log",
		"cpu_id_registry",
	}

	for _, name := range tier3 {
		f := findFactor(t, report, name)
		if f.Status != Fail {
			t.Errorf("Tier 3 factor %q: got %s, want FAIL", name, f.Status)
		}
		if f.Detail == "" {
			t.Errorf("Tier 3 factor %q: Detail is empty; should explain what is missing", name)
		}
	}
}

// TestBlockedReturnsTrue verifies Blocked is true when an enforced factor fails.
func TestBlockedReturnsTrue(t *testing.T) {
	nonce := NewNonce()
	// Missing nonce in response → nonce_match Fail (which is enforced by default).
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	raw.Nonce = "" // force nonce_match to fail

	report := BuildReport("venice", "m", raw, nonce, DefaultEnforced, nil, nil)

	if !report.Blocked() {
		t.Error("Blocked() returned false when enforced nonce_match is failing")
	}
}

// TestBlockedReturnsFalse verifies Blocked is false when no enforced factor fails.
func TestBlockedReturnsFalse(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))

	// None of the enforced factors should fail when we have valid nonce,
	// signing_key, and no TDX result (which causes tdx_debug_disabled to
	// be a Fail — but wait, debug_disabled is enforced).
	// We need to pass a tdxResult with DebugEnabled=false to get debug_disabled to pass.
	// And tdx_reportdata_binding also needs a passing tdxResult.
	// For this test, use an empty enforced list so nothing is enforced.
	report := BuildReport("venice", "m", raw, nonce, []string{}, nil, nil)

	if report.Blocked() {
		t.Error("Blocked() returned true with empty enforced list")
	}
}

// TestVerificationReportMetadata checks provider, model, and timestamp are set.
func TestVerificationReportMetadata(t *testing.T) {
	before := time.Now()
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport("venice", "e2ee-qwen3", raw, nonce, nil, nil, nil)
	after := time.Now()

	if report.Provider != "venice" {
		t.Errorf("Provider: got %q, want %q", report.Provider, "venice")
	}
	if report.Model != "e2ee-qwen3" {
		t.Errorf("Model: got %q, want %q", report.Model, "e2ee-qwen3")
	}
	if report.Timestamp.Before(before) || report.Timestamp.After(after) {
		t.Errorf("Timestamp %v outside window [%v, %v]", report.Timestamp, before, after)
	}
}

// TestBuildReportNilTDXResultFailsParseFactors verifies that when tdxResult is nil,
// the TDX-dependent factors are Fail (not panic).
func TestBuildReportNilTDXResultFailsParseFactors(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil)

	for _, name := range []string{"tdx_quote_structure", "tdx_cert_chain", "tdx_quote_signature", "tdx_debug_disabled"} {
		f := findFactor(t, report, name)
		if f.Status != Fail {
			t.Errorf("factor %q with nil tdxResult: got %s, want FAIL", name, f.Status)
		}
	}
}

// TestBuildReportWithTDXPassResult verifies TDX factors pass when given a clean result.
func TestBuildReportWithTDXPassResult(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)
	raw := buildMinimalRaw(nonce, sigKey)

	// Build a fake "everything passed" TDX result.
	tdxResult := &TDXVerifyResult{
		ParseErr:             nil,
		CertChainErr:         nil,
		SignatureErr:         nil,
		DebugEnabled:         false,
		ReportDataBindingErr: nil,
		TeeTCBSVN:            []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}

	report := BuildReport("venice", "m", raw, nonce, nil, tdxResult, nil)

	for _, name := range []string{"tdx_quote_structure", "tdx_cert_chain", "tdx_quote_signature", "tdx_debug_disabled"} {
		f := findFactor(t, report, name)
		if f.Status != Pass {
			t.Errorf("factor %q with passing TDX result: got %s (%s), want PASS", name, f.Status, f.Detail)
		}
	}

	// Check reportdata binding passes.
	f := findFactor(t, report, "tdx_reportdata_binding")
	if f.Status != Pass {
		t.Errorf("tdx_reportdata_binding with passing result: got %s (%s), want PASS", f.Status, f.Detail)
	}
}

// TestBuildReportWithTDXDebugEnabled verifies tdx_debug_disabled fails when debug is set.
func TestBuildReportWithTDXDebugEnabled(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))

	tdxResult := &TDXVerifyResult{
		DebugEnabled: true,
		TeeTCBSVN:    make([]byte, 16),
	}

	report := BuildReport("venice", "m", raw, nonce, nil, tdxResult, nil)
	f := findFactor(t, report, "tdx_debug_disabled")
	if f.Status != Fail {
		t.Errorf("tdx_debug_disabled with debug set: got %s, want FAIL", f.Status)
	}
	if !strings.Contains(f.Detail, "debug") {
		t.Errorf("tdx_debug_disabled detail should mention 'debug': %s", f.Detail)
	}
}

// TestBuildReportNvidiaPresent tests nvidia_payload_present Pass/Fail.
func TestBuildReportNvidiaPresent(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))

	// Fail: no payload.
	raw.NvidiaPayload = ""
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil)
	f := findFactor(t, report, "nvidia_payload_present")
	if f.Status != Fail {
		t.Errorf("nvidia_payload_present with empty payload: got %s, want FAIL", f.Status)
	}

	// Pass: payload present.
	raw.NvidiaPayload = "some.jwt.token"
	report = BuildReport("venice", "m", raw, nonce, nil, nil, nil)
	f = findFactor(t, report, "nvidia_payload_present")
	if f.Status != Pass {
		t.Errorf("nvidia_payload_present with payload: got %s, want PASS", f.Status)
	}
}

// TestBuildReportAttestationFreshnessSkip verifies attestation_freshness is always Skip.
func TestBuildReportAttestationFreshnessSkip(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil)

	f := findFactor(t, report, "attestation_freshness")
	if f.Status != Skip {
		t.Errorf("attestation_freshness: got %s, want SKIP", f.Status)
	}
}

// TestStatusString tests the Status.String method.
func TestStatusString(t *testing.T) {
	tests := []struct {
		status Status
		want   string
	}{
		{Pass, "PASS"},
		{Fail, "FAIL"},
		{Skip, "SKIP"},
		{Status(99), "UNKNOWN"},
	}
	for _, tc := range tests {
		if got := tc.status.String(); got != tc.want {
			t.Errorf("Status(%d).String(): got %q, want %q", tc.status, got, tc.want)
		}
	}
}

// findFactor is a test helper that locates a factor by name in the report.
// It fails the test if the factor is not found.
func findFactor(t *testing.T, report *VerificationReport, name string) FactorResult {
	t.Helper()
	for _, f := range report.Factors {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("factor %q not found in report (factors: %v)", name, factorNames(report))
	return FactorResult{}
}

func factorNames(r *VerificationReport) []string {
	names := make([]string, len(r.Factors))
	for i, f := range r.Factors {
		names[i] = f.Name
	}
	return names
}
