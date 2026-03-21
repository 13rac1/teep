package attestation

import (
	"encoding/hex"
	"errors"
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

// TestBuildReportFactorCount ensures exactly 21 factors are produced.
func TestBuildReportFactorCount(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport("venice", "test-model", raw, nonce, DefaultEnforced, nil, nil, nil, nil, nil, nil)

	if len(report.Factors) != 23 {
		t.Errorf("factor count: got %d, want 23", len(report.Factors))
	}
}

// TestBuildReportTotals verifies the Passed/Failed/Skipped tallies are consistent.
func TestBuildReportTotals(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport("venice", "test-model", raw, nonce, DefaultEnforced, nil, nil, nil, nil, nil, nil)

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
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)
	factor := findFactor(t, report, "nonce_match")
	if factor.Status != Pass {
		t.Errorf("nonce_match with matching nonce: got %s, want PASS; detail: %s", factor.Status, factor.Detail)
	}

	// Fail: nonce mismatch.
	otherNonce := NewNonce()
	raw.Nonce = otherNonce.Hex()
	report = BuildReport("venice", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)
	factor = findFactor(t, report, "nonce_match")
	if factor.Status != Fail {
		t.Errorf("nonce_match with mismatched nonce: got %s, want FAIL", factor.Status)
	}

	// Fail: empty nonce.
	raw.Nonce = ""
	report = BuildReport("venice", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)
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
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)
	factor := findFactor(t, report, "tdx_quote_present")
	if factor.Status != Pass {
		t.Errorf("tdx_quote_present with quote: got %s, want PASS", factor.Status)
	}

	raw.IntelQuote = ""
	report = BuildReport("venice", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)
	factor = findFactor(t, report, "tdx_quote_present")
	if factor.Status != Fail {
		t.Errorf("tdx_quote_present with empty quote: got %s, want FAIL", factor.Status)
	}
}

// TestBuildReportSigningKeyPresent verifies signing_key_present Pass/Fail.
func TestBuildReportSigningKeyPresent(t *testing.T) {
	nonce := NewNonce()

	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)
	factor := findFactor(t, report, "signing_key_present")
	if factor.Status != Pass {
		t.Errorf("signing_key_present with key: got %s, want PASS", factor.Status)
	}

	raw.SigningKey = ""
	report = BuildReport("venice", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)
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
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)
	factor := findFactor(t, report, "e2ee_capable")
	if factor.Status != Pass {
		t.Errorf("e2ee_capable with valid key: got %s, want PASS; detail: %s", factor.Status, factor.Detail)
	}

	// Fail: empty key.
	raw.SigningKey = ""
	report = BuildReport("venice", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)
	factor = findFactor(t, report, "e2ee_capable")
	if factor.Status != Fail {
		t.Errorf("e2ee_capable with empty key: got %s, want FAIL", factor.Status)
	}

	// Fail: malformed key.
	raw.SigningKey = strings.Repeat("0", 130)
	report = BuildReport("venice", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)
	factor = findFactor(t, report, "e2ee_capable")
	if factor.Status != Fail {
		t.Errorf("e2ee_capable with zero key: got %s, want FAIL", factor.Status)
	}
}

// TestBuildReportEnforcedFlags verifies Enforced is set only for factors in the list.
func TestBuildReportEnforcedFlags(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport("venice", "m", raw, nonce, DefaultEnforced, nil, nil, nil, nil, nil, nil)

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

// TestBuildReportTier3AlwaysFail verifies Tier 3 factors (except cpu_id_registry) Fail
// without external data. cpu_id_registry depends on PoC result.
func TestBuildReportTier3AlwaysFail(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport("venice", "m", raw, nonce, DefaultEnforced, nil, nil, nil, nil, nil, nil)

	tier3AlwaysFail := []string{
		"tls_key_binding",
		"cpu_gpu_chain",
		"measured_model_weights",
		"build_transparency_log",
	}

	for _, name := range tier3AlwaysFail {
		f := findFactor(t, report, name)
		if f.Status != Fail {
			t.Errorf("Tier 3 factor %q: got %s, want FAIL", name, f.Status)
		}
		if f.Detail == "" {
			t.Errorf("Tier 3 factor %q: Detail is empty; should explain what is missing", name)
		}
	}

	// cpu_id_registry should Fail when no pocResult, no PPID, no DeviceID.
	f := findFactor(t, report, "cpu_id_registry")
	if f.Status != Fail {
		t.Errorf("cpu_id_registry without PoC or PPID: got %s, want FAIL", f.Status)
	}
}

// TestBuildReportTLSKeyBindingPass verifies tls_key_binding passes when
// TLSFingerprint is set on the RawAttestation.
func TestBuildReportTLSKeyBindingPass(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	raw.TLSFingerprint = "aabbccddee112233445566778899aabb"

	report := BuildReport("nearai", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)
	f := findFactor(t, report, "tls_key_binding")
	if f.Status != Pass {
		t.Errorf("tls_key_binding with TLSFingerprint: got %s (%s), want PASS", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "aabbccddee112233") {
		t.Errorf("detail should contain fingerprint preview: %s", f.Detail)
	}
}

// TestBuildReportTLSKeyBindingFail verifies tls_key_binding fails when
// TLSFingerprint is absent.
func TestBuildReportTLSKeyBindingFail(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	// TLSFingerprint is empty by default

	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)
	f := findFactor(t, report, "tls_key_binding")
	if f.Status != Fail {
		t.Errorf("tls_key_binding without TLSFingerprint: got %s (%s), want FAIL", f.Status, f.Detail)
	}
}

// TestBlockedReturnsTrue verifies Blocked is true when an enforced factor fails.
func TestBlockedReturnsTrue(t *testing.T) {
	nonce := NewNonce()
	// Missing nonce in response → nonce_match Fail (which is enforced by default).
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	raw.Nonce = "" // force nonce_match to fail

	report := BuildReport("venice", "m", raw, nonce, DefaultEnforced, nil, nil, nil, nil, nil, nil)

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
	report := BuildReport("venice", "m", raw, nonce, []string{}, nil, nil, nil, nil, nil, nil)

	if report.Blocked() {
		t.Error("Blocked() returned true with empty enforced list")
	}
}

// TestVerificationReportMetadata checks provider, model, and timestamp are set.
func TestVerificationReportMetadata(t *testing.T) {
	before := time.Now()
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport("venice", "e2ee-qwen3", raw, nonce, nil, nil, nil, nil, nil, nil, nil)
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
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)

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

	report := BuildReport("venice", "m", raw, nonce, nil, tdxResult, nil, nil, nil, nil, nil)

	for _, name := range []string{"tdx_quote_structure", "tdx_cert_chain", "tdx_quote_signature", "tdx_debug_disabled"} {
		f := findFactor(t, report, name)
		if f.Status != Pass {
			t.Errorf("factor %q with passing TDX result: got %s (%s), want PASS", name, f.Status, f.Detail)
		}
	}

	// Check reportdata binding passes when detail is set.
	f := findFactor(t, report, "tdx_reportdata_binding")
	if f.Status != Skip {
		t.Errorf("tdx_reportdata_binding with no verifier detail: got %s (%s), want SKIP", f.Status, f.Detail)
	}
}

// TestBuildReportReportDataBindingPassWithDetail verifies tdx_reportdata_binding
// passes when ReportDataBindingDetail is set (provider verifier succeeded).
func TestBuildReportReportDataBindingPassWithDetail(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	tdxResult := &TDXVerifyResult{
		TeeTCBSVN:               make([]byte, 16),
		ReportDataBindingDetail: "REPORTDATA binds enclave public key via keccak256-derived address (0xabc123)",
	}

	report := BuildReport("venice", "m", raw, nonce, nil, tdxResult, nil, nil, nil, nil, nil)
	f := findFactor(t, report, "tdx_reportdata_binding")
	if f.Status != Pass {
		t.Errorf("tdx_reportdata_binding with detail: got %s (%s), want PASS", f.Status, f.Detail)
	}
	if f.Detail != "REPORTDATA binds enclave public key via keccak256-derived address (0xabc123)" {
		t.Errorf("unexpected detail: %s", f.Detail)
	}
}

// TestBuildReportReportDataBindingSkipNoVerifier verifies tdx_reportdata_binding
// is Skip when no provider verifier is configured (ReportDataBindingDetail empty).
func TestBuildReportReportDataBindingSkipNoVerifier(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	tdxResult := &TDXVerifyResult{
		TeeTCBSVN: make([]byte, 16),
	}

	report := BuildReport("nearai", "m", raw, nonce, nil, tdxResult, nil, nil, nil, nil, nil)
	f := findFactor(t, report, "tdx_reportdata_binding")
	if f.Status != Skip {
		t.Errorf("tdx_reportdata_binding without verifier: got %s (%s), want SKIP", f.Status, f.Detail)
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

	report := BuildReport("venice", "m", raw, nonce, nil, tdxResult, nil, nil, nil, nil, nil)
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
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)
	f := findFactor(t, report, "nvidia_payload_present")
	if f.Status != Fail {
		t.Errorf("nvidia_payload_present with empty payload: got %s, want FAIL", f.Status)
	}

	// Pass: payload present.
	raw.NvidiaPayload = "some.jwt.token"
	report = BuildReport("venice", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)
	f = findFactor(t, report, "nvidia_payload_present")
	if f.Status != Pass {
		t.Errorf("nvidia_payload_present with payload: got %s, want PASS", f.Status)
	}
}

// TestBuildReportAttestationFreshnessSkipNilTDX verifies intel_pcs_collateral
// is Skip when no TDX result is available.
func TestBuildReportAttestationFreshnessSkipNilTDX(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)

	f := findFactor(t, report, "intel_pcs_collateral")
	if f.Status != Skip {
		t.Errorf("intel_pcs_collateral with nil tdxResult: got %s, want SKIP", f.Status)
	}
}

// TestBuildReportAttestationFreshnessPassWithTcbStatus verifies intel_pcs_collateral
// passes when TcbStatus is set.
func TestBuildReportAttestationFreshnessPassWithTcbStatus(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	tdxResult := &TDXVerifyResult{
		TeeTCBSVN: make([]byte, 16),
		TcbStatus: "UpToDate",
	}
	report := BuildReport("venice", "m", raw, nonce, nil, tdxResult, nil, nil, nil, nil, nil)

	f := findFactor(t, report, "intel_pcs_collateral")
	if f.Status != Pass {
		t.Errorf("intel_pcs_collateral with TcbStatus: got %s, want PASS; detail: %s", f.Status, f.Detail)
	}
}

// TestBuildReportAttestationFreshnessSkipOffline verifies intel_pcs_collateral
// is Skip when TDX result exists but no collateral was fetched (offline).
func TestBuildReportAttestationFreshnessSkipOffline(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	tdxResult := &TDXVerifyResult{
		TeeTCBSVN: make([]byte, 16),
	}
	report := BuildReport("venice", "m", raw, nonce, nil, tdxResult, nil, nil, nil, nil, nil)

	f := findFactor(t, report, "intel_pcs_collateral")
	if f.Status != Skip {
		t.Errorf("intel_pcs_collateral offline: got %s, want SKIP; detail: %s", f.Status, f.Detail)
	}
}

// TestBuildReportTdxTcbCurrentUpToDate verifies tdx_tcb_current Pass for UpToDate.
func TestBuildReportTdxTcbCurrentUpToDate(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	tdxResult := &TDXVerifyResult{
		TeeTCBSVN:   make([]byte, 16),
		TcbStatus:   "UpToDate",
		AdvisoryIDs: []string{"INTEL-SA-00837"},
	}
	report := BuildReport("venice", "m", raw, nonce, nil, tdxResult, nil, nil, nil, nil, nil)

	f := findFactor(t, report, "tdx_tcb_current")
	if f.Status != Pass {
		t.Errorf("tdx_tcb_current UpToDate: got %s, want PASS; detail: %s", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "UpToDate") {
		t.Errorf("detail should contain UpToDate: %s", f.Detail)
	}
}

// TestBuildReportTdxTcbCurrentSWHardening verifies tdx_tcb_current Pass for SWHardeningNeeded.
func TestBuildReportTdxTcbCurrentSWHardening(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	tdxResult := &TDXVerifyResult{
		TeeTCBSVN:   make([]byte, 16),
		TcbStatus:   "SWHardeningNeeded",
		AdvisoryIDs: []string{"INTEL-SA-00960"},
	}
	report := BuildReport("venice", "m", raw, nonce, nil, tdxResult, nil, nil, nil, nil, nil)

	f := findFactor(t, report, "tdx_tcb_current")
	if f.Status != Pass {
		t.Errorf("tdx_tcb_current SWHardeningNeeded: got %s, want PASS; detail: %s", f.Status, f.Detail)
	}
}

// TestBuildReportTdxTcbCurrentOutOfDate verifies tdx_tcb_current Fail for OutOfDate.
func TestBuildReportTdxTcbCurrentOutOfDate(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	tdxResult := &TDXVerifyResult{
		TeeTCBSVN: make([]byte, 16),
		TcbStatus: "OutOfDate",
	}
	report := BuildReport("venice", "m", raw, nonce, nil, tdxResult, nil, nil, nil, nil, nil)

	f := findFactor(t, report, "tdx_tcb_current")
	if f.Status != Fail {
		t.Errorf("tdx_tcb_current OutOfDate: got %s, want FAIL; detail: %s", f.Status, f.Detail)
	}
}

// TestBuildReportTdxTcbCurrentRevoked verifies tdx_tcb_current Fail for Revoked.
func TestBuildReportTdxTcbCurrentRevoked(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	tdxResult := &TDXVerifyResult{
		TeeTCBSVN: make([]byte, 16),
		TcbStatus: "Revoked",
	}
	report := BuildReport("venice", "m", raw, nonce, nil, tdxResult, nil, nil, nil, nil, nil)

	f := findFactor(t, report, "tdx_tcb_current")
	if f.Status != Fail {
		t.Errorf("tdx_tcb_current Revoked: got %s, want FAIL; detail: %s", f.Status, f.Detail)
	}
}

// TestBuildReportTdxTcbCurrentOffline verifies tdx_tcb_current shows TEE_TCB_SVN when offline.
func TestBuildReportTdxTcbCurrentOffline(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	tdxResult := &TDXVerifyResult{
		TeeTCBSVN: []byte{0x07, 0x01, 0x03, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
	report := BuildReport("venice", "m", raw, nonce, nil, tdxResult, nil, nil, nil, nil, nil)

	f := findFactor(t, report, "tdx_tcb_current")
	if f.Status != Skip {
		t.Errorf("tdx_tcb_current offline: got %s, want SKIP; detail: %s", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "TEE_TCB_SVN") {
		t.Errorf("detail should contain TEE_TCB_SVN: %s", f.Detail)
	}
}

// TestBuildReportNRASPassWithSuccess verifies nvidia_nras_verified Pass with OVERALL_SUCCESS.
func TestBuildReportNRASPassWithSuccess(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	raw.NvidiaPayload = `{"evidence_list":[]}`
	nrasResult := &NvidiaVerifyResult{
		Format:        "JWT",
		OverallResult: true,
	}
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil, nrasResult, nil, nil, nil)

	f := findFactor(t, report, "nvidia_nras_verified")
	if f.Status != Pass {
		t.Errorf("nvidia_nras_verified with true: got %s, want PASS; detail: %s", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "true") {
		t.Errorf("detail should contain true: %s", f.Detail)
	}
}

// TestBuildReportNRASFailNotSuccess verifies nvidia_nras_verified Fail when result is false.
func TestBuildReportNRASFailNotSuccess(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	raw.NvidiaPayload = `{"evidence_list":[]}`
	nrasResult := &NvidiaVerifyResult{
		Format:        "JWT",
		OverallResult: false,
	}
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil, nrasResult, nil, nil, nil)

	f := findFactor(t, report, "nvidia_nras_verified")
	if f.Status != Fail {
		t.Errorf("nvidia_nras_verified with false: got %s, want FAIL; detail: %s", f.Status, f.Detail)
	}
}

// TestBuildReportNRASSkipOffline verifies nvidia_nras_verified Skip when nrasResult is nil
// and EAT payload is present (offline mode).
func TestBuildReportNRASSkipOffline(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	raw.NvidiaPayload = `{"evidence_list":[]}`
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)

	f := findFactor(t, report, "nvidia_nras_verified")
	if f.Status != Skip {
		t.Errorf("nvidia_nras_verified offline: got %s, want SKIP; detail: %s", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "offline") {
		t.Errorf("detail should mention offline: %s", f.Detail)
	}
}

// TestBuildReportNRASSkipNoEAT verifies nvidia_nras_verified Skip when payload is JWT (not EAT).
func TestBuildReportNRASSkipNoEAT(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	raw.NvidiaPayload = "eyJhbGciOi..." // JWT format
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)

	f := findFactor(t, report, "nvidia_nras_verified")
	if f.Status != Skip {
		t.Errorf("nvidia_nras_verified with JWT payload: got %s, want SKIP; detail: %s", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "no EAT") {
		t.Errorf("detail should mention no EAT: %s", f.Detail)
	}
}

// TestBuildReportNRASFailSignature verifies nvidia_nras_verified Fail on signature error.
func TestBuildReportNRASFailSignature(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	raw.NvidiaPayload = `{"evidence_list":[]}`
	nrasResult := &NvidiaVerifyResult{
		Format:       "JWT",
		SignatureErr: errors.New("bad sig"),
	}
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil, nrasResult, nil, nil, nil)

	f := findFactor(t, report, "nvidia_nras_verified")
	if f.Status != Fail {
		t.Errorf("nvidia_nras_verified with sig error: got %s, want FAIL; detail: %s", f.Status, f.Detail)
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

// TestBuildReportComposeBindingPass verifies compose_binding passes with valid result.
func TestBuildReportComposeBindingPass(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	composeResult := &ComposeBindingResult{Checked: true}
	report := BuildReport("nearai", "m", raw, nonce, nil, nil, nil, nil, nil, composeResult, nil)
	f := findFactor(t, report, "compose_binding")
	if f.Status != Pass {
		t.Errorf("compose_binding with valid binding: got %s (%s), want PASS", f.Status, f.Detail)
	}
}

// TestBuildReportComposeBindingFail verifies compose_binding fails on error.
func TestBuildReportComposeBindingFail(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	composeResult := &ComposeBindingResult{Checked: true, Err: errors.New("hash mismatch")}
	report := BuildReport("nearai", "m", raw, nonce, nil, nil, nil, nil, nil, composeResult, nil)
	f := findFactor(t, report, "compose_binding")
	if f.Status != Fail {
		t.Errorf("compose_binding with error: got %s (%s), want FAIL", f.Status, f.Detail)
	}
}

// TestBuildReportComposeBindingSkip verifies compose_binding skips without data.
func TestBuildReportComposeBindingSkip(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport("venice", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)
	f := findFactor(t, report, "compose_binding")
	if f.Status != Skip {
		t.Errorf("compose_binding without data: got %s (%s), want SKIP", f.Status, f.Detail)
	}
}

// TestBuildReportSigstorePass verifies sigstore_verification passes when all digests are OK.
func TestBuildReportSigstorePass(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	sigResults := []SigstoreResult{
		{Digest: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234", OK: true, Status: 200},
		{Digest: "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff", OK: true, Status: 200},
	}
	report := BuildReport("nearai", "m", raw, nonce, nil, nil, nil, nil, nil, nil, sigResults)
	f := findFactor(t, report, "sigstore_verification")
	if f.Status != Pass {
		t.Errorf("sigstore_verification all OK: got %s (%s), want PASS", f.Status, f.Detail)
	}
}

// TestBuildReportSigstoreFail verifies sigstore_verification fails when a digest is not found.
func TestBuildReportSigstoreFail(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	sigResults := []SigstoreResult{
		{Digest: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234", OK: true, Status: 200},
		{Digest: "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff", OK: false, Status: 404},
	}
	report := BuildReport("nearai", "m", raw, nonce, nil, nil, nil, nil, nil, nil, sigResults)
	f := findFactor(t, report, "sigstore_verification")
	if f.Status != Fail {
		t.Errorf("sigstore_verification with 404: got %s (%s), want FAIL", f.Status, f.Detail)
	}
}

// --------------------------------------------------------------------------
// NVIDIA detail formatter tests
// --------------------------------------------------------------------------

func TestNvidiaSignatureDetail(t *testing.T) {
	tests := []struct {
		name   string
		result *NvidiaVerifyResult
		want   string
	}{
		{
			"EAT format",
			&NvidiaVerifyResult{Format: "EAT", GPUCount: 8, Arch: "HOPPER"},
			"EAT: 8 GPU cert chains and SPDM ECDSA P-384 signatures verified (arch: HOPPER)",
		},
		{
			"JWT format",
			&NvidiaVerifyResult{Format: "JWT", Algorithm: "ES384"},
			"JWT signature valid (ES384)",
		},
		{
			"unknown format",
			&NvidiaVerifyResult{Format: "UNKNOWN"},
			"signature valid",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := nvidiaSignatureDetail(tc.result)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNvidiaClaimsDetail(t *testing.T) {
	tests := []struct {
		name   string
		result *NvidiaVerifyResult
		want   string
	}{
		{
			"EAT format",
			&NvidiaVerifyResult{Format: "EAT", Arch: "HOPPER", GPUCount: 4},
			"EAT: arch=HOPPER, 4 GPUs, nonce verified",
		},
		{
			"JWT format true",
			&NvidiaVerifyResult{Format: "JWT", OverallResult: true},
			"JWT claims valid (overall result: true)",
		},
		{
			"JWT format false",
			&NvidiaVerifyResult{Format: "JWT", OverallResult: false},
			"JWT claims valid (overall result: false)",
		},
		{
			"unknown format",
			&NvidiaVerifyResult{Format: "UNKNOWN"},
			"claims valid",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := nvidiaClaimsDetail(tc.result)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNvidiaNonceDetail(t *testing.T) {
	tests := []struct {
		name   string
		result *NvidiaVerifyResult
		want   string
	}{
		{
			"EAT format",
			&NvidiaVerifyResult{Format: "EAT", GPUCount: 8},
			"EAT nonce + 8 GPU SPDM requester nonces match submitted nonce",
		},
		{
			"JWT format",
			&NvidiaVerifyResult{Format: "JWT"},
			"nonce in NVIDIA payload matches submitted nonce",
		},
		{
			"empty format",
			&NvidiaVerifyResult{},
			"nonce in NVIDIA payload matches submitted nonce",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := nvidiaNonceDetail(tc.result)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// --------------------------------------------------------------------------
// BuildReport: NVIDIA factor pass paths with NvidiaVerifyResult
// --------------------------------------------------------------------------

func TestBuildReportNvidiaSignaturePass(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	raw.NvidiaPayload = `{"evidence_list":[]}`
	nvidiaResult := &NvidiaVerifyResult{
		Format:   "EAT",
		Arch:     "HOPPER",
		GPUCount: 8,
		Nonce:    nonce.Hex(),
	}

	report := BuildReport("venice", "m", raw, nonce, nil, nil, nvidiaResult, nil, nil, nil, nil)
	f := findFactor(t, report, "nvidia_signature")
	if f.Status != Pass {
		t.Errorf("nvidia_signature with passing result: got %s (%s), want PASS", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "HOPPER") {
		t.Errorf("detail should mention HOPPER: %s", f.Detail)
	}
	if !strings.Contains(f.Detail, "8 GPU") {
		t.Errorf("detail should mention 8 GPU: %s", f.Detail)
	}
}

func TestBuildReportNvidiaClaimsPass(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	raw.NvidiaPayload = `{"evidence_list":[]}`
	nvidiaResult := &NvidiaVerifyResult{
		Format:   "EAT",
		Arch:     "HOPPER",
		GPUCount: 4,
		Nonce:    nonce.Hex(),
	}

	report := BuildReport("venice", "m", raw, nonce, nil, nil, nvidiaResult, nil, nil, nil, nil)
	f := findFactor(t, report, "nvidia_claims")
	if f.Status != Pass {
		t.Errorf("nvidia_claims with passing result: got %s (%s), want PASS", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "arch=HOPPER") {
		t.Errorf("detail should mention arch=HOPPER: %s", f.Detail)
	}
}

func TestBuildReportNvidiaNoncePass(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	raw.NvidiaPayload = `{"evidence_list":[]}`
	nvidiaResult := &NvidiaVerifyResult{
		Format:   "EAT",
		Arch:     "HOPPER",
		GPUCount: 8,
		Nonce:    nonce.Hex(),
	}

	report := BuildReport("venice", "m", raw, nonce, nil, nil, nvidiaResult, nil, nil, nil, nil)
	f := findFactor(t, report, "nvidia_nonce_match")
	if f.Status != Pass {
		t.Errorf("nvidia_nonce_match with matching nonce: got %s (%s), want PASS", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "8 GPU") {
		t.Errorf("detail should mention 8 GPU: %s", f.Detail)
	}
}

func TestBuildReportNvidiaSignatureFail(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	raw.NvidiaPayload = `{"evidence_list":[]}`
	nvidiaResult := &NvidiaVerifyResult{
		Format:       "EAT",
		SignatureErr: errors.New("bad cert chain"),
	}

	report := BuildReport("venice", "m", raw, nonce, nil, nil, nvidiaResult, nil, nil, nil, nil)
	f := findFactor(t, report, "nvidia_signature")
	if f.Status != Fail {
		t.Errorf("nvidia_signature with error: got %s, want FAIL", f.Status)
	}
	if !strings.Contains(f.Detail, "bad cert chain") {
		t.Errorf("detail should mention error: %s", f.Detail)
	}
}

func TestBuildReportNvidiaClaimsFail(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	raw.NvidiaPayload = `{"evidence_list":[]}`
	nvidiaResult := &NvidiaVerifyResult{
		Format:    "EAT",
		ClaimsErr: errors.New("invalid arch"),
	}

	report := BuildReport("venice", "m", raw, nonce, nil, nil, nvidiaResult, nil, nil, nil, nil)
	f := findFactor(t, report, "nvidia_claims")
	if f.Status != Fail {
		t.Errorf("nvidia_claims with error: got %s, want FAIL", f.Status)
	}
}

func TestBuildReportNvidiaNonceMismatch(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	raw.NvidiaPayload = `{"evidence_list":[]}`
	nvidiaResult := &NvidiaVerifyResult{
		Format: "EAT",
		Nonce:  "wrong-nonce",
	}

	report := BuildReport("venice", "m", raw, nonce, nil, nil, nvidiaResult, nil, nil, nil, nil)
	f := findFactor(t, report, "nvidia_nonce_match")
	if f.Status != Fail {
		t.Errorf("nvidia_nonce_match with mismatch: got %s, want FAIL", f.Status)
	}
}

// TestBuildReportSigstoreSkip verifies sigstore_verification skips without digests.
func TestBuildReportSigstoreSkip(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport("nearai", "m", raw, nonce, nil, nil, nil, nil, nil, nil, nil)
	f := findFactor(t, report, "sigstore_verification")
	if f.Status != Skip {
		t.Errorf("sigstore_verification without digests: got %s (%s), want SKIP", f.Status, f.Detail)
	}
}

// --------------------------------------------------------------------------
// buildMetadata tests
// --------------------------------------------------------------------------

func TestBuildMetadata_AllFields(t *testing.T) {
	raw := &RawAttestation{
		TEEHardware:     "intel-tdx",
		UpstreamModel:   "Qwen/Qwen3.5-122B",
		AppName:         "dstack-nvidia-0.5.5",
		ComposeHash:     "242a6272abcdef0123456789",
		OSImageHash:     "9b69bb16aabbccddaabbccdd",
		DeviceID:        "aa781567bbccddee",
		NonceSource:     "client",
		CandidatesAvail: 6,
		CandidatesEval:  1,
		EventLogCount:   30,
	}
	m := buildMetadata(raw, nil)

	wantKeys := map[string]string{
		"hardware":     "intel-tdx",
		"upstream":     "Qwen/Qwen3.5-122B",
		"app":          "dstack-nvidia-0.5.5",
		"compose_hash": "242a6272abcdef0123456789",
		"os_image":     "9b69bb16aabbccddaabbccdd",
		"device":       "aa781567bbccddee",
		"nonce_source": "client",
		"candidates":   "1/6 evaluated",
		"event_log":    "30 entries",
	}
	for key, want := range wantKeys {
		got, ok := m[key]
		if !ok {
			t.Errorf("missing key %q", key)
			continue
		}
		if got != want {
			t.Errorf("m[%q] = %q, want %q", key, got, want)
		}
	}
}

func TestBuildMetadata_EmptyRaw(t *testing.T) {
	raw := &RawAttestation{}
	m := buildMetadata(raw, nil)
	if m != nil {
		t.Errorf("buildMetadata with empty raw: got %v, want nil", m)
	}
}

func TestBuildMetadata_WithPPID(t *testing.T) {
	raw := &RawAttestation{
		TEEHardware: "intel-tdx",
	}
	tdxResult := &TDXVerifyResult{
		PPID: "abcdef1234567890",
	}
	m := buildMetadata(raw, tdxResult)

	ppid, ok := m["ppid"]
	if !ok {
		t.Fatal("ppid not in metadata")
	}
	if ppid != "abcdef1234567890" {
		t.Errorf("ppid = %q, want %q", ppid, "abcdef1234567890")
	}
}
