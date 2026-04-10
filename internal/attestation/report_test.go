package attestation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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

func bytesFromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

// assertSingleFactor asserts that results has exactly 1 element with the expected status.
// Returns the FactorResult for further checks.
func assertSingleFactor(t *testing.T, results []FactorResult, want Status) FactorResult {
	t.Helper()
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Status != want {
		t.Errorf("status = %s, want %s; detail: %s", results[0].Status, want, results[0].Detail)
	}
	return results[0]
}

// assertFactor finds a factor by name in a multi-result slice and asserts its status.
func assertFactor(t *testing.T, results []FactorResult, name string, want Status) FactorResult {
	t.Helper()
	for _, f := range results {
		if f.Name == name {
			if f.Status != want {
				t.Errorf("factor %q: status = %s, want %s; detail: %s", name, f.Status, want, f.Detail)
			}
			return f
		}
	}
	names := make([]string, len(results))
	for i, f := range results {
		names[i] = f.Name
	}
	t.Fatalf("factor %q not found in results (have: %v)", name, names)
	return FactorResult{}
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

// allExcept returns KnownFactors minus the given names. This builds an
// AllowFail list that enforces only the excluded factors.
func allExcept(exclude ...string) []string {
	ex := make(map[string]bool, len(exclude))
	for _, n := range exclude {
		ex[n] = true
	}
	var out []string
	for _, n := range KnownFactors {
		if !ex[n] {
			out = append(out, n)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// BuildReport-level tests (cross-cutting concerns)
// ---------------------------------------------------------------------------

// TestBuildReportFactorCount ensures exactly 29 factors are produced.
func TestBuildReportFactorCount(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport(&ReportInput{Provider: "venice", Model: "test-model", Raw: raw, Nonce: nonce, AllowFail: DefaultAllowFail})

	if len(report.Factors) != 29 {
		t.Errorf("factor count: got %d, want 29", len(report.Factors))
	}
}

// TestBuildReportTotals verifies the Passed/Failed/Skipped tallies are consistent.
func TestBuildReportTotals(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport(&ReportInput{Provider: "venice", Model: "test-model", Raw: raw, Nonce: nonce, AllowFail: DefaultAllowFail})

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

// TestBuildReportEnforcedFlags verifies Enforced is set for factors NOT in AllowFail.
func TestBuildReportEnforcedFlags(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, AllowFail: DefaultAllowFail})

	allowFailSet := make(map[string]bool)
	for _, name := range DefaultAllowFail {
		allowFailSet[name] = true
	}

	for _, f := range report.Factors {
		wantEnforced := !allowFailSet[f.Name]
		if f.Enforced != wantEnforced {
			t.Errorf("factor %q: Enforced=%v, want %v", f.Name, f.Enforced, wantEnforced)
		}
	}
}

// TestBlockedReturnsTrue verifies Blocked is true when an enforced factor fails.
func TestBlockedReturnsTrue(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	raw.Nonce = "" // force nonce_match to fail

	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, AllowFail: DefaultAllowFail})

	if !report.Blocked() {
		t.Error("Blocked() returned false when enforced nonce_match is failing")
	}
}

// TestBlockedFactorsReturnsFailingEnforced verifies BlockedFactors lists all
// enforced factors that failed.
func TestBlockedFactorsReturnsFailingEnforced(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	raw.Nonce = "" // force nonce_match to fail

	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, AllowFail: DefaultAllowFail})

	blocked := report.BlockedFactors()
	if len(blocked) == 0 {
		t.Fatal("BlockedFactors() returned empty slice when Blocked() is true")
	}
	found := false
	for _, f := range blocked {
		if f.Name == "nonce_match" {
			found = true
		}
		if f.Status != Fail {
			t.Errorf("BlockedFactors() returned non-Fail factor %q (status=%v)", f.Name, f.Status)
		}
		if !f.Enforced {
			t.Errorf("BlockedFactors() returned non-enforced factor %q", f.Name)
		}
	}
	if !found {
		t.Error("BlockedFactors() did not include nonce_match")
	}
}

// TestBlockedFactorsReturnsNilWhenNotBlocked verifies BlockedFactors is nil
// when all factors are in allow_fail (nothing enforced).
func TestBlockedFactorsReturnsNilWhenNotBlocked(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, AllowFail: KnownFactors})

	if blocked := report.BlockedFactors(); blocked != nil {
		t.Errorf("BlockedFactors() returned %v, want nil", blocked)
	}
}

// TestBlockedReturnsFalse verifies Blocked is false when all factors are allow_fail.
func TestBlockedReturnsFalse(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, AllowFail: KnownFactors})

	if report.Blocked() {
		t.Error("Blocked() returned true with all factors allowed to fail")
	}
}

// TestVerificationReportMetadata checks provider, model, and timestamp are set.
func TestVerificationReportMetadata(t *testing.T) {
	before := time.Now()
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport(&ReportInput{Provider: "venice", Model: "e2ee-qwen3", Raw: raw, Nonce: nonce})
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

func TestDefaultAllowFailExcludesSupplyChainFactors(t *testing.T) {
	// Supply-chain factors must be enforced, i.e. NOT in DefaultAllowFail.
	mustEnforce := []string{
		"sigstore_verification",
		"build_transparency_log",
	}
	allowFailSet := make(map[string]bool, len(DefaultAllowFail))
	for _, f := range DefaultAllowFail {
		allowFailSet[f] = true
	}
	for _, f := range mustEnforce {
		if allowFailSet[f] {
			t.Errorf("DefaultAllowFail should not contain %q (must be enforced)", f)
		}
	}
}

func TestOnlineFactorsAreKnown(t *testing.T) {
	known := make(map[string]bool, len(KnownFactors))
	for _, f := range KnownFactors {
		known[f] = true
	}
	for _, f := range OnlineFactors {
		if !known[f] {
			t.Errorf("OnlineFactors contains unknown factor %q", f)
		}
	}
}

func TestWithOfflineAllowFail(t *testing.T) {
	// Starting from an empty list, should return exactly OnlineFactors.
	result := WithOfflineAllowFail(nil)
	if len(result) != len(OnlineFactors) {
		t.Fatalf("WithOfflineAllowFail(nil): got %d entries, want %d", len(result), len(OnlineFactors))
	}
	resultSet := make(map[string]bool, len(result))
	for _, f := range result {
		resultSet[f] = true
	}
	for _, f := range OnlineFactors {
		if !resultSet[f] {
			t.Errorf("WithOfflineAllowFail(nil): missing %q", f)
		}
	}
}

func TestWithOfflineAllowFailNoDuplicates(t *testing.T) {
	// If the input already contains some OnlineFactors, they should not
	// be duplicated.
	input := []string{"intel_pcs_collateral", "tdx_hardware_config"}
	result := WithOfflineAllowFail(input)
	seen := make(map[string]int, len(result))
	for _, f := range result {
		seen[f]++
	}
	for f, count := range seen {
		if count > 1 {
			t.Errorf("WithOfflineAllowFail duplicated %q (%d times)", f, count)
		}
	}
	// Should contain both original entries and all OnlineFactors.
	resultSet := make(map[string]bool, len(result))
	for _, f := range result {
		resultSet[f] = true
	}
	if !resultSet["tdx_hardware_config"] {
		t.Error("original entry tdx_hardware_config missing")
	}
	for _, f := range OnlineFactors {
		if !resultSet[f] {
			t.Errorf("missing online factor %q", f)
		}
	}
}

func TestWithOfflineAllowFailDoesNotMutateInput(t *testing.T) {
	input := []string{"tdx_hardware_config"}
	inputCopy := append([]string(nil), input...)
	_ = WithOfflineAllowFail(input)
	if len(input) != len(inputCopy) || input[0] != inputCopy[0] {
		t.Error("WithOfflineAllowFail mutated the input slice")
	}
}

func TestWithAllowFailAddsNewFactor(t *testing.T) {
	input := []string{"tdx_hardware_config"}
	result := WithAllowFail(input, "e2ee_usable")
	if len(result) != 2 {
		t.Fatalf("got %d entries, want 2", len(result))
	}
	if result[0] != "tdx_hardware_config" || result[1] != "e2ee_usable" {
		t.Errorf("got %v, want [tdx_hardware_config e2ee_usable]", result)
	}
}

func TestWithAllowFailDeduplicates(t *testing.T) {
	input := []string{"tdx_hardware_config", "e2ee_usable"}
	result := WithAllowFail(input, "e2ee_usable")
	if len(result) != 2 {
		t.Fatalf("got %d entries, want 2 (no duplicate)", len(result))
	}
}

func TestWithAllowFailDoesNotMutateInput(t *testing.T) {
	input := []string{"tdx_hardware_config"}
	inputCopy := append([]string(nil), input...)
	_ = WithAllowFail(input, "e2ee_usable")
	if len(input) != len(inputCopy) || input[0] != inputCopy[0] {
		t.Error("WithAllowFail mutated the input slice")
	}
}

func TestWithAllowFailNilInput(t *testing.T) {
	result := WithAllowFail(nil, "e2ee_usable")
	if len(result) != 1 || result[0] != "e2ee_usable" {
		t.Errorf("got %v, want [e2ee_usable]", result)
	}
}

// ---------------------------------------------------------------------------
// Direct evaluator tests
// ---------------------------------------------------------------------------

func TestEvalNonceMatch(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	tests := []struct {
		name string
		raw  *RawAttestation
		want Status
	}{
		{"pass", buildMinimalRaw(nonce, sigKey), Pass},
		{"mismatch", func() *RawAttestation { r := buildMinimalRaw(nonce, sigKey); r.Nonce = NewNonce().Hex(); return r }(), Fail},
		{"absent", func() *RawAttestation { r := buildMinimalRaw(nonce, sigKey); r.Nonce = ""; return r }(), Fail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertSingleFactor(t, evalNonceMatch(&ReportInput{Raw: tc.raw, Nonce: nonce}), tc.want)
		})
	}
}

func TestEvalTDXQuotePresent(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	tests := []struct {
		name  string
		quote string
		want  Status
	}{
		{"present", "dGVzdA==", Pass},
		{"absent", "", Fail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildMinimalRaw(nonce, sigKey)
			raw.IntelQuote = tc.quote
			assertSingleFactor(t, evalTDXQuotePresent(&ReportInput{Raw: raw}), tc.want)
		})
	}
}

func TestEvalSigningKeyPresent(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	tests := []struct {
		name string
		key  string
		want Status
	}{
		{"present", sigKey, Pass},
		{"absent", "", Fail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildMinimalRaw(nonce, tc.key)
			assertSingleFactor(t, evalSigningKeyPresent(&ReportInput{Raw: raw}), tc.want)
		})
	}
}

func TestEvalTDXParseDependent(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	t.Run("nil_tdx_all_fail", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		results := evalTDXParseDependent(&ReportInput{Raw: raw})
		if len(results) != 4 {
			t.Fatalf("got %d results, want 4", len(results))
		}
		for _, name := range []string{"tdx_quote_structure", "tdx_cert_chain", "tdx_quote_signature", "tdx_debug_disabled"} {
			assertFactor(t, results, name, Fail)
		}
	})

	t.Run("all_pass", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		tdx := &TDXVerifyResult{TeeTCBSVN: make([]byte, 16)}
		results := evalTDXParseDependent(&ReportInput{Raw: raw, Nonce: nonce, TDX: tdx})
		if len(results) != 4 {
			t.Fatalf("got %d results, want 4", len(results))
		}
		for _, name := range []string{"tdx_quote_structure", "tdx_cert_chain", "tdx_quote_signature", "tdx_debug_disabled"} {
			assertFactor(t, results, name, Pass)
		}
	})

	t.Run("debug_enabled", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		tdx := &TDXVerifyResult{DebugEnabled: true, TeeTCBSVN: make([]byte, 16)}
		results := evalTDXParseDependent(&ReportInput{Raw: raw, Nonce: nonce, TDX: tdx})
		f := assertFactor(t, results, "tdx_debug_disabled", Fail)
		if !strings.Contains(f.Detail, "debug") {
			t.Errorf("detail should mention debug: %s", f.Detail)
		}
	})

	t.Run("cert_chain_err", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		tdx := &TDXVerifyResult{CertChainErr: errors.New("expired"), TeeTCBSVN: make([]byte, 16)}
		results := evalTDXParseDependent(&ReportInput{Raw: raw, Nonce: nonce, TDX: tdx})
		assertFactor(t, results, "tdx_cert_chain", Fail)
	})

	t.Run("signature_err", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		tdx := &TDXVerifyResult{SignatureErr: errors.New("bad sig"), TeeTCBSVN: make([]byte, 16)}
		results := evalTDXParseDependent(&ReportInput{Raw: raw, Nonce: nonce, TDX: tdx})
		assertFactor(t, results, "tdx_quote_signature", Fail)
	})

	t.Run("parse_err_skips_chain_sig_debug", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		tdx := &TDXVerifyResult{ParseErr: errors.New("bad quote")}
		results := evalTDXParseDependent(&ReportInput{Raw: raw, Nonce: nonce, TDX: tdx})
		assertFactor(t, results, "tdx_quote_structure", Fail)
		assertFactor(t, results, "tdx_cert_chain", Skip)
		assertFactor(t, results, "tdx_quote_signature", Skip)
		assertFactor(t, results, "tdx_debug_disabled", Skip)
	})
}

func TestEvalTDXQuoteStructure(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	t.Run("pass_no_policy", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		tdx := &TDXVerifyResult{
			MRTD:   bytesFromHex(t, strings.Repeat("11", 48)),
			MRSeam: bytesFromHex(t, strings.Repeat("22", 48)),
		}
		results := evalTDXParseDependent(&ReportInput{
			Raw: raw, Nonce: nonce, TDX: tdx,
		})
		f := assertFactor(t, results, "tdx_quote_structure", Pass)
		if !strings.Contains(f.Detail, "valid") {
			t.Errorf("detail should mention valid: %s", f.Detail)
		}
	})

	t.Run("mrtd_mismatch_no_longer_fails_structure", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		tdx := &TDXVerifyResult{
			MRTD:   bytesFromHex(t, strings.Repeat("11", 48)),
			MRSeam: bytesFromHex(t, strings.Repeat("22", 48)),
		}
		results := evalTDXParseDependent(&ReportInput{
			Raw: raw, Nonce: nonce, TDX: tdx,
			Policy: MeasurementPolicy{
				MRTDAllow: map[string]struct{}{strings.Repeat("aa", 48): {}},
			},
		})
		// tdx_quote_structure should pass — measurement checks moved to tdx_mrseam_mrtd
		assertFactor(t, results, "tdx_quote_structure", Pass)
	})
}

func TestEvalTDXMrseamMrtd(t *testing.T) {
	t.Run("skip_no_policy", func(t *testing.T) {
		tdx := &TDXVerifyResult{
			MRTD:   bytesFromHex(t, strings.Repeat("11", 48)),
			MRSeam: bytesFromHex(t, strings.Repeat("22", 48)),
		}
		assertSingleFactor(t, evalTDXMrseamMrtd(&ReportInput{TDX: tdx}), Skip)
	})

	t.Run("skip_no_tdx", func(t *testing.T) {
		assertSingleFactor(t, evalTDXMrseamMrtd(&ReportInput{}), Skip)
	})

	t.Run("mrtd_mismatch", func(t *testing.T) {
		tdx := &TDXVerifyResult{
			MRTD:   bytesFromHex(t, strings.Repeat("11", 48)),
			MRSeam: bytesFromHex(t, strings.Repeat("22", 48)),
		}
		f := assertSingleFactor(t, evalTDXMrseamMrtd(&ReportInput{
			TDX: tdx,
			Policy: MeasurementPolicy{
				MRTDAllow: map[string]struct{}{strings.Repeat("aa", 48): {}},
			},
		}), Fail)
		if !strings.Contains(f.Detail, "MRTD") {
			t.Errorf("detail should mention MRTD: %s", f.Detail)
		}
	})

	t.Run("mrseam_mismatch", func(t *testing.T) {
		tdx := &TDXVerifyResult{
			MRTD:   bytesFromHex(t, strings.Repeat("11", 48)),
			MRSeam: bytesFromHex(t, strings.Repeat("22", 48)),
		}
		f := assertSingleFactor(t, evalTDXMrseamMrtd(&ReportInput{
			TDX: tdx,
			Policy: MeasurementPolicy{
				MRTDAllow:   map[string]struct{}{strings.Repeat("11", 48): {}},
				MRSeamAllow: map[string]struct{}{strings.Repeat("bb", 48): {}},
			},
		}), Fail)
		if !strings.Contains(f.Detail, "MRSEAM") {
			t.Errorf("detail should mention MRSEAM: %s", f.Detail)
		}
	})

	t.Run("pass_both_match", func(t *testing.T) {
		tdx := &TDXVerifyResult{
			MRTD:   bytesFromHex(t, strings.Repeat("11", 48)),
			MRSeam: bytesFromHex(t, strings.Repeat("22", 48)),
		}
		f := assertSingleFactor(t, evalTDXMrseamMrtd(&ReportInput{
			TDX: tdx,
			Policy: MeasurementPolicy{
				MRTDAllow:   map[string]struct{}{strings.Repeat("11", 48): {}},
				MRSeamAllow: map[string]struct{}{strings.Repeat("22", 48): {}},
			},
		}), Pass)
		if !strings.Contains(f.Detail, "MRTD/MRSEAM") {
			t.Errorf("detail should mention MRTD/MRSEAM: %s", f.Detail)
		}
	})

	t.Run("pass_mrtd_only", func(t *testing.T) {
		tdx := &TDXVerifyResult{
			MRTD:   bytesFromHex(t, strings.Repeat("11", 48)),
			MRSeam: bytesFromHex(t, strings.Repeat("22", 48)),
		}
		f := assertSingleFactor(t, evalTDXMrseamMrtd(&ReportInput{
			TDX: tdx,
			Policy: MeasurementPolicy{
				MRTDAllow: map[string]struct{}{strings.Repeat("11", 48): {}},
			},
		}), Pass)
		if !strings.Contains(f.Detail, "MRTD") {
			t.Errorf("detail should mention MRTD: %s", f.Detail)
		}
	})
}

func TestEvalTDXHardwareConfig(t *testing.T) {
	makeRTMRs := func(t *testing.T, r0hex string) [4][48]byte {
		t.Helper()
		var rtmrs [4][48]byte
		b := bytesFromHex(t, r0hex)
		copy(rtmrs[0][:], b)
		return rtmrs
	}

	t.Run("skip_no_policy", func(t *testing.T) {
		tdx := &TDXVerifyResult{RTMRs: makeRTMRs(t, strings.Repeat("ab", 48))}
		assertSingleFactor(t, evalTDXHardwareConfig(&ReportInput{TDX: tdx}), Skip)
	})

	t.Run("skip_no_tdx", func(t *testing.T) {
		assertSingleFactor(t, evalTDXHardwareConfig(&ReportInput{}), Skip)
	})

	t.Run("rtmr0_mismatch", func(t *testing.T) {
		tdx := &TDXVerifyResult{RTMRs: makeRTMRs(t, strings.Repeat("ab", 48))}
		f := assertSingleFactor(t, evalTDXHardwareConfig(&ReportInput{
			TDX: tdx,
			Policy: MeasurementPolicy{
				RTMRAllow: [4]map[string]struct{}{
					{strings.Repeat("00", 48): {}},
				},
			},
		}), Fail)
		if !strings.Contains(f.Detail, "RTMR[0]") {
			t.Errorf("detail should mention RTMR[0]: %s", f.Detail)
		}
	})

	t.Run("rtmr0_match", func(t *testing.T) {
		tdx := &TDXVerifyResult{RTMRs: makeRTMRs(t, strings.Repeat("ab", 48))}
		assertSingleFactor(t, evalTDXHardwareConfig(&ReportInput{
			TDX: tdx,
			Policy: MeasurementPolicy{
				RTMRAllow: [4]map[string]struct{}{
					{strings.Repeat("ab", 48): {}},
				},
			},
		}), Pass)
	})
}

func TestEvalTDXBootConfig(t *testing.T) {
	makeRTMRs := func(t *testing.T, r1hex, r2hex string) [4][48]byte {
		t.Helper()
		var rtmrs [4][48]byte
		copy(rtmrs[1][:], bytesFromHex(t, r1hex))
		copy(rtmrs[2][:], bytesFromHex(t, r2hex))
		return rtmrs
	}

	t.Run("skip_no_policy", func(t *testing.T) {
		tdx := &TDXVerifyResult{RTMRs: makeRTMRs(t, strings.Repeat("ab", 48), strings.Repeat("cd", 48))}
		assertSingleFactor(t, evalTDXBootConfig(&ReportInput{TDX: tdx}), Skip)
	})

	t.Run("skip_no_tdx", func(t *testing.T) {
		assertSingleFactor(t, evalTDXBootConfig(&ReportInput{}), Skip)
	})

	t.Run("rtmr1_mismatch", func(t *testing.T) {
		tdx := &TDXVerifyResult{RTMRs: makeRTMRs(t, strings.Repeat("ab", 48), strings.Repeat("cd", 48))}
		f := assertSingleFactor(t, evalTDXBootConfig(&ReportInput{
			TDX: tdx,
			Policy: MeasurementPolicy{
				RTMRAllow: [4]map[string]struct{}{
					nil,
					{strings.Repeat("00", 48): {}},
					nil,
					nil,
				},
			},
		}), Fail)
		if !strings.Contains(f.Detail, "RTMR[1]") {
			t.Errorf("detail should mention RTMR[1]: %s", f.Detail)
		}
	})

	t.Run("rtmr2_mismatch", func(t *testing.T) {
		tdx := &TDXVerifyResult{RTMRs: makeRTMRs(t, strings.Repeat("ab", 48), strings.Repeat("cd", 48))}
		f := assertSingleFactor(t, evalTDXBootConfig(&ReportInput{
			TDX: tdx,
			Policy: MeasurementPolicy{
				RTMRAllow: [4]map[string]struct{}{
					nil,
					{strings.Repeat("ab", 48): {}},
					{strings.Repeat("00", 48): {}},
					nil,
				},
			},
		}), Fail)
		if !strings.Contains(f.Detail, "RTMR[2]") {
			t.Errorf("detail should mention RTMR[2]: %s", f.Detail)
		}
	})

	t.Run("pass_both_match", func(t *testing.T) {
		tdx := &TDXVerifyResult{RTMRs: makeRTMRs(t, strings.Repeat("ab", 48), strings.Repeat("cd", 48))}
		assertSingleFactor(t, evalTDXBootConfig(&ReportInput{
			TDX: tdx,
			Policy: MeasurementPolicy{
				RTMRAllow: [4]map[string]struct{}{
					nil,
					{strings.Repeat("ab", 48): {}},
					{strings.Repeat("cd", 48): {}},
					nil,
				},
			},
		}), Pass)
	})
}

func TestEvalTDXReportDataBinding(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	tests := []struct {
		name       string
		tdx        *TDXVerifyResult
		wantStatus Status
		wantDetail string
	}{
		{
			"pass_with_detail",
			&TDXVerifyResult{
				TeeTCBSVN:               make([]byte, 16),
				ReportDataBindingDetail: "REPORTDATA binds enclave public key via keccak256-derived address (0xabc123)",
			},
			Pass, "keccak256",
		},
		{
			"fail_no_verifier",
			&TDXVerifyResult{TeeTCBSVN: make([]byte, 16)},
			Fail, "no REPORTDATA verifier",
		},
		{
			"fail_nil_tdx",
			nil,
			Fail, "no parseable TDX",
		},
		{
			"fail_binding_err",
			&TDXVerifyResult{
				TeeTCBSVN:            make([]byte, 16),
				ReportDataBindingErr: errors.New("mismatch"),
			},
			Fail, "does not bind",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildMinimalRaw(nonce, sigKey)
			f := assertSingleFactor(t, evalTDXReportDataBinding(&ReportInput{
				Raw: raw, Nonce: nonce, TDX: tc.tdx,
			}), tc.wantStatus)
			if tc.wantDetail != "" && !strings.Contains(f.Detail, tc.wantDetail) {
				t.Errorf("detail %q should contain %q", f.Detail, tc.wantDetail)
			}
		})
	}
}

func TestEvalIntelPCSCollateral(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	tests := []struct {
		name string
		tdx  *TDXVerifyResult
		want Status
	}{
		{"skip_nil_tdx", nil, Skip},
		{"pass_with_tcb_status", &TDXVerifyResult{TeeTCBSVN: make([]byte, 16), TcbStatus: "UpToDate"}, Pass},
		{"skip_offline", &TDXVerifyResult{TeeTCBSVN: make([]byte, 16)}, Skip},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildMinimalRaw(nonce, sigKey)
			assertSingleFactor(t, evalIntelPCSCollateral(&ReportInput{
				Raw: raw, Nonce: nonce, TDX: tc.tdx,
			}), tc.want)
		})
	}
}

func TestEvalTDXTCBCurrent(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	tests := []struct {
		name       string
		tdx        *TDXVerifyResult
		want       Status
		wantDetail string
	}{
		{
			"up_to_date",
			&TDXVerifyResult{TeeTCBSVN: make([]byte, 16), TcbStatus: "UpToDate", AdvisoryIDs: []string{"INTEL-SA-00837"}},
			Pass, "UpToDate",
		},
		{
			"sw_hardening_needed",
			&TDXVerifyResult{TeeTCBSVN: make([]byte, 16), TcbStatus: "SWHardeningNeeded", AdvisoryIDs: []string{"INTEL-SA-00960"}},
			Fail, "",
		},
		{
			"out_of_date",
			&TDXVerifyResult{TeeTCBSVN: make([]byte, 16), TcbStatus: "OutOfDate"},
			Fail, "",
		},
		{
			"revoked",
			&TDXVerifyResult{TeeTCBSVN: make([]byte, 16), TcbStatus: "Revoked"},
			Fail, "",
		},
		{
			"offline_shows_svn",
			&TDXVerifyResult{TeeTCBSVN: []byte{0x07, 0x01, 0x03, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
			Skip, "TEE_TCB_SVN",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildMinimalRaw(nonce, sigKey)
			f := assertSingleFactor(t, evalTDXTCBCurrent(&ReportInput{
				Raw: raw, Nonce: nonce, TDX: tc.tdx,
			}), tc.want)
			if tc.wantDetail != "" && !strings.Contains(f.Detail, tc.wantDetail) {
				t.Errorf("detail %q should contain %q", f.Detail, tc.wantDetail)
			}
		})
	}
}

func TestEvalTDXTCBNotRevoked(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	tests := []struct {
		name       string
		tdx        *TDXVerifyResult
		want       Status
		wantDetail string
	}{
		{
			"pass_up_to_date",
			&TDXVerifyResult{TeeTCBSVN: make([]byte, 16), TcbStatus: "UpToDate"},
			Pass, "not Revoked",
		},
		{
			"pass_sw_hardening_needed",
			&TDXVerifyResult{TeeTCBSVN: make([]byte, 16), TcbStatus: "SWHardeningNeeded"},
			Pass, "not Revoked",
		},
		{
			"pass_out_of_date",
			&TDXVerifyResult{TeeTCBSVN: make([]byte, 16), TcbStatus: "OutOfDate"},
			Pass, "not Revoked",
		},
		{
			"fail_revoked",
			&TDXVerifyResult{TeeTCBSVN: make([]byte, 16), TcbStatus: "Revoked"},
			Fail, "Revoked",
		},
		{
			"skip_nil_tdx",
			nil,
			Skip, "no parseable TDX",
		},
		{
			"skip_offline",
			&TDXVerifyResult{TeeTCBSVN: make([]byte, 16)},
			Skip, "offline",
		},
		{
			"skip_collateral_err",
			&TDXVerifyResult{TeeTCBSVN: make([]byte, 16), CollateralErr: errors.New("timeout")},
			Skip, "collateral fetch failed",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildMinimalRaw(nonce, sigKey)
			f := assertSingleFactor(t, evalTDXTCBNotRevoked(&ReportInput{
				Raw: raw, Nonce: nonce, TDX: tc.tdx,
			}), tc.want)
			if tc.wantDetail != "" && !strings.Contains(f.Detail, tc.wantDetail) {
				t.Errorf("detail %q should contain %q", f.Detail, tc.wantDetail)
			}
		})
	}
}

func TestEvalNvidiaPayloadPresent(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	tests := []struct {
		name    string
		payload string
		want    Status
	}{
		{"absent", "", Fail},
		{"present", "some.jwt.token", Pass},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildMinimalRaw(nonce, sigKey)
			raw.NvidiaPayload = tc.payload
			assertSingleFactor(t, evalNvidiaPayloadPresent(&ReportInput{Raw: raw}), tc.want)
		})
	}
}

func TestEvalNvidiaSignature(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	t.Run("pass", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		raw.NvidiaPayload = `{"evidence_list":[]}`
		nv := &NvidiaVerifyResult{Format: "EAT", Arch: "HOPPER", GPUCount: 8, Nonce: nonce.Hex()}
		f := assertSingleFactor(t, evalNvidiaSignature(&ReportInput{Raw: raw, Nvidia: nv}), Pass)
		if !strings.Contains(f.Detail, "HOPPER") || !strings.Contains(f.Detail, "8 GPU") {
			t.Errorf("detail should mention HOPPER and 8 GPU: %s", f.Detail)
		}
	})

	t.Run("fail_sig_err", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		raw.NvidiaPayload = `{"evidence_list":[]}`
		nv := &NvidiaVerifyResult{Format: "EAT", SignatureErr: errors.New("bad cert chain")}
		f := assertSingleFactor(t, evalNvidiaSignature(&ReportInput{Raw: raw, Nvidia: nv}), Fail)
		if !strings.Contains(f.Detail, "bad cert chain") {
			t.Errorf("detail should mention error: %s", f.Detail)
		}
	})

	t.Run("skip_no_payload", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		assertSingleFactor(t, evalNvidiaSignature(&ReportInput{Raw: raw}), Skip)
	})
}

func TestEvalNvidiaClaims(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	t.Run("pass", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		raw.NvidiaPayload = `{"evidence_list":[]}`
		nv := &NvidiaVerifyResult{Format: "EAT", Arch: "HOPPER", GPUCount: 4, Nonce: nonce.Hex()}
		f := assertSingleFactor(t, evalNvidiaClaims(&ReportInput{Raw: raw, Nvidia: nv}), Pass)
		if !strings.Contains(f.Detail, "arch=HOPPER") {
			t.Errorf("detail should mention arch=HOPPER: %s", f.Detail)
		}
	})

	t.Run("fail_claims_err", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		raw.NvidiaPayload = `{"evidence_list":[]}`
		nv := &NvidiaVerifyResult{Format: "EAT", ClaimsErr: errors.New("invalid arch")}
		assertSingleFactor(t, evalNvidiaClaims(&ReportInput{Raw: raw, Nvidia: nv}), Fail)
	})
}

func TestEvalNvidiaClientNonceBound(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	t.Run("pass", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		raw.NvidiaPayload = `{"evidence_list":[]}`
		nv := &NvidiaVerifyResult{Format: "EAT", GPUCount: 8, Nonce: nonce.Hex()}
		f := assertSingleFactor(t, evalNvidiaClientNonceBound(&ReportInput{Raw: raw, Nonce: nonce, Nvidia: nv}), Pass)
		if !strings.Contains(f.Detail, "8 GPU") {
			t.Errorf("detail should mention 8 GPU: %s", f.Detail)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		raw.NvidiaPayload = `{"evidence_list":[]}`
		nv := &NvidiaVerifyResult{Format: "EAT", Nonce: "wrong-nonce"}
		assertSingleFactor(t, evalNvidiaClientNonceBound(&ReportInput{Raw: raw, Nonce: nonce, Nvidia: nv}), Fail)
	})

	t.Run("skip_no_payload", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		assertSingleFactor(t, evalNvidiaClientNonceBound(&ReportInput{Raw: raw, Nonce: nonce, Nvidia: nil}), Skip)
	})

	t.Run("skip_empty_nonce", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		raw.NvidiaPayload = `{"evidence_list":[]}`
		nv := &NvidiaVerifyResult{Format: "EAT", Nonce: ""}
		assertSingleFactor(t, evalNvidiaClientNonceBound(&ReportInput{Raw: raw, Nonce: nonce, Nvidia: nv}), Skip)
	})
}

func TestEvalNvidiaNRASVerified(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	tests := []struct {
		name       string
		payload    string
		nras       *NvidiaVerifyResult
		want       Status
		wantDetail string
	}{
		{
			"pass",
			`{"evidence_list":[]}`,
			&NvidiaVerifyResult{Format: "JWT", OverallResult: true},
			Pass, "true",
		},
		{
			"fail_not_success",
			`{"evidence_list":[]}`,
			&NvidiaVerifyResult{Format: "JWT", OverallResult: false},
			Fail, "",
		},
		{
			"skip_offline",
			`{"evidence_list":[]}`,
			nil,
			Skip, "offline",
		},
		{
			"skip_no_eat",
			"eyJhbGciOi...",
			nil,
			Skip, "no EAT",
		},
		{
			"fail_sig_err",
			`{"evidence_list":[]}`,
			&NvidiaVerifyResult{Format: "JWT", SignatureErr: errors.New("bad sig")},
			Fail, "",
		},
		{
			"fail_claims_err",
			`{"evidence_list":[]}`,
			&NvidiaVerifyResult{Format: "JWT", ClaimsErr: errors.New("bad claims")},
			Fail, "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildMinimalRaw(nonce, sigKey)
			raw.NvidiaPayload = tc.payload
			f := assertSingleFactor(t, evalNvidiaNRASVerified(&ReportInput{
				Raw: raw, Nonce: nonce, NvidiaNRAS: tc.nras,
			}), tc.want)
			if tc.wantDetail != "" && !strings.Contains(f.Detail, tc.wantDetail) {
				t.Errorf("detail %q should contain %q", f.Detail, tc.wantDetail)
			}
		})
	}
}

func TestEvalE2EECapable(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	tests := []struct {
		name string
		key  string
		want Status
	}{
		{"pass_valid_key", sigKey, Pass},
		{"fail_empty", "", Fail},
		{"fail_malformed", strings.Repeat("0", 130), Fail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildMinimalRaw(nonce, tc.key)
			assertSingleFactor(t, evalE2EECapable(&ReportInput{Raw: raw}), tc.want)
		})
	}
}

func TestEvalTLSKeyBinding(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	tests := []struct {
		name       string
		fp         string
		key        string
		want       Status
		wantDetail string
	}{
		{"pass_with_fingerprint", "aabbccddee112233445566778899aabb", sigKey, Pass, "aabbccddee112233"},
		{"skip_e2ee", "", sigKey, Skip, ""},
		{"fail_neither", "", "", Fail, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildMinimalRaw(nonce, tc.key)
			raw.TLSFingerprint = tc.fp
			f := assertSingleFactor(t, evalTLSKeyBinding(&ReportInput{Raw: raw}), tc.want)
			if tc.wantDetail != "" && !strings.Contains(f.Detail, tc.wantDetail) {
				t.Errorf("detail %q should contain %q", f.Detail, tc.wantDetail)
			}
		})
	}
}

func TestEvalCPUGPUChain(t *testing.T) {
	assertSingleFactor(t, evalCPUGPUChain(&ReportInput{Raw: &RawAttestation{}}), Fail)
}

func TestEvalMeasuredModelWeights(t *testing.T) {
	assertSingleFactor(t, evalMeasuredModelWeights(&ReportInput{Raw: &RawAttestation{}}), Fail)
}

func TestEvalComposeBinding(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	tests := []struct {
		name    string
		compose *ComposeBindingResult
		want    Status
	}{
		{"pass", &ComposeBindingResult{Checked: true}, Pass},
		{"fail_err", &ComposeBindingResult{Checked: true, Err: errors.New("hash mismatch")}, Fail},
		{"skip_nil", nil, Skip},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildMinimalRaw(nonce, sigKey)
			assertSingleFactor(t, evalComposeBinding(&ReportInput{
				Raw: raw, Compose: tc.compose,
			}), tc.want)
		})
	}
}

func TestEvalSigstoreVerification(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	t.Run("pass_all_ok", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		sig := []SigstoreResult{
			{Digest: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234", OK: true, Status: 200},
			{Digest: "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff", OK: true, Status: 200},
		}
		assertSingleFactor(t, evalSigstoreVerification(&ReportInput{
			Provider: "neardirect", Raw: raw, Sigstore: sig,
		}), Pass)
	})

	t.Run("fail_not_found", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		sig := []SigstoreResult{
			{Digest: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234", OK: true, Status: 200},
			{Digest: "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff", OK: false, Status: 404},
		}
		assertSingleFactor(t, evalSigstoreVerification(&ReportInput{
			Provider: "neardirect", Raw: raw, Sigstore: sig,
		}), Fail)
	})

	t.Run("fail_unknown_non_rekor", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		unknownDigest := "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
		sig := []SigstoreResult{{Digest: unknownDigest, OK: false, Status: 404}}
		assertSingleFactor(t, evalSigstoreVerification(&ReportInput{
			Provider:     "neardirect",
			Raw:          raw,
			Sigstore:     sig,
			DigestToRepo: map[string]string{unknownDigest: "attacker/evil-image"},
			ImageRepos:   []string{"attacker/evil-image"},
		}), Fail)
	})

	t.Run("skip_no_digests", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		assertSingleFactor(t, evalSigstoreVerification(&ReportInput{
			Provider: "neardirect", Raw: raw,
		}), Skip)
	})
}

func TestEvalEventLogIntegrity(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	t.Run("pass_replay_matches_quote", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		raw.EventLog = []EventLogEntry{{IMR: 0, Digest: strings.Repeat("ab", 48)}}

		replayed, err := ReplayEventLog(raw.EventLog)
		if err != nil {
			t.Fatalf("ReplayEventLog: %v", err)
		}

		tdx := &TDXVerifyResult{RTMRs: replayed}
		// Policy mismatch is irrelevant — event_log_integrity only checks replay consistency.
		assertSingleFactor(t, evalEventLogIntegrity(&ReportInput{
			Raw:   raw,
			Nonce: nonce,
			TDX:   tdx,
			Policy: MeasurementPolicy{
				RTMRAllow: [4]map[string]struct{}{
					{strings.Repeat("00", 48): {}},
					nil,
					nil,
					nil,
				},
			},
		}), Pass)
	})
}

// ---------------------------------------------------------------------------
// ProvenanceType.String test
// ---------------------------------------------------------------------------

func TestProvenanceTypeString(t *testing.T) {
	tests := []struct {
		p    ProvenanceType
		want string
	}{
		{FulcioSigned, "fulcio-signed"},
		{SigstorePresent, "sigstore-present"},
		{ComposeBindingOnly, "compose-binding-only"},
		{ProvenanceType(99), "unknown"},
	}
	for _, tc := range tests {
		if got := tc.p.String(); got != tc.want {
			t.Errorf("ProvenanceType(%d).String() = %q, want %q", tc.p, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Tier 3 always-fail factors via BuildReport (quick sanity check)
// ---------------------------------------------------------------------------

func TestBuildReportTier3AlwaysFail(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, AllowFail: DefaultAllowFail})

	for _, name := range []string{"cpu_gpu_chain", "measured_model_weights", "build_transparency_log"} {
		f := findFactor(t, report, name)
		if f.Status != Fail {
			t.Errorf("Tier 3 factor %q: got %s, want FAIL", name, f.Status)
		}
		if f.Detail == "" {
			t.Errorf("Tier 3 factor %q: Detail is empty", name)
		}
	}

	// tls_key_binding skips when SigningKey is present (E2EE replaces TLS binding).
	tlsF := findFactor(t, report, "tls_key_binding")
	if tlsF.Status != Skip {
		t.Errorf("tls_key_binding with SigningKey (E2EE): got %s, want Skip", tlsF.Status)
	}

	// cpu_id_registry should Fail when no pocResult, no PPID, no DeviceID.
	f := findFactor(t, report, "cpu_id_registry")
	if f.Status != Fail {
		t.Errorf("cpu_id_registry without PoC or PPID: got %s, want FAIL", f.Status)
	}
}

// ---------------------------------------------------------------------------
// Status string test
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// NVIDIA detail formatter tests
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// buildMetadata tests
// ---------------------------------------------------------------------------

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
	m := buildMetadata(&ReportInput{Raw: raw})

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
	m := buildMetadata(&ReportInput{Raw: raw})
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
	m := buildMetadata(&ReportInput{Raw: raw, TDX: tdxResult})

	ppid, ok := m["ppid"]
	if !ok {
		t.Fatal("ppid not in metadata")
	}
	if ppid != "abcdef1234567890" {
		t.Errorf("ppid = %q, want %q", ppid, "abcdef1234567890")
	}
}

// ---------------------------------------------------------------------------
// Feature A: ReportDataBindingPassed
// ---------------------------------------------------------------------------

func TestReportDataBindingPassed(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		r := &VerificationReport{Factors: []FactorResult{
			{Name: "tdx_reportdata_binding", Status: Pass},
		}}
		if !r.ReportDataBindingPassed() {
			t.Error("expected true")
		}
	})
	t.Run("fail", func(t *testing.T) {
		r := &VerificationReport{Factors: []FactorResult{
			{Name: "tdx_reportdata_binding", Status: Fail},
		}}
		if r.ReportDataBindingPassed() {
			t.Error("expected false")
		}
	})
	t.Run("absent", func(t *testing.T) {
		r := &VerificationReport{Factors: []FactorResult{
			{Name: "some_other_factor", Status: Pass},
		}}
		if r.ReportDataBindingPassed() {
			t.Error("expected false when factor absent")
		}
	})
}

// ---------------------------------------------------------------------------
// Feature C: Ed25519 support in evalE2EECapable
// ---------------------------------------------------------------------------

// validEd25519Key generates a fresh ed25519 public key as 64-char hex.
func validEd25519Key(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return hex.EncodeToString(pub)
}

func TestEvalE2EECapable_Ed25519(t *testing.T) {
	nonce := NewNonce()

	t.Run("valid_ed25519_64hex", func(t *testing.T) {
		key := validEd25519Key(t)
		raw := buildMinimalRaw(nonce, key)
		f := assertSingleFactor(t, evalE2EECapable(&ReportInput{Raw: raw}), Pass)
		if !strings.Contains(f.Detail, "ed25519") {
			t.Errorf("detail should mention ed25519: %s", f.Detail)
		}
	})

	t.Run("valid_ed25519_with_algo", func(t *testing.T) {
		key := validEd25519Key(t)
		raw := buildMinimalRaw(nonce, key)
		raw.SigningAlgo = "ed25519"
		f := assertSingleFactor(t, evalE2EECapable(&ReportInput{Raw: raw}), Pass)
		if !strings.Contains(f.Detail, "ed25519") {
			t.Errorf("detail should mention ed25519: %s", f.Detail)
		}
	})

	t.Run("invalid_hex_64chars", func(t *testing.T) {
		// 64 chars but not valid hex
		raw := buildMinimalRaw(nonce, strings.Repeat("zz", 32))
		assertSingleFactor(t, evalE2EECapable(&ReportInput{Raw: raw}), Fail)
	})

	t.Run("wrong_length_63chars", func(t *testing.T) {
		// 63 hex chars — wrong length for Ed25519 (needs exactly 64)
		raw := buildMinimalRaw(nonce, strings.Repeat("aa", 31)+"a")
		// 63 chars goes to secp256k1 path (default), which also fails.
		assertSingleFactor(t, evalE2EECapable(&ReportInput{Raw: raw}), Fail)
	})
}

func TestEvalE2EECapable_MLKEM768(t *testing.T) {
	nonce := NewNonce()

	t.Run("valid_1184_bytes", func(t *testing.T) {
		key := base64.StdEncoding.EncodeToString(make([]byte, 1184))
		raw := buildMinimalRaw(nonce, key)
		raw.SigningAlgo = "ml-kem-768"
		f := assertSingleFactor(t, evalE2EECapable(&ReportInput{Raw: raw}), Pass)
		t.Logf("detail: %s", f.Detail)
		if !strings.Contains(f.Detail, "ML-KEM-768") {
			t.Errorf("detail should mention ML-KEM-768: %s", f.Detail)
		}
	})

	t.Run("wrong_size", func(t *testing.T) {
		key := base64.StdEncoding.EncodeToString(make([]byte, 1000))
		raw := buildMinimalRaw(nonce, key)
		raw.SigningAlgo = "ml-kem-768"
		f := assertSingleFactor(t, evalE2EECapable(&ReportInput{Raw: raw}), Fail)
		t.Logf("detail: %s", f.Detail)
		if !strings.Contains(f.Detail, "wrong size") {
			t.Errorf("detail should mention wrong size: %s", f.Detail)
		}
	})

	t.Run("invalid_base64", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, "!!!not-valid-base64!!!")
		raw.SigningAlgo = "ml-kem-768"
		f := assertSingleFactor(t, evalE2EECapable(&ReportInput{Raw: raw}), Fail)
		t.Logf("detail: %s", f.Detail)
		if !strings.Contains(f.Detail, "base64") {
			t.Errorf("detail should mention base64: %s", f.Detail)
		}
	})
}

// ---------------------------------------------------------------------------
// e2ee_usable evaluator tests
// ---------------------------------------------------------------------------

func TestEvalE2EEUsable(t *testing.T) {
	t.Run("skip_nil", func(t *testing.T) {
		f := assertSingleFactor(t, evalE2EEUsable(&ReportInput{
			Raw: &RawAttestation{},
		}), Skip)
		if !strings.Contains(f.Detail, "not configured") {
			t.Errorf("detail should mention not configured: %s", f.Detail)
		}
	})

	t.Run("skip_no_api_key", func(t *testing.T) {
		f := assertSingleFactor(t, evalE2EEUsable(&ReportInput{
			Raw: &RawAttestation{},
			E2EETest: &E2EETestResult{
				NoAPIKey:  true,
				APIKeyEnv: "VENICE_API_KEY",
			},
		}), Skip)
		if !strings.Contains(f.Detail, "VENICE_API_KEY") {
			t.Errorf("detail should mention env var: %s", f.Detail)
		}
	})

	t.Run("fail_error", func(t *testing.T) {
		f := assertSingleFactor(t, evalE2EEUsable(&ReportInput{
			Raw: &RawAttestation{},
			E2EETest: &E2EETestResult{
				Attempted: true,
				Err:       errors.New("delta.reasoning: expected encrypted but not recognised"),
			},
		}), Fail)
		if !strings.Contains(f.Detail, "reasoning") {
			t.Errorf("detail should contain error: %s", f.Detail)
		}
	})

	t.Run("pass_attempted", func(t *testing.T) {
		f := assertSingleFactor(t, evalE2EEUsable(&ReportInput{
			Raw: &RawAttestation{},
			E2EETest: &E2EETestResult{
				Attempted: true,
				Detail:    "E2EE test inference: 5 chunks received, all content encrypted (v1 ecdsa)",
			},
		}), Pass)
		if !strings.Contains(f.Detail, "5 chunks") {
			t.Errorf("detail should contain chunk count: %s", f.Detail)
		}
	})

	t.Run("skip_offline", func(t *testing.T) {
		f := assertSingleFactor(t, evalE2EEUsable(&ReportInput{
			Raw: &RawAttestation{},
			E2EETest: &E2EETestResult{
				Detail: "offline mode; E2EE usability test skipped",
			},
		}), Skip)
		if !strings.Contains(f.Detail, "offline") {
			t.Errorf("detail should mention offline: %s", f.Detail)
		}
	})

	t.Run("enforced_no_api_key_promoted_to_fail", func(t *testing.T) {
		// When E2EETest is populated (teep verify path), the factor is
		// NOT deferred. If enforced and Skip (no API key), it gets
		// promoted to Fail — correct fail-closed behavior.
		nonce := NewNonce()
		raw := buildMinimalRaw(nonce, validSigningKey(t))
		report := BuildReport(&ReportInput{
			Provider:  "venice",
			Model:     "test-model",
			Raw:       raw,
			Nonce:     nonce,
			AllowFail: allExcept("e2ee_usable"),
			E2EETest: &E2EETestResult{
				NoAPIKey:  true,
				APIKeyEnv: "VENICE_API_KEY",
			},
		})
		f := findFactor(t, report, "e2ee_usable")
		if f.Status != Fail {
			t.Errorf("e2ee_usable should be promoted to Fail (enforced, not deferred), got %s", f.Status)
		}
		if !f.Enforced {
			t.Error("should be marked enforced")
		}
	})
}

func TestEvalE2EEUsable_E2EEConfigured(t *testing.T) {
	t.Run("configured_pending", func(t *testing.T) {
		f := assertSingleFactor(t, evalE2EEUsable(&ReportInput{
			Raw:            &RawAttestation{},
			E2EEConfigured: true,
		}), Skip)
		if !strings.Contains(f.Detail, "pending") {
			t.Errorf("detail should mention pending: %s", f.Detail)
		}
		if strings.Contains(f.Detail, "not configured") {
			t.Error("detail should NOT say 'not configured' when E2EEConfigured is true")
		}
	})

	t.Run("not_configured_no_test", func(t *testing.T) {
		f := assertSingleFactor(t, evalE2EEUsable(&ReportInput{
			Raw: &RawAttestation{},
		}), Skip)
		if !strings.Contains(f.Detail, "not configured") {
			t.Errorf("detail should say not configured: %s", f.Detail)
		}
	})

	t.Run("e2ee_test_takes_precedence", func(t *testing.T) {
		// When E2EETest is non-nil, E2EEConfigured is irrelevant.
		f := assertSingleFactor(t, evalE2EEUsable(&ReportInput{
			Raw:            &RawAttestation{},
			E2EEConfigured: true,
			E2EETest: &E2EETestResult{
				Attempted: true,
				Detail:    "E2EE test passed",
			},
		}), Pass)
		if !strings.Contains(f.Detail, "E2EE test passed") {
			t.Errorf("detail should come from E2EETest: %s", f.Detail)
		}
	})
}

func TestMarkE2EEUsable(t *testing.T) {
	t.Run("promotes_skip_to_pass", func(t *testing.T) {
		report := &VerificationReport{
			Factors: []FactorResult{
				{Name: "nonce_match", Status: Pass},
				{Name: "e2ee_usable", Status: Skip, Detail: "E2EE configured; pending live test"},
			},
			Passed:  1,
			Skipped: 1,
		}
		report.MarkE2EEUsable("roundtrip succeeded")
		f := findFactor(t, report, "e2ee_usable")
		if f.Status != Pass {
			t.Errorf("status = %s, want Pass", f.Status)
		}
		if f.Detail != "roundtrip succeeded" {
			t.Errorf("detail = %q, want %q", f.Detail, "roundtrip succeeded")
		}
		if report.Passed != 2 {
			t.Errorf("Passed = %d, want 2", report.Passed)
		}
		if report.Skipped != 0 {
			t.Errorf("Skipped = %d, want 0", report.Skipped)
		}
	})

	t.Run("noop_already_pass", func(t *testing.T) {
		report := &VerificationReport{
			Factors: []FactorResult{
				{Name: "e2ee_usable", Status: Pass, Detail: "original"},
			},
			Passed:  1,
			Skipped: 0,
		}
		report.MarkE2EEUsable("second call")
		f := findFactor(t, report, "e2ee_usable")
		if f.Detail != "original" {
			t.Errorf("detail should not change for already-Pass factor: %s", f.Detail)
		}
		if report.Passed != 1 {
			t.Errorf("Passed should stay 1, got %d", report.Passed)
		}
	})

	t.Run("noop_missing_factor", func(t *testing.T) {
		report := &VerificationReport{
			Factors: []FactorResult{
				{Name: "nonce_match", Status: Pass},
			},
			Passed: 1,
		}
		// Should not panic when factor is absent.
		report.MarkE2EEUsable("roundtrip succeeded")
		if report.Passed != 1 {
			t.Errorf("Passed should remain 1, got %d", report.Passed)
		}
	})

	t.Run("skipped_zero_no_underflow", func(t *testing.T) {
		// If Skipped is already 0 (out-of-sync counters), MarkE2EEUsable
		// must not underflow to a negative value.
		report := &VerificationReport{
			Factors: []FactorResult{
				{Name: "e2ee_usable", Status: Skip, Detail: "pending"},
			},
			Passed:  0,
			Skipped: 0, // desynced: factor is Skip but counter is 0
		}
		report.MarkE2EEUsable("roundtrip succeeded")
		f := findFactor(t, report, "e2ee_usable")
		if f.Status != Pass {
			t.Errorf("status = %s, want Pass", f.Status)
		}
		if report.Passed != 1 {
			t.Errorf("Passed = %d, want 1", report.Passed)
		}
		if report.Skipped != 0 {
			t.Errorf("Skipped = %d, want 0 (should not underflow)", report.Skipped)
		}
	})
}

// ---------------------------------------------------------------------------
// Feature D: DSSE signature verification
// ---------------------------------------------------------------------------

func TestVerifyFulcioEntry_DSSE(t *testing.T) {
	img := &ImageProvenance{
		Repo:        "example/app",
		Provenance:  FulcioSigned,
		OIDCIssuer:  "https://token.actions.githubusercontent.com",
		SourceRepos: []string{"example/app"},
	}
	goodEntry := &RekorProvenance{
		HasCert:       true,
		OIDCIssuer:    "https://token.actions.githubusercontent.com",
		SourceRepo:    "example/app",
		SourceRepoURL: "https://github.com/example/app",
	}

	t.Run("sig_err_fails", func(t *testing.T) {
		r := *goodEntry
		r.SignatureErr = errors.New("DSSE verification failed")
		detail, failed := verifyFulcioEntry(&r, img, "example/app")
		if !failed {
			t.Fatal("expected failure")
		}
		if !strings.Contains(detail, "DSSE") {
			t.Errorf("detail should mention DSSE: %s", detail)
		}
	})

	t.Run("sig_err_skipped_with_nodsse", func(t *testing.T) {
		imgNoDSSE := *img
		imgNoDSSE.NoDSSE = true
		r := *goodEntry
		r.SignatureErr = errors.New("DSSE verification failed")
		_, failed := verifyFulcioEntry(&r, &imgNoDSSE, "example/app")
		if failed {
			t.Fatal("NoDSSE should skip DSSE check")
		}
	})

	t.Run("no_sig_err_passes", func(t *testing.T) {
		_, failed := verifyFulcioEntry(goodEntry, img, "example/app")
		if failed {
			t.Fatal("expected pass")
		}
	})
}

// ---------------------------------------------------------------------------
// Feature E: Enforced event log → Fail
// ---------------------------------------------------------------------------

func TestEvalEventLogIntegrity_EmptySkips(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)
	raw := buildMinimalRaw(nonce, sigKey)
	// No event log entries — evaluator always returns Skip (enforcement is BuildReport's job).
	assertSingleFactor(t, evalEventLogIntegrity(&ReportInput{Raw: raw, Nonce: nonce}), Skip)
}

func TestEvalGatewayEventLogIntegrity_EmptySkips(t *testing.T) {
	// No gateway event log entries — evaluator always returns Skip.
	assertSingleFactor(t, evalGatewayEventLogIntegrity(&ReportInput{
		Raw:        &RawAttestation{},
		GatewayTDX: &TDXVerifyResult{},
	}), Skip)
}

func TestBuildReport_EnforcedPromotion(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)
	raw := buildMinimalRaw(nonce, sigKey)

	t.Run("skip_promoted_to_fail", func(t *testing.T) {
		report := BuildReport(&ReportInput{
			Provider:  "venice",
			Model:     "test-model",
			Raw:       raw,
			Nonce:     nonce,
			AllowFail: allExcept("event_log_integrity"),
		})
		f := findFactor(t, report, "event_log_integrity")
		if f.Status != Fail {
			t.Errorf("event_log_integrity: got %s, want Fail (enforced promotion)", f.Status)
		}
		if !f.Enforced {
			t.Error("event_log_integrity: Enforced flag should be true")
		}
		if !strings.Contains(f.Detail, "enforced") {
			t.Errorf("detail should mention enforced: %s", f.Detail)
		}
	})

	t.Run("skip_unchanged_without_enforcement", func(t *testing.T) {
		report := BuildReport(&ReportInput{
			Provider:  "venice",
			Model:     "test-model",
			Raw:       raw,
			Nonce:     nonce,
			AllowFail: KnownFactors,
		})
		f := findFactor(t, report, "event_log_integrity")
		if f.Status != Skip {
			t.Errorf("event_log_integrity: got %s, want Skip (not enforced)", f.Status)
		}
	})
}

// ---------------------------------------------------------------------------
// Gateway factor count test (Features B/F/G)
// ---------------------------------------------------------------------------

func TestBuildReportGatewayFactorCount(t *testing.T) {
	nonce := NewNonce()
	gatewayNonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport(&ReportInput{
		Provider:        "nearcloud",
		Model:           "test-model",
		Raw:             raw,
		Nonce:           nonce,
		AllowFail:       DefaultAllowFail,
		GatewayTDX:      &TDXVerifyResult{TeeTCBSVN: make([]byte, 16)},
		GatewayNonceHex: gatewayNonce.Hex(),
		GatewayNonce:    gatewayNonce,
	})

	// Base 29 + 13 gateway factors = 42
	// Gateway factors: gateway_nonce_match, gateway_tdx_quote_present,
	// gateway_tdx_quote_structure, gateway_tdx_cert_chain, gateway_tdx_quote_signature,
	// gateway_tdx_debug_disabled, gateway_tdx_mrseam_mrtd, gateway_tdx_hardware_config,
	// gateway_tdx_boot_config, gateway_tdx_reportdata_binding,
	// gateway_compose_binding, gateway_cpu_id_registry, gateway_event_log_integrity
	if len(report.Factors) != 42 {
		t.Errorf("factor count with gateway: got %d, want 42", len(report.Factors))
		for _, f := range report.Factors {
			t.Logf("  [%s] %s: %s", f.Status, f.Name, f.Detail)
		}
	}
}

// ---------------------------------------------------------------------------
// Clone
// ---------------------------------------------------------------------------

func TestClone(t *testing.T) {
	t.Run("deep_copies_factors", func(t *testing.T) {
		orig := &VerificationReport{
			Factors: []FactorResult{
				{Name: "a", Status: Pass, Detail: "ok"},
				{Name: "b", Status: Fail, Detail: "bad"},
			},
			Passed: 1, Failed: 1,
		}
		cloned := orig.Clone()
		// Mutate clone; original must be unchanged.
		cloned.Factors[0].Status = Fail
		cloned.Factors[0].Detail = "mutated"
		if orig.Factors[0].Status != Pass {
			t.Error("original factor status was mutated via clone")
		}
		if orig.Factors[0].Detail != "ok" {
			t.Error("original factor detail was mutated via clone")
		}
	})

	t.Run("deep_copies_metadata", func(t *testing.T) {
		orig := &VerificationReport{
			Metadata: map[string]string{"key": "val"},
		}
		cloned := orig.Clone()
		cloned.Metadata["key"] = "changed"
		cloned.Metadata["new"] = "added"
		if orig.Metadata["key"] != "val" {
			t.Error("original metadata was mutated via clone")
		}
		if _, ok := orig.Metadata["new"]; ok {
			t.Error("new key appeared in original metadata after clone mutation")
		}
	})

	t.Run("nil_report", func(t *testing.T) {
		var r *VerificationReport
		if r.Clone() != nil {
			t.Error("Clone of nil report should return nil")
		}
	})

	t.Run("nil_metadata", func(t *testing.T) {
		orig := &VerificationReport{
			Factors: []FactorResult{{Name: "a", Status: Pass}},
			Passed:  1,
		}
		cloned := orig.Clone()
		if cloned.Metadata != nil {
			t.Error("clone of report with nil Metadata should have nil Metadata")
		}
		if cloned.Passed != 1 {
			t.Errorf("Passed = %d, want 1", cloned.Passed)
		}
	})

	t.Run("preserves_scalar_fields", func(t *testing.T) {
		orig := &VerificationReport{
			Provider: "test-provider",
			Model:    "test-model",
			Passed:   3,
			Failed:   1,
			Skipped:  2,
		}
		cloned := orig.Clone()
		if cloned.Provider != orig.Provider || cloned.Model != orig.Model {
			t.Error("scalar fields not preserved")
		}
		if cloned.Passed != 3 || cloned.Failed != 1 || cloned.Skipped != 2 {
			t.Error("counter fields not preserved")
		}
	})
}

// ---------------------------------------------------------------------------
// recomputeCounters
// ---------------------------------------------------------------------------

func TestRecomputeCounters(t *testing.T) {
	t.Run("correct_counts", func(t *testing.T) {
		r := &VerificationReport{
			Factors: []FactorResult{
				{Name: "a", Status: Pass},
				{Name: "b", Status: Pass},
				{Name: "c", Status: Fail, Enforced: true},
				{Name: "d", Status: Skip},
				{Name: "e", Status: Fail, Enforced: false},
				{Name: "e2ee_usable", Status: Skip, Detail: "pending"},
			},
		}
		r.MarkE2EEUsable("roundtrip ok")
		// e2ee_usable promoted: 3 pass, 2 fail, 1 skip
		if r.Passed != 3 {
			t.Errorf("Passed = %d, want 3", r.Passed)
		}
		if r.Failed != 2 {
			t.Errorf("Failed = %d, want 2", r.Failed)
		}
		if r.Skipped != 1 {
			t.Errorf("Skipped = %d, want 1", r.Skipped)
		}
		if r.EnforcedFailed != 1 {
			t.Errorf("EnforcedFailed = %d, want 1", r.EnforcedFailed)
		}
		if r.AllowedFailed != 1 {
			t.Errorf("AllowedFailed = %d, want 1", r.AllowedFailed)
		}
	})

	t.Run("desynced_counters_fixed", func(t *testing.T) {
		// Start with intentionally wrong counters.
		r := &VerificationReport{
			Factors: []FactorResult{
				{Name: "a", Status: Pass},
				{Name: "e2ee_usable", Status: Skip},
			},
			Passed:  99,
			Skipped: 0,
		}
		r.MarkE2EEUsable("promotes skip to pass and recomputes")
		if r.Passed != 2 {
			t.Errorf("Passed = %d, want 2 (recomputed from factors)", r.Passed)
		}
		if r.Skipped != 0 {
			t.Errorf("Skipped = %d, want 0", r.Skipped)
		}
	})
}

// ---------------------------------------------------------------------------
// MarkE2EEFailed
// ---------------------------------------------------------------------------

func TestMarkE2EEFailed(t *testing.T) {
	t.Run("demotes_pass_to_fail", func(t *testing.T) {
		report := &VerificationReport{
			Factors: []FactorResult{
				{Name: "nonce_match", Status: Pass},
				{Name: "e2ee_usable", Status: Pass, Detail: "roundtrip succeeded"},
			},
			Passed: 2,
		}
		report.MarkE2EEFailed("E2EE decryption failed: bad ciphertext")
		f := findFactor(t, report, "e2ee_usable")
		if f.Status != Fail {
			t.Errorf("status = %s, want Fail", f.Status)
		}
		if f.Detail != "E2EE decryption failed: bad ciphertext" {
			t.Errorf("detail = %q, want error message", f.Detail)
		}
		if report.Passed != 1 {
			t.Errorf("Passed = %d, want 1", report.Passed)
		}
		if report.Failed != 1 {
			t.Errorf("Failed = %d, want 1", report.Failed)
		}
	})

	t.Run("demotes_skip_to_fail", func(t *testing.T) {
		report := &VerificationReport{
			Factors: []FactorResult{
				{Name: "nonce_match", Status: Pass},
				{Name: "e2ee_usable", Status: Skip, Detail: "pending"},
			},
			Passed:  1,
			Skipped: 1,
		}
		report.MarkE2EEFailed("decryption failed")
		f := findFactor(t, report, "e2ee_usable")
		if f.Status != Fail {
			t.Errorf("status = %s, want Fail", f.Status)
		}
		if report.Skipped != 0 {
			t.Errorf("Skipped = %d, want 0", report.Skipped)
		}
		if report.Failed != 1 {
			t.Errorf("Failed = %d, want 1", report.Failed)
		}
	})

	t.Run("noop_already_fail", func(t *testing.T) {
		report := &VerificationReport{
			Factors: []FactorResult{
				{Name: "e2ee_usable", Status: Fail, Detail: "original error"},
			},
			Failed: 1,
		}
		report.MarkE2EEFailed("second failure")
		f := findFactor(t, report, "e2ee_usable")
		if f.Detail != "original error" {
			t.Errorf("detail should not change for already-Fail factor: %s", f.Detail)
		}
	})

	t.Run("noop_missing_factor", func(t *testing.T) {
		report := &VerificationReport{
			Factors: []FactorResult{
				{Name: "nonce_match", Status: Pass},
			},
			Passed: 1,
		}
		report.MarkE2EEFailed("decryption failed")
		if report.Passed != 1 {
			t.Errorf("Passed should remain 1, got %d", report.Passed)
		}
	})

	t.Run("enforced_counts_correct", func(t *testing.T) {
		report := &VerificationReport{
			Factors: []FactorResult{
				{Name: "nonce_match", Status: Pass, Enforced: true},
				{Name: "e2ee_usable", Status: Pass, Enforced: true},
			},
			Passed:         2,
			EnforcedFailed: 0,
		}
		report.MarkE2EEFailed("decryption failed")
		if report.EnforcedFailed != 1 {
			t.Errorf("EnforcedFailed = %d, want 1", report.EnforcedFailed)
		}
		if report.Passed != 1 {
			t.Errorf("Passed = %d, want 1", report.Passed)
		}
	})
}

// ---------------------------------------------------------------------------
// Deferred factor mechanism
// ---------------------------------------------------------------------------

func TestEvalE2EEUsable_Deferred(t *testing.T) {
	t.Run("deferred_when_e2ee_configured_no_test", func(t *testing.T) {
		// Proxy path: E2EEConfigured=true, E2EETest=nil → Deferred=true
		results := evalE2EEUsable(&ReportInput{
			Raw:            &RawAttestation{},
			E2EEConfigured: true,
		})
		f := assertSingleFactor(t, results, Skip)
		if !f.Deferred {
			t.Error("Deferred should be true for E2EEConfigured+nil E2EETest (proxy path)")
		}
	})

	t.Run("not_deferred_when_not_configured", func(t *testing.T) {
		// No E2EE configured → not deferred
		results := evalE2EEUsable(&ReportInput{
			Raw: &RawAttestation{},
		})
		f := assertSingleFactor(t, results, Skip)
		if f.Deferred {
			t.Error("Deferred should be false when E2EE is not configured")
		}
	})

	t.Run("not_deferred_when_test_passes", func(t *testing.T) {
		// teep verify path: E2EETest populated → not deferred
		results := evalE2EEUsable(&ReportInput{
			Raw:            &RawAttestation{},
			E2EEConfigured: true,
			E2EETest: &E2EETestResult{
				Attempted: true,
				Detail:    "E2EE test passed",
			},
		})
		f := assertSingleFactor(t, results, Pass)
		if f.Deferred {
			t.Error("Deferred should be false when E2EETest is populated and passes")
		}
	})

	t.Run("not_deferred_when_test_fails", func(t *testing.T) {
		results := evalE2EEUsable(&ReportInput{
			Raw: &RawAttestation{},
			E2EETest: &E2EETestResult{
				Attempted: true,
				Err:       errors.New("test failed"),
			},
		})
		f := assertSingleFactor(t, results, Fail)
		if f.Deferred {
			t.Error("Deferred should be false when E2EETest fails")
		}
	})
}

func TestBuildReport_DeferredSkipNotPromoted(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)
	raw := buildMinimalRaw(nonce, sigKey)

	t.Run("deferred_factor_stays_skip_when_enforced", func(t *testing.T) {
		// e2ee_usable is enforced (not in allow_fail) and deferred (E2EEConfigured=true).
		// It must stay Skip, not be promoted to Fail.
		report := BuildReport(&ReportInput{
			Provider:       "nearcloud",
			Model:          "test-model",
			Raw:            raw,
			Nonce:          nonce,
			AllowFail:      allExcept("e2ee_usable"),
			E2EEConfigured: true,
		})
		f := findFactor(t, report, "e2ee_usable")
		if f.Status != Skip {
			t.Errorf("e2ee_usable: got %s, want Skip (deferred factor should not be promoted)", f.Status)
		}
		if !f.Enforced {
			t.Error("e2ee_usable should be marked enforced")
		}
		if !f.Deferred {
			t.Error("e2ee_usable should be marked deferred")
		}
		// Report should NOT be blocked by the deferred skip.
		if report.Blocked() {
			t.Error("report should not be blocked when only deferred factors are Skip")
		}
	})

	t.Run("non_deferred_factor_promoted_to_fail", func(t *testing.T) {
		// A non-deferred enforced Skip factor is promoted to Fail.
		report := BuildReport(&ReportInput{
			Provider:  "venice",
			Model:     "test-model",
			Raw:       raw,
			Nonce:     nonce,
			AllowFail: allExcept("event_log_integrity"),
		})
		f := findFactor(t, report, "event_log_integrity")
		if f.Status != Fail {
			t.Errorf("event_log_integrity: got %s, want Fail (non-deferred enforced promotion)", f.Status)
		}
		if f.Deferred {
			t.Error("event_log_integrity should not be deferred")
		}
	})

	t.Run("deferred_not_configured_promoted_to_fail", func(t *testing.T) {
		// e2ee_usable with E2EEConfigured=false is NOT deferred, so it
		// can be promoted to Fail when enforced.
		report := BuildReport(&ReportInput{
			Provider:  "venice",
			Model:     "test-model",
			Raw:       raw,
			Nonce:     nonce,
			AllowFail: allExcept("e2ee_usable"),
		})
		f := findFactor(t, report, "e2ee_usable")
		if f.Status != Fail {
			t.Errorf("e2ee_usable (not configured): got %s, want Fail (not deferred, so promoted)", f.Status)
		}
		if f.Deferred {
			t.Error("e2ee_usable should not be deferred when not configured")
		}
	})
}

// TestAllowFailConsistency verifies that e2ee_usable behaves correctly under
// both allow_fail configurations (Venice/NearDirect vs NearCloud/Chutes).
func TestAllowFailConsistency(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)
	raw := buildMinimalRaw(nonce, sigKey)

	t.Run("venice_allow_fail_e2ee", func(t *testing.T) {
		// Venice: e2ee_usable is in DefaultAllowFail → not enforced.
		report := BuildReport(&ReportInput{
			Provider:       "venice",
			Model:          "test-model",
			Raw:            raw,
			Nonce:          nonce,
			AllowFail:      DefaultAllowFail,
			E2EEConfigured: true,
		})
		f := findFactor(t, report, "e2ee_usable")
		if f.Status != Skip {
			t.Errorf("venice e2ee_usable: got %s, want Skip", f.Status)
		}
		if f.Enforced {
			t.Error("venice: e2ee_usable should NOT be enforced (in DefaultAllowFail)")
		}
	})

	t.Run("nearcloud_enforced_e2ee_stays_skip", func(t *testing.T) {
		// NearCloud: e2ee_usable NOT in NearcloudDefaultAllowFail → enforced.
		// But since E2EEConfigured=true, Deferred=true, stays Skip.
		report := BuildReport(&ReportInput{
			Provider:       "nearcloud",
			Model:          "test-model",
			Raw:            raw,
			Nonce:          nonce,
			AllowFail:      NearcloudDefaultAllowFail,
			E2EEConfigured: true,
		})
		f := findFactor(t, report, "e2ee_usable")
		if f.Status != Skip {
			t.Errorf("nearcloud e2ee_usable: got %s, want Skip (deferred)", f.Status)
		}
		if !f.Enforced {
			t.Error("nearcloud: e2ee_usable should be enforced")
		}
		if !f.Deferred {
			t.Error("nearcloud: e2ee_usable should be deferred")
		}
	})

	t.Run("neardirect_enforced_e2ee_stays_skip", func(t *testing.T) {
		// NearDirect: e2ee_usable NOT in NeardirectDefaultAllowFail → enforced.
		// e2ee_usable is intentionally enforced for neardirect; do not add it
		// to NeardirectDefaultAllowFail without security review.
		report := BuildReport(&ReportInput{
			Provider:       "neardirect",
			Model:          "test-model",
			Raw:            raw,
			Nonce:          nonce,
			AllowFail:      NeardirectDefaultAllowFail,
			E2EEConfigured: true,
		})
		f := findFactor(t, report, "e2ee_usable")
		if f.Status != Skip {
			t.Errorf("neardirect e2ee_usable: got %s, want Skip (deferred)", f.Status)
		}
		if !f.Enforced {
			t.Error("neardirect: e2ee_usable should be enforced (not in NeardirectDefaultAllowFail)")
		}
		if !f.Deferred {
			t.Error("neardirect: e2ee_usable should be deferred")
		}
	})

	t.Run("chutes_enforced_e2ee_stays_skip", func(t *testing.T) {
		// Chutes: e2ee_usable NOT in ChutesDefaultAllowFail → enforced.
		report := BuildReport(&ReportInput{
			Provider:       "chutes",
			Model:          "test-model",
			Raw:            raw,
			Nonce:          nonce,
			AllowFail:      ChutesDefaultAllowFail,
			E2EEConfigured: true,
		})
		f := findFactor(t, report, "e2ee_usable")
		if f.Status != Skip {
			t.Errorf("chutes e2ee_usable: got %s, want Skip (deferred)", f.Status)
		}
		if !f.Enforced {
			t.Error("chutes: e2ee_usable should be enforced")
		}
		if !f.Deferred {
			t.Error("chutes: e2ee_usable should be deferred")
		}
	})

	t.Run("mark_usable_then_fail_roundtrip", func(t *testing.T) {
		// Simulate full lifecycle: build → MarkE2EEUsable → MarkE2EEFailed
		report := BuildReport(&ReportInput{
			Provider:       "nearcloud",
			Model:          "test-model",
			Raw:            raw,
			Nonce:          nonce,
			AllowFail:      NearcloudDefaultAllowFail,
			E2EEConfigured: true,
		})
		f := findFactor(t, report, "e2ee_usable")
		if f.Status != Skip {
			t.Fatalf("initial: got %s, want Skip", f.Status)
		}

		// Successful relay promotes to Pass.
		cloned := report.Clone()
		cloned.MarkE2EEUsable("E2EE roundtrip succeeded")
		f = findFactor(t, cloned, "e2ee_usable")
		if f.Status != Pass {
			t.Fatalf("after MarkE2EEUsable: got %s, want Pass", f.Status)
		}

		// Decryption failure demotes to Fail.
		failed := cloned.Clone()
		failed.MarkE2EEFailed("decryption error")
		f = findFactor(t, failed, "e2ee_usable")
		if f.Status != Fail {
			t.Errorf("after MarkE2EEFailed: got %s, want Fail", f.Status)
		}

		// Original is untouched.
		f = findFactor(t, report, "e2ee_usable")
		if f.Status != Skip {
			t.Error("original report should be unchanged after Clone+mutation")
		}

		// Cloned (Pass) is untouched.
		f = findFactor(t, cloned, "e2ee_usable")
		if f.Status != Pass {
			t.Error("cloned report (Pass) should be unchanged after further Clone+mutation")
		}
	})
}

// ---------------------------------------------------------------------------
// tdxQuoteVersion
// ---------------------------------------------------------------------------

func TestTDXQuoteVersion_Unknown(t *testing.T) {
	r := &TDXVerifyResult{} // quote is nil → default branch
	got := tdxQuoteVersion(r)
	if got != "Quote (unknown version)" {
		t.Errorf("tdxQuoteVersion (nil) = %q, want %q", got, "Quote (unknown version)")
	}
}

// ---------------------------------------------------------------------------
// evalGatewayNonceMatch
// ---------------------------------------------------------------------------

func TestEvalGatewayNonceMatch_Empty(t *testing.T) {
	in := &ReportInput{Raw: &RawAttestation{}, GatewayNonceHex: ""}
	results := evalGatewayNonceMatch(in)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != Fail {
		t.Errorf("status = %v, want Fail", results[0].Status)
	}
	t.Logf("result: %s %s", results[0].Status, results[0].Detail)
}

func TestEvalGatewayNonceMatch_Mismatch(t *testing.T) {
	nonce := NewNonce()
	in := &ReportInput{
		Raw:             &RawAttestation{},
		GatewayNonce:    nonce,
		GatewayNonceHex: NewNonce().Hex(), // different nonce
	}
	results := evalGatewayNonceMatch(in)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != Fail {
		t.Errorf("status = %v, want Fail", results[0].Status)
	}
	t.Logf("result: %s %s", results[0].Status, results[0].Detail)
}

// ---------------------------------------------------------------------------
// evalGatewayComposeBinding
// ---------------------------------------------------------------------------

func TestEvalGatewayComposeBinding_NilCompose(t *testing.T) {
	in := &ReportInput{Raw: &RawAttestation{}, GatewayCompose: nil}
	results := evalGatewayComposeBinding(in)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != Skip {
		t.Errorf("status = %v, want Skip", results[0].Status)
	}
}

func TestEvalGatewayComposeBinding_WithError(t *testing.T) {
	in := &ReportInput{
		Raw: &RawAttestation{},
		GatewayCompose: &ComposeBindingResult{
			Checked: true,
			Err:     errors.New("binding check failed"),
		},
	}
	results := evalGatewayComposeBinding(in)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != Fail {
		t.Errorf("status = %v, want Fail", results[0].Status)
	}
}

func TestEvalGatewayComposeBinding_Pass(t *testing.T) {
	in := &ReportInput{
		Raw: &RawAttestation{},
		GatewayCompose: &ComposeBindingResult{
			Checked: true,
			Err:     nil,
		},
	}
	results := evalGatewayComposeBinding(in)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != Pass {
		t.Errorf("status = %v, want Pass", results[0].Status)
	}
}

// ---------------------------------------------------------------------------
// buildTransparencyNoRekor
// ---------------------------------------------------------------------------

func TestBuildTransparencyNoRekor_WithScPolicy(t *testing.T) {
	scPolicy := &SupplyChainPolicy{} // non-nil → Fail
	in := &ReportInput{Raw: &RawAttestation{}}
	result := buildTransparencyNoRekor(in, scPolicy)
	if result.Status != Fail {
		t.Errorf("status = %v, want Fail", result.Status)
	}
	t.Logf("detail: %s", result.Detail)
}

func TestBuildTransparencyNoRekor_WithComposeHash(t *testing.T) {
	in := &ReportInput{
		Raw: &RawAttestation{ComposeHash: "abc123deadbeef"},
	}
	result := buildTransparencyNoRekor(in, nil)
	if result.Status != Skip {
		t.Errorf("status = %v, want Skip", result.Status)
	}
	t.Logf("detail: %s", result.Detail)
}

func TestBuildTransparencyNoRekor_Chutes(t *testing.T) {
	in := &ReportInput{
		Raw: &RawAttestation{BackendFormat: FormatChutes},
	}
	result := buildTransparencyNoRekor(in, nil)
	if result.Status != Skip {
		t.Errorf("status = %v, want Skip", result.Status)
	}
	t.Logf("detail: %s", result.Detail)
}

func TestBuildTransparencyNoRekor_NoRekorFail(t *testing.T) {
	in := &ReportInput{
		Raw: &RawAttestation{}, // no ComposeHash, not Chutes, scPolicy nil
	}
	result := buildTransparencyNoRekor(in, nil)
	if result.Status != Fail {
		t.Errorf("status = %v, want Fail", result.Status)
	}
}

// ---------------------------------------------------------------------------
// evalGatewayTDXMrseamMrtd
// ---------------------------------------------------------------------------

func TestEvalGatewayTDXMrseamMrtd_NilGatewayTDX(t *testing.T) {
	in := &ReportInput{Raw: &RawAttestation{}, GatewayTDX: nil}
	results := evalGatewayTDXMrseamMrtd(in)
	if results[0].Status != Skip {
		t.Errorf("status = %v, want Skip", results[0].Status)
	}
}

func TestEvalGatewayTDXMrseamMrtd_NoPolicy(t *testing.T) {
	in := &ReportInput{
		Raw:        &RawAttestation{},
		GatewayTDX: &TDXVerifyResult{},
		// No GatewayPolicy configured → both HasMRTDPolicy and HasMRSeamPolicy are false
	}
	results := evalGatewayTDXMrseamMrtd(in)
	if results[0].Status != Skip {
		t.Errorf("status = %v, want Skip", results[0].Status)
	}
}

func TestEvalGatewayTDXMrseamMrtd_MRTDFail(t *testing.T) {
	in := &ReportInput{
		Raw:        &RawAttestation{},
		GatewayTDX: &TDXVerifyResult{MRTD: []byte{0xaa, 0xbb}},
		GatewayPolicy: MeasurementPolicy{
			MRTDAllow: map[string]struct{}{"ccdd": {}},
		},
	}
	results := evalGatewayTDXMrseamMrtd(in)
	if results[0].Status != Fail {
		t.Errorf("status = %v, want Fail", results[0].Status)
	}
}

func TestEvalGatewayTDXMrseamMrtd_MRTDPass(t *testing.T) {
	mrtd := []byte{0xaa, 0xbb}
	mrtdHex := hex.EncodeToString(mrtd)
	in := &ReportInput{
		Raw:        &RawAttestation{},
		GatewayTDX: &TDXVerifyResult{MRTD: mrtd},
		GatewayPolicy: MeasurementPolicy{
			MRTDAllow: map[string]struct{}{mrtdHex: {}},
		},
	}
	results := evalGatewayTDXMrseamMrtd(in)
	if results[0].Status != Pass {
		t.Errorf("status = %v, want Pass", results[0].Status)
	}
}

func TestEvalGatewayTDXMrseamMrtd_MRSeamFail(t *testing.T) {
	in := &ReportInput{
		Raw:        &RawAttestation{},
		GatewayTDX: &TDXVerifyResult{MRSeam: []byte{0x01}},
		GatewayPolicy: MeasurementPolicy{
			MRSeamAllow: map[string]struct{}{"ffff": {}},
		},
	}
	results := evalGatewayTDXMrseamMrtd(in)
	if results[0].Status != Fail {
		t.Errorf("status = %v, want Fail", results[0].Status)
	}
}

func TestEvalGatewayTDXMrseamMrtd_BothMatch(t *testing.T) {
	mrtd := []byte{0xaa}
	mrseam := []byte{0xbb}
	in := &ReportInput{
		Raw:        &RawAttestation{},
		GatewayTDX: &TDXVerifyResult{MRTD: mrtd, MRSeam: mrseam},
		GatewayPolicy: MeasurementPolicy{
			MRTDAllow:   map[string]struct{}{hex.EncodeToString(mrtd): {}},
			MRSeamAllow: map[string]struct{}{hex.EncodeToString(mrseam): {}},
		},
	}
	results := evalGatewayTDXMrseamMrtd(in)
	if results[0].Status != Pass {
		t.Errorf("status = %v, want Pass", results[0].Status)
	}
}

// ---------------------------------------------------------------------------
// evalGatewayTDXHardwareConfig
// ---------------------------------------------------------------------------

func TestEvalGatewayTDXHardwareConfig_NilGatewayTDX(t *testing.T) {
	in := &ReportInput{Raw: &RawAttestation{}, GatewayTDX: nil}
	results := evalGatewayTDXHardwareConfig(in)
	if results[0].Status != Skip {
		t.Errorf("status = %v, want Skip", results[0].Status)
	}
}

func TestEvalGatewayTDXHardwareConfig_NoRTMR0Policy(t *testing.T) {
	in := &ReportInput{Raw: &RawAttestation{}, GatewayTDX: &TDXVerifyResult{}}
	results := evalGatewayTDXHardwareConfig(in)
	if results[0].Status != Skip {
		t.Errorf("status = %v, want Skip", results[0].Status)
	}
}

func TestEvalGatewayTDXHardwareConfig_RTMR0Fail(t *testing.T) {
	in := &ReportInput{
		Raw:        &RawAttestation{},
		GatewayTDX: &TDXVerifyResult{},
		GatewayPolicy: MeasurementPolicy{
			RTMRAllow: [4]map[string]struct{}{{("wronghex"): {}}},
		},
	}
	results := evalGatewayTDXHardwareConfig(in)
	if results[0].Status != Fail {
		t.Errorf("status = %v, want Fail", results[0].Status)
	}
}

func TestEvalGatewayTDXHardwareConfig_RTMR0Pass(t *testing.T) {
	var rtmr0 [48]byte
	rtmr0Hex := hex.EncodeToString(rtmr0[:])
	in := &ReportInput{
		Raw:        &RawAttestation{},
		GatewayTDX: &TDXVerifyResult{RTMRs: [4][48]byte{rtmr0}},
		GatewayPolicy: MeasurementPolicy{
			RTMRAllow: [4]map[string]struct{}{{rtmr0Hex: {}}},
		},
	}
	results := evalGatewayTDXHardwareConfig(in)
	if results[0].Status != Pass {
		t.Errorf("status = %v, want Pass", results[0].Status)
	}
}

// ---------------------------------------------------------------------------
// evalGatewayTDXBootConfig
// ---------------------------------------------------------------------------

func TestEvalGatewayTDXBootConfig_NilGatewayTDX(t *testing.T) {
	in := &ReportInput{Raw: &RawAttestation{}, GatewayTDX: nil}
	results := evalGatewayTDXBootConfig(in)
	if results[0].Status != Skip {
		t.Errorf("status = %v, want Skip", results[0].Status)
	}
}

func TestEvalGatewayTDXBootConfig_NoPolicy(t *testing.T) {
	in := &ReportInput{Raw: &RawAttestation{}, GatewayTDX: &TDXVerifyResult{}}
	results := evalGatewayTDXBootConfig(in)
	if results[0].Status != Skip {
		t.Errorf("status = %v, want Skip", results[0].Status)
	}
}

func TestEvalGatewayTDXBootConfig_RTMR1Fail(t *testing.T) {
	in := &ReportInput{
		Raw:        &RawAttestation{},
		GatewayTDX: &TDXVerifyResult{},
		GatewayPolicy: MeasurementPolicy{
			RTMRAllow: [4]map[string]struct{}{
				0: nil,
				1: {("wronghex"): {}},
			},
		},
	}
	results := evalGatewayTDXBootConfig(in)
	if results[0].Status != Fail {
		t.Errorf("status = %v, want Fail", results[0].Status)
	}
}

func TestEvalGatewayTDXBootConfig_Pass(t *testing.T) {
	var rtmr1, rtmr2 [48]byte
	rtmr1Hex := hex.EncodeToString(rtmr1[:])
	rtmr2Hex := hex.EncodeToString(rtmr2[:])
	in := &ReportInput{
		Raw:        &RawAttestation{},
		GatewayTDX: &TDXVerifyResult{},
		GatewayPolicy: MeasurementPolicy{
			RTMRAllow: [4]map[string]struct{}{
				0: nil,
				1: {rtmr1Hex: {}},
				2: {rtmr2Hex: {}},
			},
		},
	}
	results := evalGatewayTDXBootConfig(in)
	if results[0].Status != Pass {
		t.Errorf("status = %v, want Pass", results[0].Status)
	}
}

// ---------------------------------------------------------------------------
// evalGatewayTDXReportDataBinding
// ---------------------------------------------------------------------------

func TestEvalGatewayTDXReportDataBinding_ParseErr(t *testing.T) {
	in := &ReportInput{
		Raw:        &RawAttestation{},
		GatewayTDX: &TDXVerifyResult{ParseErr: errors.New("bad quote")},
	}
	results := evalGatewayTDXReportDataBinding(in)
	if results[0].Status != Fail {
		t.Errorf("status = %v, want Fail", results[0].Status)
	}
}

func TestEvalGatewayTDXReportDataBinding_BindingErr(t *testing.T) {
	in := &ReportInput{
		Raw:        &RawAttestation{},
		GatewayTDX: &TDXVerifyResult{ReportDataBindingErr: errors.New("nonce mismatch")},
	}
	results := evalGatewayTDXReportDataBinding(in)
	if results[0].Status != Fail {
		t.Errorf("status = %v, want Fail", results[0].Status)
	}
}

func TestEvalGatewayTDXReportDataBinding_Pass(t *testing.T) {
	in := &ReportInput{
		Raw:        &RawAttestation{},
		GatewayTDX: &TDXVerifyResult{ReportDataBindingDetail: "binding verified"},
	}
	results := evalGatewayTDXReportDataBinding(in)
	if results[0].Status != Pass {
		t.Errorf("status = %v, want Pass", results[0].Status)
	}
}

func TestEvalGatewayTDXReportDataBinding_NoDetail(t *testing.T) {
	in := &ReportInput{
		Raw:        &RawAttestation{},
		GatewayTDX: &TDXVerifyResult{}, // no ParseErr, no BindingErr, no Detail
	}
	results := evalGatewayTDXReportDataBinding(in)
	if results[0].Status != Fail {
		t.Errorf("status = %v, want Fail", results[0].Status)
	}
}
