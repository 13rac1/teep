package attestation

import (
	"crypto/ed25519"
	"crypto/rand"
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

// testNeardirectPolicy returns a neardirect supply chain policy for tests.
// Duplicates the policy from internal/provider/neardirect/policy.go to avoid
// circular imports (attestation cannot import provider).
func testNeardirectPolicy() *SupplyChainPolicy {
	return &SupplyChainPolicy{Images: []ImageProvenance{
		{Repo: "datadog/agent", ModelTier: true, Provenance: SigstorePresent,
			KeyFingerprint: "25bcab4ec8eede1e3091a14692126798c23986832ae6e5948d6f7eb0a928ab0b"},
		{Repo: "certbot/dns-cloudflare", ModelTier: true, Provenance: ComposeBindingOnly},
		{Repo: "nearaidev/compose-manager", ModelTier: true, Provenance: FulcioSigned,
			NoDSSE:       true,
			OIDCIssuer:   "https://token.actions.githubusercontent.com",
			OIDCIdentity: "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master",
			SourceRepos:  []string{"nearai/compose-manager", "https://github.com/nearai/compose-manager"}},
	}}
}

// testNearcloudPolicy returns a nearcloud supply chain policy for tests.
// Duplicates the policy from internal/provider/nearcloud/policy.go to avoid
// circular imports (attestation cannot import provider).
func testNearcloudPolicy() *SupplyChainPolicy {
	p := testNeardirectPolicy()
	// datadog/agent is also a gateway image in nearcloud.
	for i := range p.Images {
		if p.Images[i].Repo == "datadog/agent" {
			p.Images[i].GatewayTier = true
		}
	}
	ghOIDC := "https://token.actions.githubusercontent.com"
	p.Images = append(p.Images,
		ImageProvenance{Repo: "nearaidev/dstack-vpc-client", GatewayTier: true, Provenance: FulcioSigned,
			NoDSSE: true, OIDCIssuer: ghOIDC,
			OIDCIdentity: "https://github.com/nearai/dstack-vpc-client/.github/workflows/build.yml@refs/heads/main",
			SourceRepos:  []string{"nearai/dstack-vpc-client", "https://github.com/nearai/dstack-vpc-client"}},
		ImageProvenance{Repo: "nearaidev/dstack-vpc", GatewayTier: true, Provenance: FulcioSigned,
			NoDSSE: true, OIDCIssuer: ghOIDC,
			OIDCIdentity: "https://github.com/nearai/dstack-vpc/.github/workflows/build.yml@refs/heads/main",
			SourceRepos:  []string{"nearai/dstack-vpc", "https://github.com/nearai/dstack-vpc"}},
		ImageProvenance{Repo: "alpine", GatewayTier: true, Provenance: SigstorePresent},
		ImageProvenance{Repo: "nearaidev/cloud-api", GatewayTier: true, Provenance: FulcioSigned,
			NoDSSE: true, OIDCIssuer: ghOIDC,
			OIDCIdentity: "https://github.com/nearai/cloud-api/.github/workflows/build.yml@refs/heads/main",
			SourceRepos:  []string{"nearai/cloud-api", "https://github.com/nearai/cloud-api"}},
		ImageProvenance{Repo: "nearaidev/cvm-ingress", GatewayTier: true, Provenance: FulcioSigned,
			NoDSSE: true, OIDCIssuer: ghOIDC,
			OIDCIdentity: "https://github.com/nearai/cvm-ingress/.github/workflows/build-push.yml@refs/heads/main",
			SourceRepos:  []string{"nearai/cvm-ingress", "https://github.com/nearai/cvm-ingress"}},
	)
	return p
}

// ---------------------------------------------------------------------------
// BuildReport-level tests (cross-cutting concerns)
// ---------------------------------------------------------------------------

// TestBuildReportFactorCount ensures exactly 24 factors are produced.
func TestBuildReportFactorCount(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport(&ReportInput{Provider: "venice", Model: "test-model", Raw: raw, Nonce: nonce, Enforced: DefaultEnforced})

	if len(report.Factors) != 26 {
		t.Errorf("factor count: got %d, want 26", len(report.Factors))
	}
}

// TestBuildReportTotals verifies the Passed/Failed/Skipped tallies are consistent.
func TestBuildReportTotals(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport(&ReportInput{Provider: "venice", Model: "test-model", Raw: raw, Nonce: nonce, Enforced: DefaultEnforced})

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

// TestBuildReportEnforcedFlags verifies Enforced is set only for factors in the list.
func TestBuildReportEnforcedFlags(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, Enforced: DefaultEnforced})

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

// TestBlockedReturnsTrue verifies Blocked is true when an enforced factor fails.
func TestBlockedReturnsTrue(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	raw.Nonce = "" // force nonce_match to fail

	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, Enforced: DefaultEnforced})

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

	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, Enforced: DefaultEnforced})

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
// when no enforced factor fails.
func TestBlockedFactorsReturnsNilWhenNotBlocked(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, Enforced: []string{}})

	if blocked := report.BlockedFactors(); blocked != nil {
		t.Errorf("BlockedFactors() returned %v, want nil", blocked)
	}
}

// TestBlockedReturnsFalse verifies Blocked is false when no enforced factor fails.
func TestBlockedReturnsFalse(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, Enforced: []string{}})

	if report.Blocked() {
		t.Error("Blocked() returned true with empty enforced list")
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

func TestDefaultEnforcedIncludesSupplyChainFactors(t *testing.T) {
	need := map[string]bool{
		"sigstore_verification":  true,
		"build_transparency_log": true,
	}
	for _, f := range DefaultEnforced {
		delete(need, f)
	}
	if len(need) != 0 {
		t.Fatalf("DefaultEnforced missing required factors: %v", need)
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

	t.Run("mrtd_policy_mismatch", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		tdx := &TDXVerifyResult{
			MRTD:   bytesFromHex(t, strings.Repeat("11", 48)),
			MRSeam: bytesFromHex(t, strings.Repeat("22", 48)),
		}
		results := evalTDXParseDependent(&ReportInput{
			Raw:   raw,
			Nonce: nonce,
			TDX:   tdx,
			Policy: MeasurementPolicy{
				MRTDAllow: map[string]struct{}{strings.Repeat("aa", 48): {}},
			},
		})
		f := assertFactor(t, results, "tdx_quote_structure", Fail)
		if !strings.Contains(f.Detail, "MRTD") {
			t.Errorf("detail should mention MRTD: %s", f.Detail)
		}
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
			"skip_no_verifier",
			&TDXVerifyResult{TeeTCBSVN: make([]byte, 16)},
			Skip, "no REPORTDATA verifier",
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

func TestEvalNvidiaNonceMatch(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	t.Run("pass", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		raw.NvidiaPayload = `{"evidence_list":[]}`
		nv := &NvidiaVerifyResult{Format: "EAT", GPUCount: 8, Nonce: nonce.Hex()}
		f := assertSingleFactor(t, evalNvidiaNonceMatch(&ReportInput{Raw: raw, Nonce: nonce, Nvidia: nv}), Pass)
		if !strings.Contains(f.Detail, "8 GPU") {
			t.Errorf("detail should mention 8 GPU: %s", f.Detail)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		raw.NvidiaPayload = `{"evidence_list":[]}`
		nv := &NvidiaVerifyResult{Format: "EAT", Nonce: "wrong-nonce"}
		assertSingleFactor(t, evalNvidiaNonceMatch(&ReportInput{Raw: raw, Nonce: nonce, Nvidia: nv}), Fail)
	})
}

func TestEvalNvidiaClientNonceBound(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	t.Run("pass_direct_match", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		raw.NvidiaPayload = `{"evidence_list":[]}`
		nv := &NvidiaVerifyResult{Format: "EAT", Nonce: nonce.Hex()}
		f := assertSingleFactor(t, evalNvidiaClientNonceBound(&ReportInput{Raw: raw, Nonce: nonce, Nvidia: nv}), Pass)
		if !strings.Contains(f.Detail, "client nonce directly") {
			t.Errorf("detail should mention direct match: %s", f.Detail)
		}
	})

	t.Run("fail_matched_via_request_nonce", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		raw.NvidiaPayload = `{"evidence_list":[]}`
		raw.NvidiaNonce = "aabbccdd"
		nv := &NvidiaVerifyResult{Format: "EAT", Nonce: "aabbccdd"} // matches request_nonce, not client
		f := assertSingleFactor(t, evalNvidiaClientNonceBound(&ReportInput{Raw: raw, Nonce: nonce, Nvidia: nv}), Fail)
		if !strings.Contains(f.Detail, "request_nonce") {
			t.Errorf("detail should mention request_nonce fallback: %s", f.Detail)
		}
	})

	t.Run("skip_no_nvidia", func(t *testing.T) {
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

	t.Run("pass_allowlisted_non_rekor", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		neardirectDigest := "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
		certbotDigest := "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
		sig := []SigstoreResult{
			{Digest: neardirectDigest, OK: true, Status: 200},
			{Digest: certbotDigest, OK: false, Status: 404},
		}
		f := assertSingleFactor(t, evalSigstoreVerification(&ReportInput{
			Provider:          "neardirect",
			Raw:               raw,
			SupplyChainPolicy: testNeardirectPolicy(),
			Sigstore:          sig,
			DigestToRepo:      map[string]string{neardirectDigest: "nearaidev/compose-manager", certbotDigest: "certbot/dns-cloudflare"},
			ImageRepos:        []string{"nearaidev/compose-manager", "certbot/dns-cloudflare"},
		}), Pass)
		if !strings.Contains(f.Detail, "compose-pinned") {
			t.Errorf("detail should mention compose-pinned: %s", f.Detail)
		}
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

	t.Run("rtmr_policy_mismatch", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		raw.EventLog = []EventLogEntry{{IMR: 0, Digest: strings.Repeat("ab", 48)}}

		replayed, err := ReplayEventLog(raw.EventLog)
		if err != nil {
			t.Fatalf("ReplayEventLog: %v", err)
		}

		tdx := &TDXVerifyResult{RTMRs: replayed}
		f := assertSingleFactor(t, evalEventLogIntegrity(&ReportInput{
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
		}), Fail)
		if !strings.Contains(f.Detail, "RTMR[0]") {
			t.Errorf("detail should mention RTMR[0]: %s", f.Detail)
		}
	})
}

// ---------------------------------------------------------------------------
// Build transparency log (supply chain policy) tests
// ---------------------------------------------------------------------------

func TestEvalBuildTransparencyLog(t *testing.T) {
	nonce := NewNonce()
	sigKey := validSigningKey(t)

	t.Run("pass_neardirect", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		sig := []SigstoreResult{{
			Digest: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			OK:     true, Status: 200,
		}}
		rekor := []RekorProvenance{{
			Digest:        sig[0].Digest,
			HasCert:       true,
			SubjectURI:    "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master",
			OIDCIssuer:    "https://token.actions.githubusercontent.com",
			SourceRepo:    "nearai/compose-manager",
			SourceRepoURL: "https://github.com/nearai/compose-manager",
			SourceCommit:  "0123456789abcdef",
			RunnerEnv:     "github-hosted",
		}}
		assertSingleFactor(t, evalBuildTransparencyLog(&ReportInput{
			Provider:          "neardirect",
			Raw:               raw,
			SupplyChainPolicy: testNeardirectPolicy(),
			ImageRepos:        []string{"nearaidev/compose-manager"},
			DigestToRepo:      map[string]string{sig[0].Digest: "nearaidev/compose-manager"},
			Sigstore:          sig,
			Rekor:             rekor,
		}), Pass)
	})

	t.Run("rejects_image_repo", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		f := assertSingleFactor(t, evalBuildTransparencyLog(&ReportInput{
			Provider:          "neardirect",
			Raw:               raw,
			SupplyChainPolicy: testNeardirectPolicy(),
			ImageRepos:        []string{"ghcr.io/attacker/router"},
		}), Fail)
		if !strings.Contains(f.Detail, "supply chain policy") {
			t.Errorf("detail should mention supply chain policy: %s", f.Detail)
		}
	})

	t.Run("nearcloud_separate_allowlists", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		sig := []SigstoreResult{{
			Digest: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			OK:     true, Status: 200,
		}}
		rekor := []RekorProvenance{{
			Digest:        sig[0].Digest,
			HasCert:       true,
			SubjectURI:    "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master",
			OIDCIssuer:    "https://token.actions.githubusercontent.com",
			SourceRepo:    "nearai/compose-manager",
			SourceRepoURL: "https://github.com/nearai/compose-manager",
			SourceCommit:  "0123456789abcdef",
			RunnerEnv:     "github-hosted",
		}}
		assertSingleFactor(t, evalBuildTransparencyLog(&ReportInput{
			Provider:          "nearcloud",
			Raw:               raw,
			SupplyChainPolicy: testNearcloudPolicy(),
			ImageRepos:        []string{"nearaidev/compose-manager"},
			GatewayImageRepos: []string{"nearaidev/dstack-vpc-client"},
			DigestToRepo:      map[string]string{sig[0].Digest: "nearaidev/compose-manager"},
			Sigstore:          sig,
			Rekor:             rekor,
		}), Pass)
	})

	t.Run("rejects_gateway_only_image", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		f := assertSingleFactor(t, evalBuildTransparencyLog(&ReportInput{
			Provider:          "neardirect",
			Raw:               raw,
			SupplyChainPolicy: testNearcloudPolicy(), // has dstack-vpc-client as gateway-only
			ImageRepos:        []string{"nearaidev/dstack-vpc-client"},
		}), Fail)
		if !strings.Contains(strings.ToLower(f.Detail), "model container policy") {
			t.Errorf("detail should mention model policy rejection: %s", f.Detail)
		}
	})

	t.Run("rejects_signer", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		sig := []SigstoreResult{{
			Digest: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			OK:     true, Status: 200,
		}}
		rekor := []RekorProvenance{{
			Digest:        sig[0].Digest,
			HasCert:       true,
			SubjectURI:    "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master",
			OIDCIssuer:    "https://token.actions.githubusercontent.com",
			SourceRepo:    "attacker/router",
			SourceRepoURL: "https://github.com/attacker/router",
		}}
		f := assertSingleFactor(t, evalBuildTransparencyLog(&ReportInput{
			Provider:          "neardirect",
			Raw:               raw,
			SupplyChainPolicy: testNeardirectPolicy(),
			ImageRepos:        []string{"nearaidev/compose-manager"},
			DigestToRepo:      map[string]string{sig[0].Digest: "nearaidev/compose-manager"},
			Sigstore:          sig,
			Rekor:             rekor,
		}), Fail)
		if !strings.Contains(f.Detail, "unexpected source repo") {
			t.Errorf("detail should mention source repo rejection: %s", f.Detail)
		}
	})

	t.Run("fulcio_oidc_identity_mismatch", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		sig := []SigstoreResult{{
			Digest: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			OK:     true, Status: 200,
		}}
		rekor := []RekorProvenance{{
			Digest:        sig[0].Digest,
			HasCert:       true,
			SubjectURI:    "https://github.com/attacker/evil-repo/.github/workflows/evil.yml@refs/heads/main",
			OIDCIssuer:    "https://token.actions.githubusercontent.com",
			SourceRepo:    "nearai/compose-manager",
			SourceRepoURL: "https://github.com/nearai/compose-manager",
			SourceCommit:  "0123456789abcdef",
			RunnerEnv:     "github-hosted",
		}}
		f := assertSingleFactor(t, evalBuildTransparencyLog(&ReportInput{
			Provider:          "neardirect",
			Raw:               raw,
			SupplyChainPolicy: testNeardirectPolicy(),
			ImageRepos:        []string{"nearaidev/compose-manager"},
			DigestToRepo:      map[string]string{sig[0].Digest: "nearaidev/compose-manager"},
			Sigstore:          sig,
			Rekor:             rekor,
		}), Fail)
		if !strings.Contains(f.Detail, "unexpected OIDC identity") {
			t.Errorf("detail should mention OIDC identity mismatch: %s", f.Detail)
		}
	})

	t.Run("key_fingerprint_mismatch", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		composeManagerDigest := "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
		datadogDigest := "dddd1234dddd1234dddd1234dddd1234dddd1234dddd1234dddd1234dddd1234"
		sig := []SigstoreResult{
			{Digest: composeManagerDigest, OK: true, Status: 200},
			{Digest: datadogDigest, OK: true, Status: 200},
		}
		rekor := []RekorProvenance{
			{
				Digest:        composeManagerDigest,
				HasCert:       true,
				SubjectURI:    "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master",
				OIDCIssuer:    "https://token.actions.githubusercontent.com",
				SourceRepo:    "nearai/compose-manager",
				SourceRepoURL: "https://github.com/nearai/compose-manager",
				SourceCommit:  "0123456789abcdef",
				RunnerEnv:     "github-hosted",
			},
			{
				Digest:         datadogDigest,
				HasCert:        false,
				KeyFingerprint: "0000000000000000000000000000000000000000000000000000000000000000",
			},
		}
		f := assertSingleFactor(t, evalBuildTransparencyLog(&ReportInput{
			Provider:          "neardirect",
			Raw:               raw,
			SupplyChainPolicy: testNeardirectPolicy(),
			ImageRepos:        []string{"nearaidev/compose-manager", "datadog/agent"},
			DigestToRepo: map[string]string{
				composeManagerDigest: "nearaidev/compose-manager",
				datadogDigest:        "datadog/agent",
			},
			Sigstore: sig,
			Rekor:    rekor,
		}), Fail)
		if !strings.Contains(f.Detail, "unexpected signing key fingerprint") {
			t.Errorf("detail should mention key fingerprint mismatch: %s", f.Detail)
		}
	})

	t.Run("key_fingerprint_pass", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		composeManagerDigest := "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
		datadogDigest := "dddd1234dddd1234dddd1234dddd1234dddd1234dddd1234dddd1234dddd1234"
		sig := []SigstoreResult{
			{Digest: composeManagerDigest, OK: true, Status: 200},
			{Digest: datadogDigest, OK: true, Status: 200},
		}
		rekor := []RekorProvenance{
			{
				Digest:        composeManagerDigest,
				HasCert:       true,
				SubjectURI:    "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master",
				OIDCIssuer:    "https://token.actions.githubusercontent.com",
				SourceRepo:    "nearai/compose-manager",
				SourceRepoURL: "https://github.com/nearai/compose-manager",
				SourceCommit:  "0123456789abcdef",
				RunnerEnv:     "github-hosted",
			},
			{
				Digest:            datadogDigest,
				HasCert:           false,
				KeyFingerprint:    "25bcab4ec8eede1e3091a14692126798c23986832ae6e5948d6f7eb0a928ab0b",
				SETVerified:       true,
				InclusionVerified: true,
			},
		}
		assertSingleFactor(t, evalBuildTransparencyLog(&ReportInput{
			Provider:          "neardirect",
			Raw:               raw,
			SupplyChainPolicy: testNeardirectPolicy(),
			ImageRepos:        []string{"nearaidev/compose-manager", "datadog/agent"},
			DigestToRepo: map[string]string{
				composeManagerDigest: "nearaidev/compose-manager",
				datadogDigest:        "datadog/agent",
			},
			Sigstore: sig,
			Rekor:    rekor,
		}), Pass)
	})

	t.Run("sigstore_entry_unverified_set_fails", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		composeManagerDigest := "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
		datadogDigest := "dddd1234dddd1234dddd1234dddd1234dddd1234dddd1234dddd1234dddd1234"
		sig := []SigstoreResult{
			{Digest: composeManagerDigest, OK: true, Status: 200},
			{Digest: datadogDigest, OK: true, Status: 200},
		}
		rekor := []RekorProvenance{
			{
				Digest:        composeManagerDigest,
				HasCert:       true,
				SubjectURI:    "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master",
				OIDCIssuer:    "https://token.actions.githubusercontent.com",
				SourceRepo:    "nearai/compose-manager",
				SourceRepoURL: "https://github.com/nearai/compose-manager",
				SourceCommit:  "0123456789abcdef",
				RunnerEnv:     "github-hosted",
			},
			{
				// Sigstore entry without SET/inclusion verification must fail.
				Digest:         datadogDigest,
				HasCert:        false,
				KeyFingerprint: "25bcab4ec8eede1e3091a14692126798c23986832ae6e5948d6f7eb0a928ab0b",
			},
		}
		f := assertSingleFactor(t, evalBuildTransparencyLog(&ReportInput{
			Provider:          "neardirect",
			Raw:               raw,
			SupplyChainPolicy: testNeardirectPolicy(),
			ImageRepos:        []string{"nearaidev/compose-manager", "datadog/agent"},
			DigestToRepo: map[string]string{
				composeManagerDigest: "nearaidev/compose-manager",
				datadogDigest:        "datadog/agent",
			},
			Sigstore: sig,
			Rekor:    rekor,
		}), Fail)
		if !strings.Contains(f.Detail, "SET verification did not succeed") {
			t.Errorf("detail should mention SET verification failure: %s", f.Detail)
		}
	})

	t.Run("no_rekor_no_policy", func(t *testing.T) {
		raw := buildMinimalRaw(nonce, sigKey)
		// Unknown provider → no supply chain policy → no Rekor → Fail
		assertSingleFactor(t, evalBuildTransparencyLog(&ReportInput{
			Provider: "unknown",
			Raw:      raw,
		}), Fail)
	})
}

func TestSupplyChainPolicyNanoGPT(t *testing.T) {
	p := &SupplyChainPolicy{Images: []ImageProvenance{
		{Repo: "alpine", ModelTier: true, Provenance: ComposeBindingOnly},
		{Repo: "dstacktee/dstack-ingress", ModelTier: true, Provenance: ComposeBindingOnly},
		{Repo: "dstacktee/vllm-proxy", ModelTier: true, Provenance: ComposeBindingOnly},
		{Repo: "haproxy", ModelTier: true, Provenance: ComposeBindingOnly},
		{Repo: "lmsysorg/sglang", ModelTier: true, Provenance: ComposeBindingOnly},
		{Repo: "mondaylord/vllm-openai", ModelTier: true, Provenance: ComposeBindingOnly},
		{Repo: "phalanetwork/vllm-proxy", ModelTier: true, Provenance: ComposeBindingOnly},
		{Repo: "python", ModelTier: true, Provenance: ComposeBindingOnly},
		{Repo: "redis", ModelTier: true, Provenance: ComposeBindingOnly},
		{Repo: "vllm/vllm-openai", ModelTier: true, Provenance: ComposeBindingOnly},
	}}

	for _, repo := range []string{
		"alpine", "dstacktee/dstack-ingress", "dstacktee/vllm-proxy",
		"haproxy", "lmsysorg/sglang", "mondaylord/vllm-openai",
		"phalanetwork/vllm-proxy", "python", "redis", "vllm/vllm-openai",
	} {
		if !p.AllowedInModel(repo) {
			t.Errorf("repo %q should be allowed in model tier", repo)
		}
	}
	if p.AllowedInModel("attacker/evil-image") {
		t.Error("unexpected repo should not be allowed")
	}
	if p.HasGatewayImages() {
		t.Error("NanoGPT policy should have no gateway images")
	}
}

// ---------------------------------------------------------------------------
// Tier 3 always-fail factors via BuildReport (quick sanity check)
// ---------------------------------------------------------------------------

func TestBuildReportTier3AlwaysFail(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, Enforced: DefaultEnforced})

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

func TestNvidiaNonceDetail(t *testing.T) {
	tests := []struct {
		name   string
		result *NvidiaVerifyResult
		want   string
	}{
		{
			"EAT format",
			&NvidiaVerifyResult{Format: "EAT", GPUCount: 8},
			"EAT nonce matches submitted nonce (8 GPUs)",
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
			Provider: "venice",
			Model:    "test-model",
			Raw:      raw,
			Nonce:    nonce,
			Enforced: []string{"event_log_integrity"},
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
			Provider: "venice",
			Model:    "test-model",
			Raw:      raw,
			Nonce:    nonce,
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
		Enforced:        DefaultEnforced,
		GatewayTDX:      &TDXVerifyResult{TeeTCBSVN: make([]byte, 16)},
		GatewayNonceHex: gatewayNonce.Hex(),
		GatewayNonce:    gatewayNonce,
	})

	// Base 24 + 10 gateway factors = 34
	// Gateway factors: gateway_nonce_match, gateway_tdx_quote_present,
	// gateway_tdx_quote_structure, gateway_tdx_cert_chain, gateway_tdx_quote_signature,
	// gateway_tdx_debug_disabled, gateway_tdx_reportdata_binding,
	// gateway_compose_binding, gateway_cpu_id_registry, gateway_event_log_integrity
	if len(report.Factors) != 36 {
		t.Errorf("factor count with gateway: got %d, want 36", len(report.Factors))
		for _, f := range report.Factors {
			t.Logf("  [%s] %s: %s", f.Status, f.Name, f.Detail)
		}
	}
}
