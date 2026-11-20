package attestation

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// In ACI mode a factor that the audit of every pinned session checked passes
// with aci_session_verified, and is enforced by the Phala Cloud policy. A
// factor that the audit does not check keeps its own result, and with no
// pinned session every factor keeps it.
func TestACISessionCoverage(t *testing.T) {
	nonce := NewNonce()
	pinned := []ACIPinnedSession{{ID: "s1"}}
	build := func(sessions *ACISessionResult, quote string) *VerificationReport {
		raw := buildMinimalRaw(nonce, validSigningKey(t))
		raw.ACICanonicalReport = true
		raw.IntelQuote = quote
		return BuildReport(&ReportInput{Provider: "phalacloud", Model: "m", Raw: raw, Nonce: nonce,
			AllowFail: PhalaCloudACIDefaultAllowFail, ACISessions: sessions})
	}

	covered := build(&ACISessionResult{Pinned: pinned, Covered: []string{FactorTEECertChain, FactorComposeBinding}}, "")
	for _, name := range []string{FactorTEECertChain, FactorComposeBinding} {
		f := findFactor(t, covered, name)
		if f.Status != Pass || !strings.Contains(f.Detail, "covered by aci_session_verified") {
			t.Errorf("%s: %+v, want a pass covered by aci_session_verified", name, f)
		}
	}
	if f := findFactor(t, covered, FactorTEECertChain); !f.Enforced {
		t.Errorf("tee_cert_chain: %+v, want enforced for Phala Cloud", f)
	}
	for _, name := range []string{FactorTEEQuoteSignature, FactorTEEHardwareConfig, FactorNvidiaClientNonce, FactorCPUGPUChain} {
		if f := findFactor(t, covered, name); f.Status == Pass {
			t.Errorf("%s is not covered and passed: %+v", name, f)
		}
	}
	if f := findFactor(t, covered, FactorTEEQuoteSignature); f.Status != Fail || !f.Enforced || !covered.Blocked() {
		t.Errorf("tee_quote_signature not covered: %+v, want an enforced failure that blocks", f)
	}

	all := slices.Clone(phalaCloudSessionFactors)
	for name, sessions := range map[string]*ACISessionResult{
		"no pinned session": {Covered: all},
		"sessions failed":   {Err: errors.New("fetch"), Pinned: pinned, Covered: all},
	} {
		r := build(sessions, "")
		if f := findFactor(t, r, FactorTEECertChain); f.Status != Fail {
			t.Errorf("%s: tee_cert_chain %+v, want a failure", name, f)
		}
	}

	direct := build(&ACISessionResult{Pinned: pinned, Covered: all}, "dGVzdA==")
	if f := findFactor(t, direct, FactorTEECertChain); strings.Contains(f.Detail, "aci_session_verified") {
		t.Errorf("a response with its own quote is not in ACI mode: %+v", f)
	}

	full := build(&ACISessionResult{Pinned: pinned, Covered: all}, "")
	for _, name := range all {
		if f := findFactor(t, full, name); f.Status != Pass || !f.Enforced {
			t.Errorf("%s: %+v, want an enforced pass", name, f)
		}
	}
}
