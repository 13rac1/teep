package attestation

import (
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/tlsct"
)

func TestTLSBindingRequiresDerivedIdentity(t *testing.T) {
	for _, name := range []string{"nearcloud", "neardirect", "tinfoil_v3_cloud", "tinfoil_v3_direct"} {
		t.Run(name, func(t *testing.T) {
			fp := strings.Repeat("ab", 32)
			raw := &RawAttestation{TLSFingerprint: fp, GatewayTLSFingerprint: fp, TinfoilTLSKeyFP: fp}
			in := &ReportInput{Provider: name, Raw: raw, ProviderUsesTLSBinding: true}
			assertSingleFactor(t, evalTLSKeyBinding(in), Fail)
			raw.TransportTLSFingerprint = fp
			assertSingleFactor(t, evalTLSKeyBinding(in), Fail)
			raw.TransportTLSAuthority = "example.com"
			assertSingleFactor(t, evalTLSKeyBinding(in), Pass)
			// Native fields do not determine the client-facing transport scope.
			raw.TLSFingerprint = strings.Repeat("cd", 32)
			assertSingleFactor(t, evalTLSKeyBinding(in), Pass)
			report := BuildReport(in)
			if report.TLSAuthority != raw.TransportTLSAuthority || !tlsct.SPKIFingerprintsEqual(report.TLSKeyFP, fp) {
				t.Fatal("report did not use the derived transport identity")
			}
			raw.TransportTLSFingerprint = "bad"
			assertSingleFactor(t, evalTLSKeyBinding(in), Fail)
		})
	}
}
