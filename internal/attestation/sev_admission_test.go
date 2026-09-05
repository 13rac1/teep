package attestation

import (
	"slices"
	"sync"
	"testing"

	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	sevtest "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify/testdata"
	"github.com/google/go-sev-guest/verify/trust"
)

func TestSEVOnlineRequiresAuthenticatedEvidence(t *testing.T) {
	report, err := sevabi.ReportToProto(testdata.AttestationBytes)
	if err != nil {
		t.Fatal(err)
	}
	certificateURL := kds.VCEKCertURL("Milan", report.GetChipId(), kds.TCBVersion(report.GetReportedTcb()))
	for _, mode := range []string{"valid", "report_signature", "certificate_signature", "malformed_report"} {
		t.Run(mode, func(t *testing.T) {
			raw, certificate := slices.Clone(testdata.AttestationBytes), slices.Clone(testdata.VcekBytes)
			switch mode {
			case "report_signature":
				raw[0x2a0] ^= 1 // First byte of the ABI report signature.
			case "certificate_signature":
				certificate[len(certificate)-1] ^= 1
			case "malformed_report":
				raw = raw[:10]
			}
			// Only retrieval is mocked. Signed collateral and the CPU report pass
			// through the production online verifier with embedded AMD roots.
			getter := sevtest.SimpleGetter(map[string][]byte{
				"https://kdsintf.amd.com/vcek/v1/Milan/cert_chain": trust.AskArkMilanVcekBytes,
				certificateURL: certificate,
			})
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					result := VerifySEVReportOnline(t.Context(), raw, getter)
					if mode != "valid" {
						if result.OnlineVerified || (result.ParseErr == nil && result.CertChainErr == nil && result.SignatureErr == nil) {
							t.Error("failed verification accepted evidence")
						}
						return
					}
					if !result.OnlineVerified || result.CertChainErr != nil || result.SignatureErr != nil {
						t.Errorf("verified=%v chain=%v signature=%v", result.OnlineVerified, result.CertChainErr, result.SignatureErr)
					}
				})
			}
			wg.Wait()
		})
	}
}
