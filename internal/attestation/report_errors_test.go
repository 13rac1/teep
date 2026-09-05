package attestation

import (
	"errors"
	"fmt"
	"testing"
)

func TestVerificationErrorsPreserveNetworkCauses(t *testing.T) {
	cause := errors.New("temporary resource exhaustion")
	wrapped := fmt.Errorf("fetch evidence: %w", cause)
	for name, input := range map[string]*ReportInput{
		"backend PCS": {TDX: &TDXVerifyResult{CollateralErr: wrapped}},
		"gateway PCS": {GatewayTDX: &TDXVerifyResult{CollateralErr: wrapped}},
		"backend KDS": {SEV: &SEVVerifyResult{CertChainErr: wrapped}},
		"gateway KDS": {GatewaySEV: &SEVVerifyResult{CertChainErr: wrapped}},
		"NRAS":        {NvidiaNRAS: &NvidiaVerifyResult{SignatureErr: wrapped}},
		"PoC":         {PoC: &PoCResult{Err: wrapped}},
		"gateway PoC": {GatewayPoC: &PoCResult{Err: wrapped}},
		"Sigstore":    {Sigstore: []SigstoreResult{{Err: wrapped}}},
		"Rekor":       {Rekor: []RekorProvenance{{Err: wrapped}}},
		"Tinfoil":     {TinfoilSC: &TinfoilSupplyChainResult{Components: []TinfoilComponentResult{{SigstoreErr: wrapped}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if !errors.Is(input.VerificationErrors(), cause) {
				t.Fatal("verification lost the underlying error")
			}
		})
	}
	if err := (&ReportInput{}).VerificationErrors(); err != nil {
		t.Fatalf("empty input returned an error: %v", err)
	}
}
