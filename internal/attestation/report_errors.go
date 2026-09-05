package attestation

import "errors"

// VerificationErrors preserves the causes of verification failures for callers
// that must distinguish temporary resource exhaustion from invalid evidence.
// It does not evaluate enforcement policy; BuildReport owns that decision.
func (in *ReportInput) VerificationErrors() error {
	var errs []error
	for _, result := range []*TDXVerifyResult{in.TDX, in.GatewayTDX} {
		if result != nil {
			errs = append(errs, result.ParseErr, result.CertChainErr, result.SignatureErr, result.CollateralErr, result.ReportDataBindingErr)
		}
	}
	for _, result := range []*SEVVerifyResult{in.SEV, in.GatewaySEV} {
		if result != nil {
			errs = append(errs, result.ParseErr, result.CertChainErr, result.SignatureErr, result.PolicyErr, result.TCBErr, result.ReportDataBindingErr)
		}
	}
	for _, result := range []*NvidiaVerifyResult{in.Nvidia, in.NvidiaNRAS} {
		if result != nil {
			errs = append(errs, result.SignatureErr, result.ClaimsErr)
		}
	}
	for _, result := range []*PoCResult{in.PoC, in.GatewayPoC} {
		if result != nil {
			errs = append(errs, result.Err)
		}
	}
	for _, result := range []*ComposeBindingResult{in.Compose, in.GatewayCompose} {
		if result != nil {
			errs = append(errs, result.Err)
		}
	}
	for _, result := range in.Sigstore {
		errs = append(errs, result.Err)
	}
	for i := range in.Rekor {
		result := &in.Rekor[i]
		errs = append(errs, result.Err, result.SignatureErr, result.SETErr, result.InclusionErr)
	}
	if result := in.TinfoilSC; result != nil {
		errs = append(errs, result.SigstoreErr, result.CodeMatchErr, result.HWMatchErr, result.TDXPolicyErr)
		for _, component := range result.Components {
			errs = append(errs, component.SigstoreErr)
		}
	}
	if in.E2EETest != nil {
		errs = append(errs, in.E2EETest.Err)
	}
	return errors.Join(errs...)
}
