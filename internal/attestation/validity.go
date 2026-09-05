package attestation

import (
	"errors"
	"time"
)

// EvidenceValidity contains an optional validity bound from successful
// cryptographic verification. Parsed diagnostic dates cannot construct it.
type EvidenceValidity struct {
	expiresAt time.Time
	present   bool
}

// Expiry returns the authenticated bound, or false when none was supplied.
func (v EvidenceValidity) Expiry() (time.Time, bool) { return v.expiresAt, v.present }

func verifiedEvidenceValidity(bound time.Time) (EvidenceValidity, error) {
	if bound.IsZero() {
		return EvidenceValidity{}, errors.New("authenticated evidence has a zero validity bound")
	}
	return EvidenceValidity{expiresAt: bound, present: true}, nil
}

func minimumEvidenceValidity(a, b EvidenceValidity) EvidenceValidity {
	if b.present && (!a.present || b.expiresAt.Before(a.expiresAt)) {
		return b
	}
	return a
}

func reportEvidenceValidity(in *ReportInput, factors []FactorResult) EvidenceValidity {
	passed := func(name string) bool {
		for _, factor := range factors {
			if factor.Name == name {
				return factor.Status == Pass
			}
		}
		return false
	}
	var bound EvidenceValidity
	if in.TDX != nil && in.TDX.CollateralErr == nil && (passed(FactorTEETCBCurrent) || passed(FactorTEETCBNotRevoked)) {
		bound = minimumEvidenceValidity(bound, in.TDX.Validity)
	}
	if in.GatewayTDX != nil && in.GatewayTDX.CollateralErr == nil && passed(FactorGWCertChain) && passed(FactorGWQuoteSignature) {
		bound = minimumEvidenceValidity(bound, in.GatewayTDX.Validity)
	}
	if in.SEV != nil && in.SEV.OnlineVerified && in.SEV.CertChainErr == nil && in.SEV.SignatureErr == nil && passed(FactorTEECertChain) && passed(FactorTEEQuoteSignature) {
		bound = minimumEvidenceValidity(bound, in.SEV.Validity)
	}
	if in.GatewaySEV != nil && in.GatewaySEV.OnlineVerified && in.GatewaySEV.CertChainErr == nil && in.GatewaySEV.SignatureErr == nil && passed(FactorGWCertChain) && passed(FactorGWQuoteSignature) {
		bound = minimumEvidenceValidity(bound, in.GatewaySEV.Validity)
	}
	if in.Nvidia != nil && in.Nvidia.SignatureErr == nil && in.Nvidia.ClaimsErr == nil && passed(FactorNvidiaSignature) && passed(FactorNvidiaClaims) {
		bound = minimumEvidenceValidity(bound, in.Nvidia.Validity)
	}
	if in.NvidiaNRAS != nil && in.NvidiaNRAS.SignatureErr == nil && in.NvidiaNRAS.ClaimsErr == nil && passed(FactorNvidiaNRAS) {
		bound = minimumEvidenceValidity(bound, in.NvidiaNRAS.Validity)
	}
	// Proof of Cloud does not independently verify its JWT signature. Historical
	// Sigstore signer certificates, inference TLS certificates, discovery, and
	// cache age do not contribute authorization expiration.
	return bound
}
