package attestation

import "slices"

// TLSInferenceResult describes the standalone chat probe without E2EE.
// Successful TLS transport does not prove encrypted-field response authentication.
type TLSInferenceResult struct {
	Attempted bool   `json:"attempted"`
	Failed    bool   `json:"failed"`
	Detail    string `json:"detail"`
}

// MarkTLSInference records the standalone TLS-only probe independently of E2EE.
// Attempted or failed probes are enforced and are not allow_fail factors.
// An unattempted, nonfailed probe remains visible as an unenforced Skip.
func (r *VerificationReport) MarkTLSInference(result *TLSInferenceResult) {
	if result == nil {
		return
	}
	status := Skip
	if result.Failed {
		status = Fail
	} else if result.Attempted {
		status = Pass
	}
	value := FactorResult{Tier: TierBinding, Name: "tls_inference", Status: status, Detail: result.Detail, Enforced: status != Skip}
	for i := range r.Factors {
		if r.Factors[i].Name == value.Name {
			r.Factors[i] = value
			r.recomputeCounters()
			return
		}
	}
	position := len(r.Factors)
	for i := range r.Factors {
		if r.Factors[i].Tier == TierBinding {
			position = i + 1
		}
	}
	r.Factors = slices.Insert(r.Factors, position, value)
	r.recomputeCounters()
}
