package attestation

import "testing"

func TestMarkTLSInferenceOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result *TLSInferenceResult
		status Status
	}{
		{name: "absent"},
		{name: "skipped", result: &TLSInferenceResult{Detail: "probe skipped"}, status: Skip},
		{name: "success", result: &TLSInferenceResult{Attempted: true, Detail: "probe succeeded"}, status: Pass},
		{name: "failure", result: &TLSInferenceResult{Attempted: true, Failed: true, Detail: "probe failed"}, status: Fail},
		{name: "failure before attempt", result: &TLSInferenceResult{Failed: true, Detail: "preparation failed"}, status: Fail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e2ee := FactorResult{Tier: TierBinding, Name: FactorE2EEUsable, Status: Skip}
			report := &VerificationReport{Factors: []FactorResult{e2ee}, Skipped: 1}
			// Updating an outcome must replace it, without counting it twice.
			report.MarkTLSInference(tc.result)
			report.MarkTLSInference(tc.result)
			if report.Factors[0] != e2ee {
				t.Fatal("TLS-only outcome changed E2EE status")
			}
			if tc.result == nil {
				if len(report.Factors) != 1 || report.Skipped != 1 || report.Blocked() {
					t.Fatal("absent outcome changed the report")
				}
				return
			}
			if len(report.Factors) != 2 {
				t.Fatal("missing or duplicated TLS-only outcome")
			}
			factor := report.Factors[1]
			if factor.Name != "tls_inference" || factor.Status != tc.status || factor.Detail != tc.result.Detail || factor.Enforced != (tc.status != Skip) {
				t.Fatalf("incorrect TLS-only outcome: %+v", factor)
			}
			passed, failed, skipped := 0, 0, 1
			switch tc.status {
			case Pass:
				passed++
			case Fail:
				failed++
			case Skip:
				skipped++
			case NotApplicable:
				t.Fatal("TLS-only probe must have an explicit outcome")
			}
			if report.Passed != passed || report.Failed != failed || report.Skipped != skipped || report.EnforcedFailed != failed || report.AllowedFailed != 0 {
				t.Fatal("incorrect report counters")
			}
			if report.Blocked() != (tc.status == Fail) {
				t.Fatal("TLS-only failure enforcement changed")
			}
		})
	}
}
