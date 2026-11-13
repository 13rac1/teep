package attestation

import (
	"errors"
	"slices"
	"testing"
)

// aci_receipt_verified is enforced for Phala Cloud. Without a probe receipt
// it is a deferred Skip, which the "Promote Skip → Fail" rule leaves a Skip,
// as for e2ee_usable: teep serve (no probe) and teep verify without an API
// key or with a probe that failed earlier are not blocked by it. A receipt
// that fails the check fails it and blocks.
func TestEvalACIReceiptVerified(t *testing.T) {
	if slices.Contains(PhalaCloudACIDefaultAllowFail, FactorACIReceiptVerified) {
		t.Fatal("aci_receipt_verified must be enforced for Phala Cloud")
	}
	canonical := &RawAttestation{ACICanonicalReport: true}
	for _, tc := range []struct {
		name     string
		raw      *RawAttestation
		test     *E2EETestResult
		status   Status
		deferred bool
	}{
		{"not canonical", &RawAttestation{}, nil, NotApplicable, false},
		{"serve: no probe", canonical, nil, Skip, true},
		{"verify: no API key", canonical, &E2EETestResult{NoAPIKey: true}, Skip, true},
		{"verify: probe failed before the receipt", canonical, &E2EETestResult{Attempted: true, Err: errors.New("timeout")}, Skip, true},
		{"verify: receipt failed", canonical, &E2EETestResult{Attempted: true, Receipt: &ACIReceiptResult{Err: errors.New("signature")}}, Fail, false},
		{"verify: receipt verified", canonical, &E2EETestResult{Attempted: true, Receipt: &ACIReceiptResult{Detail: "receipt verified"}}, Pass, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := evalACIReceiptVerified(&ReportInput{Raw: tc.raw, E2EETest: tc.test})
			if len(got) != 1 || got[0].Status != tc.status || got[0].Deferred != tc.deferred {
				t.Fatalf("factor = %+v, want status %v deferred %v", got, tc.status, tc.deferred)
			}
		})
	}
}

// Through BuildReport with the Phala Cloud policy: the deferred Skip stays a
// Skip and does not block; a failed receipt is an enforced failure.
func TestACIReceiptVerifiedEnforcement(t *testing.T) {
	nonce := NewNonce()
	build := func(test *E2EETestResult) FactorResult {
		raw := buildMinimalRaw(nonce, validSigningKey(t))
		raw.ACICanonicalReport = true
		report := BuildReport(&ReportInput{Provider: "phalacloud", Model: "m", Raw: raw, Nonce: nonce, AllowFail: PhalaCloudACIDefaultAllowFail, E2EETest: test})
		return findFactor(t, report, FactorACIReceiptVerified)
	}
	for name, test := range map[string]*E2EETestResult{"serve": nil, "verify without API key": {NoAPIKey: true}} {
		f := build(test)
		if f.Status != Skip || !f.Enforced {
			t.Errorf("%s: %+v, want an enforced Skip that the promotion leaves", name, f)
		}
	}
	f := build(&E2EETestResult{Attempted: true, Receipt: &ACIReceiptResult{Err: errors.New("forged")}})
	if f.Status != Fail || !f.Enforced {
		t.Errorf("failed receipt: %+v, want an enforced failure", f)
	}
}
