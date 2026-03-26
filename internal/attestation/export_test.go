package attestation

import "testing"

// Bridges for package attestation_test (external test package).

var EvalSigstoreVerificationForTest = evalSigstoreVerification
var EvalBuildTransparencyLogForTest = evalBuildTransparencyLog

func BuildMinimalRawForTest(nonce Nonce, signingKey string) *RawAttestation {
	return buildMinimalRaw(nonce, signingKey)
}

func ValidSigningKeyForTest(t *testing.T) string {
	t.Helper()
	return validSigningKey(t)
}

func AssertSingleFactorForTest(t *testing.T, results []FactorResult, want Status) FactorResult {
	t.Helper()
	return assertSingleFactor(t, results, want)
}
