package verify

import (
	"errors"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
)

func TestOutcomeFromE2EEResult_Nil(t *testing.T) {
	if got := outcomeFromE2EEResult(nil); got != nil {
		t.Errorf("outcomeFromE2EEResult(nil) = %v, want nil", got)
	}
}

func TestE2EEResultFromOutcome_Nil(t *testing.T) {
	if got := e2eeResultFromOutcome(nil); got != nil {
		t.Errorf("e2eeResultFromOutcome(nil) = %v, want nil", got)
	}
}

func TestOutcomeFromE2EEResult_Success(t *testing.T) {
	r := &attestation.E2EETestResult{
		Attempted: true,
		APIKeyEnv: "VENICE_API_KEY",
		Detail:    "2 encrypted chunks decrypted",
	}
	o := outcomeFromE2EEResult(r)
	if !o.Attempted {
		t.Error("Attempted should be true")
	}
	if o.Failed {
		t.Error("Failed should be false")
	}
	if o.ErrMsg != "" {
		t.Errorf("ErrMsg = %q, want empty", o.ErrMsg)
	}
	if o.APIKeyEnv != "VENICE_API_KEY" {
		t.Errorf("APIKeyEnv = %q, want VENICE_API_KEY", o.APIKeyEnv)
	}
	if o.Detail != "2 encrypted chunks decrypted" {
		t.Errorf("Detail = %q", o.Detail)
	}
}

func TestOutcomeFromE2EEResult_WithError(t *testing.T) {
	r := &attestation.E2EETestResult{
		Attempted: true,
		Err:       errors.New("decryption failed"),
		Detail:    "failed after 1 chunk",
	}
	o := outcomeFromE2EEResult(r)
	if !o.Failed {
		t.Error("Failed should be true when Err is set")
	}
	if o.ErrMsg != "decryption failed" {
		t.Errorf("ErrMsg = %q, want 'decryption failed'", o.ErrMsg)
	}
}

func TestE2EEResultFromOutcome_Success(t *testing.T) {
	o := &capture.E2EEOutcome{
		Attempted: true,
		APIKeyEnv: "NEARCLOUD_API_KEY",
		Detail:    "ok",
	}
	r := e2eeResultFromOutcome(o)
	if !r.Attempted {
		t.Error("Attempted should be true")
	}
	if r.Err != nil {
		t.Errorf("Err should be nil, got %v", r.Err)
	}
	if r.APIKeyEnv != "NEARCLOUD_API_KEY" {
		t.Errorf("APIKeyEnv = %q", r.APIKeyEnv)
	}
}

func TestE2EEResultFromOutcome_WithError(t *testing.T) {
	o := &capture.E2EEOutcome{
		Attempted: true,
		Failed:    true,
		ErrMsg:    "timeout",
	}
	r := e2eeResultFromOutcome(o)
	if r.Err == nil {
		t.Fatal("Err should be non-nil when Failed is true")
	}
	if r.Err.Error() != "timeout" {
		t.Errorf("Err = %q, want 'timeout'", r.Err)
	}
}

func TestE2EEResultFromOutcome_FailedEmptyMsg(t *testing.T) {
	o := &capture.E2EEOutcome{
		Attempted: true,
		Failed:    true,
		ErrMsg:    "",
	}
	r := e2eeResultFromOutcome(o)
	if r.Err == nil {
		t.Fatal("Err should be non-nil when Failed is true")
	}
	if r.Err.Error() == "" {
		t.Error("Err message should not be empty for failed outcome with empty ErrMsg")
	}
}

func TestOutcomeE2EERoundTrip(t *testing.T) {
	original := &attestation.E2EETestResult{
		Attempted: true,
		NoAPIKey:  true,
		APIKeyEnv: "CHUTES_API_KEY",
		Err:       errors.New("connection refused"),
		Detail:    "test detail",
	}
	outcome := outcomeFromE2EEResult(original)
	restored := e2eeResultFromOutcome(outcome)

	if restored.Attempted != original.Attempted {
		t.Errorf("Attempted mismatch")
	}
	if restored.NoAPIKey != original.NoAPIKey {
		t.Errorf("NoAPIKey mismatch")
	}
	if restored.APIKeyEnv != original.APIKeyEnv {
		t.Errorf("APIKeyEnv mismatch")
	}
	if restored.Detail != original.Detail {
		t.Errorf("Detail mismatch")
	}
	if restored.Err == nil {
		t.Fatal("Err should survive round-trip")
	}
	if restored.Err.Error() != original.Err.Error() {
		t.Errorf("Err message = %q, want %q", restored.Err.Error(), original.Err.Error())
	}
}

// The receipt result of a probe survives the capture: a failed receipt still
// blocks in a replay, a recorded pass becomes a deferred Skip that quotes it
// (the replay checks nothing), and the reason why a probe did not check the
// receipt is kept.
func TestOutcomeReceiptRoundTrip(t *testing.T) {
	failed := e2eeResultFromOutcome(outcomeFromE2EEResult(&attestation.E2EETestResult{
		Attempted: true, Receipt: &attestation.ACIReceiptResult{Err: errors.New("signature"), Unknown: []string{"x"}},
	}))
	if failed.Err != nil || failed.Receipt == nil || failed.Receipt.Err == nil || failed.Receipt.Err.Error() != "signature" || len(failed.Receipt.Unknown) != 1 {
		t.Fatalf("failed receipt restored as %+v / %+v", failed, failed.Receipt)
	}
	verified := e2eeResultFromOutcome(outcomeFromE2EEResult(&attestation.E2EETestResult{
		Attempted: true, Receipt: &attestation.ACIReceiptResult{Detail: "receipt verified"},
	}))
	// A recorded pass is not a check: it comes back as a reason, so the
	// factor is a deferred Skip and not a Pass.
	if verified.Receipt != nil || verified.NoReceiptCheck != "recorded verdict: receipt verified; the replay does not check the receipt again" {
		t.Fatalf("verified receipt restored as %+v / %q", verified.Receipt, verified.NoReceiptCheck)
	}
	passed := &attestation.VerificationReport{Factors: []attestation.FactorResult{
		{Name: attestation.FactorACIReceiptVerified, Status: attestation.Skip, Deferred: true, Enforced: true},
	}}
	passed.MarkACIReceipt(verified, "")
	if f := passed.Factors[0]; f.Status != attestation.Skip || !f.Deferred {
		t.Errorf("a replayed pass gives %+v, want a deferred Skip", f)
	}
	offline := e2eeResultFromOutcome(outcomeFromE2EEResult(&attestation.E2EETestResult{Attempted: true, NoReceiptCheck: "not checked"}))
	if offline.Receipt != nil || offline.NoReceiptCheck != "not checked" {
		t.Fatalf("offline probe restored as %+v", offline)
	}

	report := &attestation.VerificationReport{Factors: []attestation.FactorResult{
		{Name: attestation.FactorACIReceiptVerified, Status: attestation.Skip, Deferred: true, Enforced: true},
	}}
	report.MarkACIReceipt(failed, "")
	if !report.Blocked() {
		t.Error("a replayed failed receipt does not block")
	}
}
