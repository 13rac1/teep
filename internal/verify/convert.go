package verify

import (
	"errors"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
)

// outcomeFromE2EEResult converts an attestation.E2EETestResult to a serializable
// E2EEOutcome. Returns nil if r is nil.
func outcomeFromE2EEResult(r *attestation.E2EETestResult) *capture.E2EEOutcome {
	if r == nil {
		return nil
	}
	o := &capture.E2EEOutcome{
		Attempted: r.Attempted,
		NoAPIKey:  r.NoAPIKey,
		APIKeyEnv: r.APIKeyEnv,
		Detail:    r.Detail,
		KeyType:   r.KeyType,
	}
	if r.Err != nil {
		o.Failed = true
		o.ErrMsg = r.Err.Error()
	}
	o.NoReceiptCheck = r.NoReceiptCheck
	if r.Receipt != nil {
		o.Receipt = &capture.ReceiptOutcome{Detail: r.Receipt.Detail, Unknown: r.Receipt.Unknown}
		if r.Receipt.Err != nil {
			o.Receipt.Failed = true
			o.Receipt.ErrMsg = r.Receipt.Err.Error()
		}
	}
	return o
}

// e2eeResultFromOutcome converts a captured E2EEOutcome back to an
// attestation.E2EETestResult. Returns nil if o is nil.
func e2eeResultFromOutcome(o *capture.E2EEOutcome) *attestation.E2EETestResult {
	if o == nil {
		return nil
	}
	r := &attestation.E2EETestResult{
		Attempted: o.Attempted,
		NoAPIKey:  o.NoAPIKey,
		APIKeyEnv: o.APIKeyEnv,
		Detail:    o.Detail,
		KeyType:   o.KeyType,
	}
	if o.Failed {
		// Err is reconstructed from the serialized message; type information is
		// lost across the capture boundary. Callers only check Err != nil.
		msg := o.ErrMsg
		if msg == "" {
			msg = "(error message lost across capture boundary)"
		}
		r.Err = errors.New(msg)
	}
	r.NoReceiptCheck = o.NoReceiptCheck
	switch {
	case o.Receipt != nil && o.Receipt.Failed:
		// A recorded failure stays a failure: the replay must not unblock
		// what the live run blocked.
		msg := o.Receipt.ErrMsg
		if msg == "" {
			msg = "(error message lost across capture boundary)"
		}
		r.Receipt = &attestation.ACIReceiptResult{Err: errors.New(msg), Unknown: o.Receipt.Unknown}
	case o.Receipt != nil:
		// A recorded pass is not a check: the replay does not check the
		// receipt again, so the factor does not pass on it.
		r.NoReceiptCheck = "recorded verdict: " + o.Receipt.Detail + "; the replay does not check the receipt again"
	}
	return r
}
