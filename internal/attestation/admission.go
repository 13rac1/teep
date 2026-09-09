package attestation

import (
	"errors"
	"time"
)

// AdmissionTime retains verified NRAS time claims only until initial publication.
// It must not be retained in cached authorization or used as a request deadline.
// Its zero value applies when no NRAS JWT was successfully verified.
type AdmissionTime struct {
	expires   time.Time
	notBefore time.Time
}

// NVIDIAAdmission returns time eligibility only from a successfully verified JWT.
func NVIDIAAdmission(result *NvidiaVerifyResult) AdmissionTime {
	if result == nil || result.SignatureErr != nil || result.ClaimsErr != nil || !result.OverallResult {
		return AdmissionTime{}
	}
	return result.admission
}

// Check rejects evidence that became ineligible while other admission checks ran.
func (a AdmissionTime) Check(now time.Time) error {
	if !a.expires.IsZero() && !now.Before(a.expires) {
		return errors.New("verified NRAS JWT expired before authorization publication")
	}
	if !a.notBefore.IsZero() && now.Before(a.notBefore) {
		return errors.New("verified NRAS JWT is not yet valid at authorization publication")
	}
	return nil
}
