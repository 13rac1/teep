// Package multi provides a format-dispatching ReportDataVerifier for gateway
// providers that route to multiple backends (nanogpt, phalacloud/RedPill).
//
// The Verifier inspects RawAttestation.BackendFormat to select the correct
// sub-verifier at verification time, rather than at provider construction time.
package multi

import (
	"fmt"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
)

// Verifier dispatches ReportData verification to format-specific sub-verifiers.
// Gateway providers wire this with one sub-verifier per supported BackendFormat.
type Verifier struct {
	Verifiers map[attestation.BackendFormat]provider.ReportDataVerifier
}

// VerifyReportData dispatches to the sub-verifier matching raw.BackendFormat.
// Returns an error if no verifier is registered for the format.
func (v Verifier) VerifyReportData(reportData [64]byte, raw *attestation.RawAttestation, nonce attestation.Nonce) (string, error) {
	sub, ok := v.Verifiers[raw.BackendFormat]
	if !ok {
		return "", fmt.Errorf("no REPORTDATA verifier for backend format %q", raw.BackendFormat)
	}
	return sub.VerifyReportData(reportData, raw, nonce)
}
