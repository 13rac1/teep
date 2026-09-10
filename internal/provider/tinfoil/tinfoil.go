// Package tinfoil implements the Attester and ReportDataVerifier interfaces
// for the Tinfoil v3 attestation protocol.
//
// Tinfoil attestation uses a single endpoint:
//
//	GET {base_url}/.well-known/tinfoil-attestation?nonce={hex}
//
// The response is a v3 attestation document: a challenge, a CPU quote (TDX or
// SEV-SNP), two endorsed sections, and collateral.
//
// The document carries no signature. Its whole authentication is the CPU
// quote, whose REPORT_DATA commits to the client nonce and to the hashes of
// the two endorsed sections. One section holds the TLS key fingerprint and the
// HPKE public key; the other holds device evidence. Nothing in the document is
// trusted until the hardware signature over that REPORT_DATA verifies.
//
// SEE: attestation.go for the document shape and the format registry, and
// verify.go for the REPORT_DATA derivation.
package tinfoil

import (
	"github.com/13rac1/teep/internal/provider"
	"net/http"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
)

// TEE hardware identifiers stored in RawAttestation.TEEHardware.
const (
	HardwareIntelTDX = "intel-tdx"
	HardwareAMDSEV   = "amd-sev-snp"
)

// Preparer injects the Tinfoil Authorization header into outgoing requests.
type Preparer struct {
	apiKey string
}

// NewPreparer returns a Tinfoil Preparer configured with the given API key.
func NewPreparer(apiKey string) *Preparer {
	return &Preparer{apiKey: apiKey}
}

// PrepareRequest sets the Authorization header on req.
func (p *Preparer) PrepareRequest(req *http.Request, _ http.Header, _ *e2ee.ChutesE2EE, _ bool, _ string, _ provider.PreparationData) error {
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	return nil
}

// DefaultMeasurementPolicy returns the Go-coded default TDX measurement
// allowlists for Tinfoil. MR_SEAM values are the Intel TDX module
// measurements shared across all TDX providers.
func DefaultMeasurementPolicy() attestation.MeasurementPolicy {
	base := attestation.DstackBaseMeasurementPolicy()
	return attestation.MeasurementPolicy{
		MRSeamAllow: base.MRSeamAllow,
	}
}
