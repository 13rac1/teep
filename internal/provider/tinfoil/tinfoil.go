// Package tinfoil implements the Attester and ReportDataVerifier interfaces
// for the Tinfoil V3 attestation protocol.
//
// Tinfoil attestation uses a single endpoint:
//
//	GET {base_url}/.well-known/tinfoil-attestation?nonce={hex}
//
// The response is a V3 attestation document containing CPU quotes (TDX or
// SEV-SNP), GPU evidence (required), topology-conditional NVSwitch evidence,
// a TLS certificate, and an ECDSA envelope signature.
package tinfoil

import (
	"net/http"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
)

// FormatURI is the V3 attestation document format identifier.
const FormatURI = "https://tinfoil.sh/predicate/attestation/v3"

// CPU platform constants used in the V3 attestation document's cpu.platform field.
const (
	PlatformTDX    = "tdx"
	PlatformSEVSNP = "sev-snp"
)

// TEE hardware identifiers stored in RawAttestation.TEEHardware.
const (
	HardwareIntelTDX = "intel-tdx"
	HardwareAMDSEV   = "amd-sev-snp"
)

// Known GPU architectures for NVSwitch normalization.
const (
	ArchHopper    = "HOPPER"
	ArchBlackwell = "BLACKWELL"
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
func (p *Preparer) PrepareRequest(req *http.Request, _ http.Header, _ *e2ee.ChutesE2EE, _ bool, _ string) error {
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
