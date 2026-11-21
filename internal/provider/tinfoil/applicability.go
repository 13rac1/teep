package tinfoil

import "github.com/13rac1/teep/internal/attestation"

// InapplicableFactors returns the set of factors that don't apply to Tinfoil.
// Tinfoil uses Sigstore DSSE instead of compose/Rekor.
//
// The NVIDIA factors all apply: an enclave with GPUs sends the client nonce as
// each GPU's SPDM requester nonce, and teep submits the same evidence to NRAS.
// SEE: readDeviceEvidence in attestation.go.
func InapplicableFactors() attestation.InapplicableFactors {
	return attestation.InapplicableFactors{
		// Tinfoil names the software in a Sigstore-signed release, not a
		// compose: the release's code measurements are RTMR1 and RTMR2 (TDX)
		// or the launch measurement (SEV-SNP), and RTMR3 is zero.
		"compose_binding":       "Tinfoil has no compose; covered by sigstore_code_verified and tee_measurement (the quote matches a Sigstore-signed release)",
		"sigstore_verification": "Tinfoil publishes no per-image cosign signatures; the release, which pins the image digest, is checked by sigstore_code_verified",
		"event_log_integrity":   "Tinfoil has no runtime event log (RTMR3 is zero, checked by tee_hardware_config); covered by sigstore_code_verified and tee_measurement",
	}
}
