package venice

import "github.com/13rac1/teep/internal/attestation"

// ACIInapplicableFactors returns the set of factors that don't apply to the
// Venice ACI/1 attestation format. ACI/1 uses source_provenance (repo_url +
// repo_commit) instead of docker-compose manifests, so compose-based supply
// chain verification is structurally impossible.
func ACIInapplicableFactors() attestation.InapplicableFactors {
	f := attestation.DefaultInapplicableFactors()
	f["compose_binding"] = "ACI/1 uses source_provenance, not docker-compose"
	f["build_transparency_log"] = "ACI/1 uses source_provenance, not compose-based image digests"
	f["provider_signer_recognition"] = "ACI/1 uses source_provenance, not compose-based image repos"
	f["component_signature_recognition"] = "ACI/1 uses source_provenance, not compose-based image repos"
	f["sigstore_verification"] = "ACI/1 uses source_provenance, not per-image cosign verification"
	return f
}
