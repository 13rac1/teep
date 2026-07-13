package tinfoil

import (
	"sort"

	"github.com/13rac1/teep/internal/attestation"
)

// GithubActionsOIDCIssuer is the OIDC issuer for GitHub Actions-issued
// Fulcio certificates. Every Tinfoil component observed in live captures —
// the router, hardware-measurements, and every per-model inference enclave
// repo — is signed by this issuer (GH #118 part 1).
const GithubActionsOIDCIssuer = "https://token.actions.githubusercontent.com"

// tinfoilImage builds the ImageProvenance entry for a Tinfoil GitHub-repo +
// Fulcio-workflow component. Every Tinfoil component shares the same trust
// shape: Fulcio-signed by GitHub Actions under the tinfoilsh org, with the
// workflow file and release tag varying per repo and per release (Tinfoil
// cuts a new tag on every deploy), so WorkflowPattern is tag-agnostic —
// see WorkflowPattern in sigstore.go, which this mirrors exactly (the same
// regex the Sigstore verifier itself enforces when fetching and verifying
// the DSSE bundle for repo).
func tinfoilImage(repo string) attestation.ImageProvenance {
	return attestation.ImageProvenance{
		Repo:                  repo,
		Provenance:            attestation.FulcioSigned,
		OIDCIssuer:            GithubActionsOIDCIssuer,
		WorkflowPattern:       WorkflowPattern(repo),
		ProviderSignerTrusted: true,
	}
}

// CloudSupplyChainPolicy returns the supply chain policy for the
// tinfoil_v3_cloud provider, which always attests the confidential model
// router enclave (RouterRepo) rather than a per-model enclave, plus the
// hardware measurement allowlist repo. Constructed fresh on every call
// (immutable; no package-level mutable state), mirroring
// neardirect.SupplyChainPolicy().
func CloudSupplyChainPolicy() *attestation.SupplyChainPolicy {
	return &attestation.SupplyChainPolicy{Images: []attestation.ImageProvenance{
		tinfoilImage(RouterRepo),
		tinfoilImage(HardwareMeasurementsRepo),
	}}
}

// directModelRepos are the Sigstore GitHub repos recognized for the
// tinfoil_v3_direct provider's per-model inference enclaves, in addition to
// HardwareMeasurementsRepo. This is an explicit allowlist rather than a bare
// "tinfoilsh/confidential-*" prefix wildcard: an unknown model repo fails
// closed (component_recognition/component_signature Fail) until a reviewed
// policy edit adds it, matching the #114/#116 intent that new components
// require a deliberate trust decision, not an automatic pattern match.
//
// This list is seeded from modelRepoMap's known non-conventional mappings
// plus every model repo directly observed in live captures/fixtures to
// date. Adding a new Tinfoil direct model requires adding its repo here.
var directModelRepos = func() []string {
	seen := make(map[string]bool, len(modelRepoMap)+1)
	repos := make([]string, 0, len(modelRepoMap)+1)
	add := func(repo string) {
		if seen[repo] {
			return
		}
		seen[repo] = true
		repos = append(repos, repo)
	}
	for _, repo := range modelRepoMap {
		add(repo)
	}
	// Observed live capture (2026-07): tinfoilsh/confidential-gemma4-31b,
	// the "gemma4-31b" model served via tinfoil_v3_direct, resolved through
	// the naming convention (RepoForModel) rather than a modelRepoMap
	// override.
	add("tinfoilsh/confidential-gemma4-31b")
	sort.Strings(repos)
	return repos
}()

// DirectSupplyChainPolicy returns the supply chain policy for the
// tinfoil_v3_direct provider: the known per-model enclave repos
// (directModelRepos) plus the hardware measurement allowlist repo.
// Constructed fresh on every call (immutable; no package-level mutable
// state) — directModelRepos itself is computed once at init and never
// mutated after, so sharing it across calls is safe; each call still
// allocates a fresh Images slice/SupplyChainPolicy so callers cannot
// observe or mutate shared state through the returned policy.
func DirectSupplyChainPolicy() *attestation.SupplyChainPolicy {
	images := make([]attestation.ImageProvenance, 0, len(directModelRepos)+1)
	for _, repo := range directModelRepos {
		images = append(images, tinfoilImage(repo))
	}
	images = append(images, tinfoilImage(HardwareMeasurementsRepo))
	return &attestation.SupplyChainPolicy{Images: images}
}
