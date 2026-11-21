package tinfoil

import (
	"sort"

	"github.com/13rac1/teep/internal/attestation"
)

// GithubActionsOIDCIssuer is the OIDC issuer for GitHub Actions-issued
// Fulcio certificates, used by every Tinfoil component.
const GithubActionsOIDCIssuer = "https://token.actions.githubusercontent.com"

// orgRepoPattern matches the tinfoilsh enclave repos that the org signer rule
// covers.
//
// DANGER: a wider pattern makes the enforced component_signature_recognition
// factor pass for any tinfoilsh repo that publishes a Fulcio-signed release,
// because attestation.orgImageFor builds the expected SAN from the attested
// repo name itself. Before GH #118 this factor accepted only the
// confidential- prefix and the two named repos. RouterRepo and
// PlatformRepo are explicit Images entries, so Lookup resolves
// them before this rule applies. Guarded by TestOrgRepoPatternWidth.
const orgRepoPattern = `^tinfoilsh/confidential-[a-z0-9][a-z0-9._-]*$`

// orgSigner is Tinfoil's provider-wide signer identity: GitHub Actions
// Fulcio release workflows in tinfoilsh org repos. SEE:
// attestation.OrgSignerPolicy for the trust semantics.
func orgSigner() *attestation.OrgSignerPolicy {
	return &attestation.OrgSignerPolicy{
		OIDCIssuer:  GithubActionsOIDCIssuer,
		RepoPattern: orgRepoPattern,
	}
}

// tinfoilImage builds the ImageProvenance entry for a Tinfoil component:
// Fulcio-signed by GitHub Actions with the repo's release workflow SAN,
// independent of the release tag (SEE: WorkflowPattern in sigstore.go).
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
// tinfoil_v3_cloud provider, which attests the confidential model router
// enclave (RouterRepo) rather than a per-model enclave, plus the hardware
// measurement allowlist repo. Each call returns a new policy; the package
// has no shared mutable state.
func CloudSupplyChainPolicy() *attestation.SupplyChainPolicy {
	return &attestation.SupplyChainPolicy{
		Images: []attestation.ImageProvenance{
			tinfoilImage(RouterRepo),
			tinfoilImage(PlatformRepo),
		},
		OrgSigner: orgSigner(),
	}
}

// directModelRepos are the Sigstore GitHub repos expected for the
// tinfoil_v3_direct provider's per-model inference enclaves, in addition to
// PlatformRepo. Tracking, not enforcement: the list feeds only
// component_recognition, so a repo missing here is a persistent WARN while
// the enforced signer factors are satisfied by the OrgSigner rule (SEE:
// attestation.OrgSignerPolicy). Add a reviewed repo to silence its WARN.
//
// Initial entries come from modelRepoMap's non-conventional mappings plus
// the model-to-repo mapping served by /.well-known/tinfoil-proxy as of
// 2026-08.
var directModelRepos = func() []string {
	seen := make(map[string]bool, len(modelRepoMap))
	repos := make([]string, 0, len(modelRepoMap))
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
	for _, repo := range []string{
		"tinfoilsh/confidential-deepseek-v4-1-flash",
		"tinfoilsh/confidential-doc-upload",
		"tinfoilsh/confidential-gemma4-31b",
		"tinfoilsh/confidential-glm5-2",
		"tinfoilsh/confidential-gpt-oss-120b",
		"tinfoilsh/confidential-gpt-oss-safeguard-120b",
		"tinfoilsh/confidential-kimi-k2-6-b200",
		"tinfoilsh/confidential-llama3-3-70b",
		"tinfoilsh/confidential-pii-cpu",
		"tinfoilsh/confidential-realtime-models",
		"tinfoilsh/confidential-websearch",
	} {
		add(repo)
	}
	sort.Strings(repos)
	return repos
}()

// DirectSupplyChainPolicy returns the supply chain policy for the
// tinfoil_v3_direct provider: the known per-model enclave repos
// (directModelRepos) plus the hardware measurement allowlist repo. Each call
// returns a new policy; the package has no shared mutable state.
func DirectSupplyChainPolicy() *attestation.SupplyChainPolicy {
	images := make([]attestation.ImageProvenance, 0, len(directModelRepos)+1)
	for _, repo := range directModelRepos {
		images = append(images, tinfoilImage(repo))
	}
	images = append(images, tinfoilImage(PlatformRepo))
	return &attestation.SupplyChainPolicy{Images: images, OrgSigner: orgSigner()}
}
