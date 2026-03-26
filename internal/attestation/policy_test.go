package attestation_test

import (
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/nanogpt"
	"github.com/13rac1/teep/internal/provider/nearcloud"
	"github.com/13rac1/teep/internal/provider/neardirect"
)

// ---------------------------------------------------------------------------
// Sigstore: allowlisted non-Rekor images (uses real supply chain policies)
// ---------------------------------------------------------------------------

func TestEvalSigstoreVerification_AllowlistedNonRekor(t *testing.T) {
	nonce := attestation.NewNonce()
	sigKey := attestation.ValidSigningKeyForTest(t)
	raw := attestation.BuildMinimalRawForTest(nonce, sigKey)
	neardirectDigest := "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
	certbotDigest := "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
	sig := []attestation.SigstoreResult{
		{Digest: neardirectDigest, OK: true, Status: 200},
		{Digest: certbotDigest, OK: false, Status: 404},
	}
	f := attestation.AssertSingleFactorForTest(t, attestation.EvalSigstoreVerificationForTest(&attestation.ReportInput{
		Provider:          "neardirect",
		Raw:               raw,
		SupplyChainPolicy: neardirect.SupplyChainPolicy(),
		Sigstore:          sig,
		DigestToRepo:      map[string]string{neardirectDigest: "nearaidev/compose-manager", certbotDigest: "certbot/dns-cloudflare"},
		ImageRepos:        []string{"nearaidev/compose-manager", "certbot/dns-cloudflare"},
	}), attestation.Pass)
	if !strings.Contains(f.Detail, "compose-pinned") {
		t.Errorf("detail should mention compose-pinned: %s", f.Detail)
	}
}

// ---------------------------------------------------------------------------
// Build transparency log (supply chain policy) tests
// ---------------------------------------------------------------------------

func TestEvalBuildTransparencyLog(t *testing.T) {
	nonce := attestation.NewNonce()
	sigKey := attestation.ValidSigningKeyForTest(t)

	t.Run("pass_neardirect", func(t *testing.T) {
		raw := attestation.BuildMinimalRawForTest(nonce, sigKey)
		sig := []attestation.SigstoreResult{{
			Digest: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			OK:     true, Status: 200,
		}}
		rekor := []attestation.RekorProvenance{{
			Digest:        sig[0].Digest,
			HasCert:       true,
			SubjectURI:    "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master",
			OIDCIssuer:    "https://token.actions.githubusercontent.com",
			SourceRepo:    "nearai/compose-manager",
			SourceRepoURL: "https://github.com/nearai/compose-manager",
			SourceCommit:  "0123456789abcdef",
			RunnerEnv:     "github-hosted",
		}}
		attestation.AssertSingleFactorForTest(t, attestation.EvalBuildTransparencyLogForTest(&attestation.ReportInput{
			Provider:          "neardirect",
			Raw:               raw,
			SupplyChainPolicy: neardirect.SupplyChainPolicy(),
			ImageRepos:        []string{"nearaidev/compose-manager"},
			DigestToRepo:      map[string]string{sig[0].Digest: "nearaidev/compose-manager"},
			Sigstore:          sig,
			Rekor:             rekor,
		}), attestation.Pass)
	})

	t.Run("rejects_image_repo", func(t *testing.T) {
		raw := attestation.BuildMinimalRawForTest(nonce, sigKey)
		f := attestation.AssertSingleFactorForTest(t, attestation.EvalBuildTransparencyLogForTest(&attestation.ReportInput{
			Provider:          "neardirect",
			Raw:               raw,
			SupplyChainPolicy: neardirect.SupplyChainPolicy(),
			ImageRepos:        []string{"ghcr.io/attacker/router"},
		}), attestation.Fail)
		if !strings.Contains(f.Detail, "supply chain policy") {
			t.Errorf("detail should mention supply chain policy: %s", f.Detail)
		}
	})

	t.Run("nearcloud_separate_allowlists", func(t *testing.T) {
		raw := attestation.BuildMinimalRawForTest(nonce, sigKey)
		sig := []attestation.SigstoreResult{{
			Digest: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			OK:     true, Status: 200,
		}}
		rekor := []attestation.RekorProvenance{{
			Digest:        sig[0].Digest,
			HasCert:       true,
			SubjectURI:    "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master",
			OIDCIssuer:    "https://token.actions.githubusercontent.com",
			SourceRepo:    "nearai/compose-manager",
			SourceRepoURL: "https://github.com/nearai/compose-manager",
			SourceCommit:  "0123456789abcdef",
			RunnerEnv:     "github-hosted",
		}}
		attestation.AssertSingleFactorForTest(t, attestation.EvalBuildTransparencyLogForTest(&attestation.ReportInput{
			Provider:          "nearcloud",
			Raw:               raw,
			SupplyChainPolicy: nearcloud.SupplyChainPolicy(),
			ImageRepos:        []string{"nearaidev/compose-manager"},
			GatewayImageRepos: []string{"nearaidev/dstack-vpc-client"},
			DigestToRepo:      map[string]string{sig[0].Digest: "nearaidev/compose-manager"},
			Sigstore:          sig,
			Rekor:             rekor,
		}), attestation.Pass)
	})

	t.Run("rejects_gateway_only_image", func(t *testing.T) {
		raw := attestation.BuildMinimalRawForTest(nonce, sigKey)
		f := attestation.AssertSingleFactorForTest(t, attestation.EvalBuildTransparencyLogForTest(&attestation.ReportInput{
			Provider:          "neardirect",
			Raw:               raw,
			SupplyChainPolicy: nearcloud.SupplyChainPolicy(), // has dstack-vpc-client as gateway-only
			ImageRepos:        []string{"nearaidev/dstack-vpc-client"},
		}), attestation.Fail)
		if !strings.Contains(strings.ToLower(f.Detail), "model container policy") {
			t.Errorf("detail should mention model policy rejection: %s", f.Detail)
		}
	})

	t.Run("rejects_signer", func(t *testing.T) {
		raw := attestation.BuildMinimalRawForTest(nonce, sigKey)
		sig := []attestation.SigstoreResult{{
			Digest: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			OK:     true, Status: 200,
		}}
		rekor := []attestation.RekorProvenance{{
			Digest:        sig[0].Digest,
			HasCert:       true,
			SubjectURI:    "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master",
			OIDCIssuer:    "https://token.actions.githubusercontent.com",
			SourceRepo:    "attacker/router",
			SourceRepoURL: "https://github.com/attacker/router",
		}}
		f := attestation.AssertSingleFactorForTest(t, attestation.EvalBuildTransparencyLogForTest(&attestation.ReportInput{
			Provider:          "neardirect",
			Raw:               raw,
			SupplyChainPolicy: neardirect.SupplyChainPolicy(),
			ImageRepos:        []string{"nearaidev/compose-manager"},
			DigestToRepo:      map[string]string{sig[0].Digest: "nearaidev/compose-manager"},
			Sigstore:          sig,
			Rekor:             rekor,
		}), attestation.Fail)
		if !strings.Contains(f.Detail, "unexpected source repo") {
			t.Errorf("detail should mention source repo rejection: %s", f.Detail)
		}
	})

	t.Run("fulcio_oidc_identity_mismatch", func(t *testing.T) {
		raw := attestation.BuildMinimalRawForTest(nonce, sigKey)
		sig := []attestation.SigstoreResult{{
			Digest: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			OK:     true, Status: 200,
		}}
		rekor := []attestation.RekorProvenance{{
			Digest:        sig[0].Digest,
			HasCert:       true,
			SubjectURI:    "https://github.com/attacker/evil-repo/.github/workflows/evil.yml@refs/heads/main",
			OIDCIssuer:    "https://token.actions.githubusercontent.com",
			SourceRepo:    "nearai/compose-manager",
			SourceRepoURL: "https://github.com/nearai/compose-manager",
			SourceCommit:  "0123456789abcdef",
			RunnerEnv:     "github-hosted",
		}}
		f := attestation.AssertSingleFactorForTest(t, attestation.EvalBuildTransparencyLogForTest(&attestation.ReportInput{
			Provider:          "neardirect",
			Raw:               raw,
			SupplyChainPolicy: neardirect.SupplyChainPolicy(),
			ImageRepos:        []string{"nearaidev/compose-manager"},
			DigestToRepo:      map[string]string{sig[0].Digest: "nearaidev/compose-manager"},
			Sigstore:          sig,
			Rekor:             rekor,
		}), attestation.Fail)
		if !strings.Contains(f.Detail, "unexpected OIDC identity") {
			t.Errorf("detail should mention OIDC identity mismatch: %s", f.Detail)
		}
	})

	t.Run("key_fingerprint_mismatch", func(t *testing.T) {
		raw := attestation.BuildMinimalRawForTest(nonce, sigKey)
		composeManagerDigest := "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
		datadogDigest := "dddd1234dddd1234dddd1234dddd1234dddd1234dddd1234dddd1234dddd1234"
		sig := []attestation.SigstoreResult{
			{Digest: composeManagerDigest, OK: true, Status: 200},
			{Digest: datadogDigest, OK: true, Status: 200},
		}
		rekor := []attestation.RekorProvenance{
			{
				Digest:        composeManagerDigest,
				HasCert:       true,
				SubjectURI:    "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master",
				OIDCIssuer:    "https://token.actions.githubusercontent.com",
				SourceRepo:    "nearai/compose-manager",
				SourceRepoURL: "https://github.com/nearai/compose-manager",
				SourceCommit:  "0123456789abcdef",
				RunnerEnv:     "github-hosted",
			},
			{
				Digest:         datadogDigest,
				HasCert:        false,
				KeyFingerprint: "0000000000000000000000000000000000000000000000000000000000000000",
			},
		}
		f := attestation.AssertSingleFactorForTest(t, attestation.EvalBuildTransparencyLogForTest(&attestation.ReportInput{
			Provider:          "neardirect",
			Raw:               raw,
			SupplyChainPolicy: neardirect.SupplyChainPolicy(),
			ImageRepos:        []string{"nearaidev/compose-manager", "datadog/agent"},
			DigestToRepo: map[string]string{
				composeManagerDigest: "nearaidev/compose-manager",
				datadogDigest:        "datadog/agent",
			},
			Sigstore: sig,
			Rekor:    rekor,
		}), attestation.Fail)
		if !strings.Contains(f.Detail, "unexpected signing key fingerprint") {
			t.Errorf("detail should mention key fingerprint mismatch: %s", f.Detail)
		}
	})

	t.Run("key_fingerprint_pass", func(t *testing.T) {
		raw := attestation.BuildMinimalRawForTest(nonce, sigKey)
		composeManagerDigest := "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
		datadogDigest := "dddd1234dddd1234dddd1234dddd1234dddd1234dddd1234dddd1234dddd1234"
		sig := []attestation.SigstoreResult{
			{Digest: composeManagerDigest, OK: true, Status: 200},
			{Digest: datadogDigest, OK: true, Status: 200},
		}
		rekor := []attestation.RekorProvenance{
			{
				Digest:        composeManagerDigest,
				HasCert:       true,
				SubjectURI:    "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master",
				OIDCIssuer:    "https://token.actions.githubusercontent.com",
				SourceRepo:    "nearai/compose-manager",
				SourceRepoURL: "https://github.com/nearai/compose-manager",
				SourceCommit:  "0123456789abcdef",
				RunnerEnv:     "github-hosted",
			},
			{
				Digest:            datadogDigest,
				HasCert:           false,
				KeyFingerprint:    "25bcab4ec8eede1e3091a14692126798c23986832ae6e5948d6f7eb0a928ab0b",
				SETVerified:       true,
				InclusionVerified: true,
			},
		}
		attestation.AssertSingleFactorForTest(t, attestation.EvalBuildTransparencyLogForTest(&attestation.ReportInput{
			Provider:          "neardirect",
			Raw:               raw,
			SupplyChainPolicy: neardirect.SupplyChainPolicy(),
			ImageRepos:        []string{"nearaidev/compose-manager", "datadog/agent"},
			DigestToRepo: map[string]string{
				composeManagerDigest: "nearaidev/compose-manager",
				datadogDigest:        "datadog/agent",
			},
			Sigstore: sig,
			Rekor:    rekor,
		}), attestation.Pass)
	})

	t.Run("sigstore_entry_unverified_set_fails", func(t *testing.T) {
		raw := attestation.BuildMinimalRawForTest(nonce, sigKey)
		composeManagerDigest := "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
		datadogDigest := "dddd1234dddd1234dddd1234dddd1234dddd1234dddd1234dddd1234dddd1234"
		sig := []attestation.SigstoreResult{
			{Digest: composeManagerDigest, OK: true, Status: 200},
			{Digest: datadogDigest, OK: true, Status: 200},
		}
		rekor := []attestation.RekorProvenance{
			{
				Digest:        composeManagerDigest,
				HasCert:       true,
				SubjectURI:    "https://github.com/nearai/compose-manager/.github/workflows/build.yml@refs/heads/master",
				OIDCIssuer:    "https://token.actions.githubusercontent.com",
				SourceRepo:    "nearai/compose-manager",
				SourceRepoURL: "https://github.com/nearai/compose-manager",
				SourceCommit:  "0123456789abcdef",
				RunnerEnv:     "github-hosted",
			},
			{
				// Sigstore entry without SET/inclusion verification must fail.
				Digest:         datadogDigest,
				HasCert:        false,
				KeyFingerprint: "25bcab4ec8eede1e3091a14692126798c23986832ae6e5948d6f7eb0a928ab0b",
			},
		}
		f := attestation.AssertSingleFactorForTest(t, attestation.EvalBuildTransparencyLogForTest(&attestation.ReportInput{
			Provider:          "neardirect",
			Raw:               raw,
			SupplyChainPolicy: neardirect.SupplyChainPolicy(),
			ImageRepos:        []string{"nearaidev/compose-manager", "datadog/agent"},
			DigestToRepo: map[string]string{
				composeManagerDigest: "nearaidev/compose-manager",
				datadogDigest:        "datadog/agent",
			},
			Sigstore: sig,
			Rekor:    rekor,
		}), attestation.Fail)
		if !strings.Contains(f.Detail, "SET verification did not succeed") {
			t.Errorf("detail should mention SET verification failure: %s", f.Detail)
		}
	})

	t.Run("no_rekor_no_policy", func(t *testing.T) {
		raw := attestation.BuildMinimalRawForTest(nonce, sigKey)
		// Unknown provider → no supply chain policy → no Rekor → Fail
		attestation.AssertSingleFactorForTest(t, attestation.EvalBuildTransparencyLogForTest(&attestation.ReportInput{
			Provider: "unknown",
			Raw:      raw,
		}), attestation.Fail)
	})
}

// ---------------------------------------------------------------------------
// Supply chain policy tests (use real provider policies)
// ---------------------------------------------------------------------------

func TestSupplyChainPolicyNanoGPT(t *testing.T) {
	p := nanogpt.SupplyChainPolicy()

	for _, repo := range []string{
		"alpine", "dstacktee/dstack-ingress", "dstacktee/vllm-proxy",
		"haproxy", "lmsysorg/sglang", "mondaylord/vllm-openai",
		"phalanetwork/vllm-proxy", "python", "redis", "vllm/vllm-openai",
	} {
		if !p.AllowedInModel(repo) {
			t.Errorf("repo %q should be allowed in model tier", repo)
		}
	}
	if p.AllowedInModel("attacker/evil-image") {
		t.Error("unexpected repo should not be allowed")
	}
	if p.HasGatewayImages() {
		t.Error("NanoGPT policy should have no gateway images")
	}
}

func TestGatewayRepoNames(t *testing.T) {
	p := nearcloud.SupplyChainPolicy()
	names := p.GatewayRepoNames()
	want := []string{"datadog/agent", "nearaidev/dstack-vpc-client", "nearaidev/dstack-vpc", "alpine", "nearaidev/cloud-api", "nearaidev/cvm-ingress"}
	if len(names) != len(want) {
		t.Fatalf("GatewayRepoNames() = %v (len %d), want len %d", names, len(names), len(want))
	}
	for i, name := range names {
		if name != want[i] {
			t.Errorf("GatewayRepoNames()[%d] = %q, want %q", i, name, want[i])
		}
	}
}

func TestGatewayRepoNames_NoGateway(t *testing.T) {
	p := neardirect.SupplyChainPolicy()
	names := p.GatewayRepoNames()
	if len(names) != 0 {
		t.Errorf("GatewayRepoNames() = %v, want empty", names)
	}
}
