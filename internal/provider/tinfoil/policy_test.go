package tinfoil

import (
	"regexp"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
)

// TestOrgRepoPatternWidth pins the width of the org signer rule. The rule
// builds the expected Fulcio SAN from the attested repo name, so the pattern
// is the only boundary on which repos it trusts: widening it makes the
// enforced component_signature_recognition factor pass for every matching
// repo that publishes a Fulcio-signed release.
func TestOrgRepoPatternWidth(t *testing.T) {
	re := regexp.MustCompile(orgRepoPattern)
	tests := []struct {
		repo string
		want bool
	}{
		{"tinfoilsh/confidential-gemma4-31b", true},
		{"tinfoilsh/confidential-model-router", true},
		{"tinfoilsh/confidential-brand-new-model", true},
		// Outside the enclave namespace: covered by Images or not at all.
		{"tinfoilsh/hardware-measurements", false},
		{"tinfoilsh/verifier", false},
		{"tinfoilsh/..", false},
		{"tinfoilsh/.", false},
		{"tinfoilsh/confidential-", false},
		// Outside the org entirely.
		{"attacker/confidential-model", false},
		{"nottinfoilsh/confidential-model", false},
	}
	for _, tc := range tests {
		t.Run(tc.repo, func(t *testing.T) {
			if got := re.MatchString(tc.repo); got != tc.want {
				t.Errorf("orgRepoPattern matches %q = %v, want %v", tc.repo, got, tc.want)
			}
		})
	}
}

// TestIsValidSigstoreRepo pins the shape check on the repo path the proxy
// discovery response assigns to a model. The value is provider-controlled and
// reaches release URL paths and the supply chain policy.
func TestIsValidSigstoreRepo(t *testing.T) {
	tests := []struct {
		repo string
		want bool
	}{
		{"tinfoilsh/confidential-gemma4-31b", true},
		{"tinfoilsh/hardware-measurements", true},
		{"a/b", true},
		{"tinfoilsh/..", false},
		{"tinfoilsh/.", false},
		{"", false},
		{"tinfoilsh", false},
		{"tinfoilsh/a/b", false},
		{"tinfoilsh/repo?query=1", false},
		{"tinfoilsh/repo name", false},
		{"-tinfoilsh/repo", false},
		{"tinfoilsh/", false},
	}
	for _, tc := range tests {
		t.Run(tc.repo, func(t *testing.T) {
			if got := isValidSigstoreRepo(tc.repo); got != tc.want {
				t.Errorf("isValidSigstoreRepo(%q) = %v, want %v", tc.repo, got, tc.want)
			}
		})
	}
}

// TestOrgSignerExemptReposAreListed guards the narrow orgRepoPattern: the
// Tinfoil components outside the confidential- namespace must stay explicit
// Images entries, because Lookup is the only path that resolves them.
func TestOrgSignerExemptReposAreListed(t *testing.T) {
	tests := map[string]struct {
		policy *attestation.SupplyChainPolicy
		repo   string
	}{
		"cloud_router":    {CloudSupplyChainPolicy(), RouterRepo},
		"cloud_hardware":  {CloudSupplyChainPolicy(), PlatformRepo},
		"direct_hardware": {DirectSupplyChainPolicy(), PlatformRepo},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if tc.policy.Lookup(tc.repo) == nil {
				t.Errorf("Lookup(%q) = nil, want an explicit Images entry", tc.repo)
			}
		})
	}
}
