package attestation

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestExtractComposeDigests_WithDockerCompose(t *testing.T) {
	// app_compose with a docker_compose_file that has an image digest.
	appCompose := `{"docker_compose_file":"services:\n  app:\n    image: ghcr.io/org/repo@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234\n"}`

	cd := ExtractComposeDigests(appCompose)
	t.Logf("digests: %v", cd.Digests)
	t.Logf("repos: %v", cd.Repos)
	t.Logf("digestToRepo: %v", cd.DigestToRepo)
	if len(cd.Digests) == 0 {
		t.Error("expected non-empty Digests from docker_compose_file")
	}
	if len(cd.Repos) == 0 {
		t.Error("expected non-empty Repos from docker_compose_file")
	}
}

func TestExtractComposeDigests_PlainYAML(t *testing.T) {
	// Raw YAML (no docker_compose_file wrapper) — ExtractDockerCompose fails,
	// falls back to using appCompose directly.
	appCompose := "services:\n  app:\n    image: ghcr.io/org/repo@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234\n"

	cd := ExtractComposeDigests(appCompose)
	t.Logf("digests: %v", cd.Digests)
	if len(cd.Digests) == 0 {
		t.Error("expected non-empty Digests from plain YAML fallback")
	}
}

func TestExtractComposeDigests_Empty(t *testing.T) {
	cd := ExtractComposeDigests("")
	t.Logf("empty: digests=%v repos=%v", cd.Digests, cd.Repos)
	// Should not panic; empty is acceptable.
	if cd.Digests != nil {
		t.Error("expected nil Digests for empty compose")
	}
}

func TestMergeComposeDigests_Basic(t *testing.T) {
	model := ComposeDigests{
		Digests:      []string{"aaa", "bbb"},
		Repos:        []string{"repo1"},
		DigestToRepo: map[string]string{"aaa": "repo1", "bbb": "repo2"},
	}
	gateway := ComposeDigests{
		Digests:      []string{"ccc"},
		Repos:        []string{"repo3"},
		DigestToRepo: map[string]string{"ccc": "repo3"},
	}

	allDigests, digestToRepo := MergeComposeDigests(model, gateway)
	t.Logf("allDigests: %v", allDigests)
	t.Logf("digestToRepo: %v", digestToRepo)

	if len(allDigests) != 3 {
		t.Errorf("allDigests len = %d, want 3", len(allDigests))
	}
	if digestToRepo["aaa"] != "repo1" {
		t.Errorf("digestToRepo[aaa] = %q, want repo1", digestToRepo["aaa"])
	}
	if digestToRepo["ccc"] != "repo3" {
		t.Errorf("digestToRepo[ccc] = %q, want repo3", digestToRepo["ccc"])
	}
}

func TestMergeComposeDigests_Deduplication(t *testing.T) {
	// Same digest in both model and gateway — should appear once.
	model := ComposeDigests{
		Digests:      []string{"shared", "model-only"},
		DigestToRepo: map[string]string{"shared": "repo1", "model-only": "repo2"},
	}
	gateway := ComposeDigests{
		Digests:      []string{"shared", "gateway-only"},
		DigestToRepo: map[string]string{"shared": "repo1", "gateway-only": "repo3"},
	}

	allDigests, _ := MergeComposeDigests(model, gateway)
	t.Logf("allDigests: %v", allDigests)

	seen := make(map[string]int)
	for _, d := range allDigests {
		seen[d]++
	}
	if seen["shared"] != 1 {
		t.Errorf("shared digest appears %d times, want 1", seen["shared"])
	}
	if len(allDigests) != 3 {
		t.Errorf("allDigests len = %d, want 3 (shared+model-only+gateway-only)", len(allDigests))
	}
}

func TestMergeComposeDigests_Conflict(t *testing.T) {
	// Same digest maps to different repos — first-writer-wins (model).
	model := ComposeDigests{
		Digests:      []string{"abc"},
		DigestToRepo: map[string]string{"abc": "repo-model"},
	}
	gateway := ComposeDigests{
		Digests:      []string{"abc"},
		DigestToRepo: map[string]string{"abc": "repo-gateway"},
	}

	_, digestToRepo := MergeComposeDigests(model, gateway)
	t.Logf("digestToRepo: %v", digestToRepo)
	if digestToRepo["abc"] != "repo-model" {
		t.Errorf("first-writer-wins: digestToRepo[abc] = %q, want repo-model", digestToRepo["abc"])
	}
}

func TestVerifyComposeBinding_Pass(t *testing.T) {
	appCompose := `{"docker_compose_file":"version: '3'\nservices:\n  app:\n    image: ghcr.io/org/repo@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234\n"}`
	hash := sha256.Sum256([]byte(appCompose))

	// Build expected MRConfigID: prefix byte 0x01 followed by the hash, zero-padded to 48 bytes.
	mrConfigID := make([]byte, 48)
	mrConfigID[0] = 0x01
	copy(mrConfigID[1:], hash[:])

	if err := VerifyComposeBinding(appCompose, mrConfigID); err != nil {
		t.Fatalf("expected pass, got error: %v", err)
	}
}

func TestVerifyComposeBinding_Mismatch(t *testing.T) {
	appCompose := `{"docker_compose_file":"version: '3'"}`
	mrConfigID := make([]byte, 48)
	mrConfigID[0] = 0x01
	// wrong hash — leave zeros

	err := VerifyComposeBinding(appCompose, mrConfigID)
	if err == nil {
		t.Fatal("expected error for hash mismatch, got nil")
	}
	t.Logf("expected error: %v", err)
}

func TestVerifyComposeBinding_EmptyMRConfigID(t *testing.T) {
	err := VerifyComposeBinding("something", nil)
	if err == nil {
		t.Fatal("expected error for empty MRConfigID, got nil")
	}
}

func TestVerifyComposeBinding_TooShort(t *testing.T) {
	err := VerifyComposeBinding("something", []byte{0x01})
	if err == nil {
		t.Fatal("expected error for short MRConfigID, got nil")
	}
}

func TestExtractDockerCompose_Present(t *testing.T) {
	input := `{"docker_compose_file":"version: '3'\nservices:\n  app:\n    image: test\n"}`
	dc, err := ExtractDockerCompose(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dc == "" {
		t.Fatal("expected non-empty docker_compose_file")
	}
	t.Logf("docker_compose_file: %s", dc)
}

func TestExtractDockerCompose_Absent(t *testing.T) {
	input := `{"other_field": "value"}`
	dc, err := ExtractDockerCompose(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dc != "" {
		t.Fatalf("expected empty string, got %q", dc)
	}
}

func TestExtractDockerCompose_InvalidJSON(t *testing.T) {
	_, err := ExtractDockerCompose("not json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestExtractImageDigests_Found(t *testing.T) {
	text := `services:
  app:
    image: ghcr.io/org/repo@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234
  worker:
    image: ghcr.io/org/worker@sha256:0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
`
	digests := ExtractImageDigests(text)
	if len(digests) != 2 {
		t.Fatalf("expected 2 digests, got %d: %v", len(digests), digests)
	}
	if digests[0] != "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234" {
		t.Errorf("unexpected first digest: %s", digests[0])
	}
	if digests[1] != "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff" {
		t.Errorf("unexpected second digest: %s", digests[1])
	}
}

func TestExtractImageDigests_Dedup(t *testing.T) {
	text := `image: ghcr.io/org/repo@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234
image: ghcr.io/org/repo@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234`
	digests := ExtractImageDigests(text)
	if len(digests) != 1 {
		t.Fatalf("expected 1 digest after dedup, got %d", len(digests))
	}
}

func TestExtractImageDigests_None(t *testing.T) {
	digests := ExtractImageDigests("no images here")
	if len(digests) != 0 {
		t.Fatalf("expected 0 digests, got %d", len(digests))
	}
}

func TestExtractImageRepositories_FoundAndNormalized(t *testing.T) {
	text := `services:
  api:
    image: ghcr.io/nearai/router:v1.2.3@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234
  worker:
    image: registry.example.com:5000/nearai/worker@sha256:0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
`
	repos := ExtractImageRepositories(text)
	if len(repos) != 2 {
		t.Fatalf("expected 2 repositories, got %d: %v", len(repos), repos)
	}
	if repos[0] != "ghcr.io/nearai/router" {
		t.Errorf("unexpected first repo: %s", repos[0])
	}
	if repos[1] != "registry.example.com:5000/nearai/worker" {
		t.Errorf("unexpected second repo: %s", repos[1])
	}
}

func TestExtractImageRepositories_Dedup(t *testing.T) {
	text := `image: ghcr.io/nearai/router:v1@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234
image: ghcr.io/nearai/router:v2@sha256:0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff`
	repos := ExtractImageRepositories(text)
	if len(repos) != 1 {
		t.Fatalf("expected 1 repository after dedup, got %d", len(repos))
	}
	if repos[0] != "ghcr.io/nearai/router" {
		t.Fatalf("unexpected repository: %s", repos[0])
	}
}

func TestNormalizeImageRepository_Empty(t *testing.T) {
	got := normalizeImageRepository("")
	if got != "" {
		t.Errorf("normalizeImageRepository(\"\") = %q, want \"\"", got)
	}
}

func TestNormalizeImageRepository_ComposeVarDefault(t *testing.T) {
	got := normalizeImageRepository("compose_manager_image:-nearaidev/compose-manager")
	if got != "nearaidev/compose-manager" {
		t.Fatalf("normalizeImageRepository(compose var default) = %q, want %q", got, "nearaidev/compose-manager")
	}
}

func TestNormalizeImageRepository_ComposeVarDefault_OfficialImage(t *testing.T) {
	got := normalizeImageRepository("image:-ubuntu")
	if got != "ubuntu" {
		t.Fatalf("normalizeImageRepository(compose var default official image) = %q, want %q", got, "ubuntu")
	}
}

func TestExtractImageRepositories_ComposeVarDefault(t *testing.T) {
	text := `services:
  compose-manager:
    image: compose_manager_image:-nearaidev/compose-manager@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234
`
	repos := ExtractImageRepositories(text)
	if len(repos) != 1 {
		t.Fatalf("expected 1 repository, got %d: %v", len(repos), repos)
	}
	if repos[0] != "nearaidev/compose-manager" {
		t.Fatalf("unexpected repository: %s", repos[0])
	}
}

func TestExtractImageRepositories_ComposeVarDefault_OfficialImage(t *testing.T) {
	text := `services:
  base:
    image: image:-ubuntu@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234
`
	repos := ExtractImageRepositories(text)
	if len(repos) != 1 {
		t.Fatalf("expected 1 repository, got %d: %v", len(repos), repos)
	}
	if repos[0] != "ubuntu" {
		t.Fatalf("unexpected repository: %s", repos[0])
	}
}

func TestExtractImageDigests_Capped(t *testing.T) {
	// Build text with maxImageDigests+1 unique digests; only maxImageDigests should be returned.
	var b strings.Builder
	for i := 0; i <= maxImageDigests; i++ {
		fmt.Fprintf(&b, "image: ghcr.io/org/img%d@sha256:%064x\n", i, i)
	}
	digests := ExtractImageDigests(b.String())
	if len(digests) != maxImageDigests {
		t.Errorf("expected %d digests (capped), got %d", maxImageDigests, len(digests))
	}
}

func TestExtractImageDigestToRepoMap_Conflict(t *testing.T) {
	// Same digest appears with two different image refs — first-writer-wins.
	digest := "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
	text := fmt.Sprintf("repo1@sha256:%s\nrepo2@sha256:%s", digest, digest)
	m := ExtractImageDigestToRepoMap(text)
	if m[digest] != "repo1" {
		t.Errorf("first-writer-wins: got %q, want \"repo1\"", m[digest])
	}
}

func TestExtractImageDigestToRepoMap(t *testing.T) {
	text := `services:
  api:
    image: ghcr.io/nearai/router:v1@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234
  db:
    image: certbot/dns-cloudflare@sha256:0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
`
	m := ExtractImageDigestToRepoMap(text)
	if len(m) != 2 {
		t.Fatalf("expected 2 entries, got %d: %v", len(m), m)
	}
	if m["abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"] != "ghcr.io/nearai/router" {
		t.Errorf("router digest mapped to wrong repo: %q", m["abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"])
	}
	if m["0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"] != "certbot/dns-cloudflare" {
		t.Errorf("certbot digest mapped to wrong repo: %q", m["0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"])
	}
}
