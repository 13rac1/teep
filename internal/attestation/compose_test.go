package attestation

import (
	"crypto/sha256"
	"testing"
)

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
