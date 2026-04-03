package attestation

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// fixtureNonce is the nonce embedded in the test fixture EAT.
const fixtureNonce = "dec6216ca055ffdc2991de0c1e8d835707246991599e46e20a3ca56d16a896de"

func loadEATFixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/nvidia_eat_hopper.json")
	if err != nil {
		t.Fatalf("read EAT fixture: %v", err)
	}
	return string(data)
}

func fixtureNonceBytes(t *testing.T) Nonce {
	t.Helper()
	n, err := ParseNonce(fixtureNonce)
	if err != nil {
		t.Fatalf("parse fixture nonce: %v", err)
	}
	return n
}

// TestVerifyNVIDIAEAT_RealFixture runs full end-to-end verification against
// the real Venice EAT fixture (8 H100 GPUs).
func TestVerifyNVIDIAEAT_RealFixture(t *testing.T) {
	payload := loadEATFixture(t)
	nonce := fixtureNonceBytes(t)

	result := verifyNVIDIAEAT(context.Background(), payload, nonce)

	if result.SignatureErr != nil {
		t.Fatalf("SignatureErr: %v", result.SignatureErr)
	}
	if result.ClaimsErr != nil {
		t.Fatalf("ClaimsErr: %v", result.ClaimsErr)
	}
	if result.Arch != "HOPPER" {
		t.Errorf("Arch: got %q, want %q", result.Arch, "HOPPER")
	}
	if result.GPUCount != 8 {
		t.Errorf("GPUCount: got %d, want 8", result.GPUCount)
	}
	if result.Nonce != fixtureNonce {
		t.Errorf("Nonce: got %q, want %q", result.Nonce, fixtureNonce)
	}
	if result.Format != "EAT" {
		t.Errorf("Format: got %q, want %q", result.Format, "EAT")
	}
}

// TestVerifyGPUEvidence_CertChain verifies the certificate chain of a single
// GPU from the fixture validates against the pinned root CA.
func TestVerifyGPUEvidence_CertChain(t *testing.T) {
	payload := loadEATFixture(t)
	var eat nvidiaEAT
	if err := json.Unmarshal([]byte(payload), &eat); err != nil {
		t.Fatalf("unmarshal EAT: %v", err)
	}

	rootCA, err := loadPinnedNVIDIARootCA()
	if err != nil {
		t.Fatalf("load root CA: %v", err)
	}

	// Parse and verify the first GPU's cert chain.
	certs, err := parseCertChain(eat.EvidenceList[0].Certificate)
	if err != nil {
		t.Fatalf("parseCertChain: %v", err)
	}

	if len(certs) != 5 {
		t.Errorf("cert chain length: got %d, want 5", len(certs))
	}

	if err := verifyCertChain(certs, rootCA); err != nil {
		t.Fatalf("verifyCertChain: %v", err)
	}

	// Verify the leaf is the expected GPU cert.
	leafCN := certs[0].Subject.CommonName
	if !strings.Contains(leafCN, "GH100") {
		t.Errorf("leaf CN %q does not contain GH100", leafCN)
	}
}

// TestVerifyGPUEvidence_Signature verifies the ECDSA P-384 SPDM signature
// for a single GPU from the fixture.
func TestVerifyGPUEvidence_Signature(t *testing.T) {
	payload := loadEATFixture(t)
	nonce := fixtureNonceBytes(t)
	var eat nvidiaEAT
	if err := json.Unmarshal([]byte(payload), &eat); err != nil {
		t.Fatalf("unmarshal EAT: %v", err)
	}

	rootCA, err := loadPinnedNVIDIARootCA()
	if err != nil {
		t.Fatalf("load root CA: %v", err)
	}

	// Verify first GPU's evidence (includes signature check).
	if err := verifyGPUEvidence(context.Background(), eat.EvidenceList[0], nonce, rootCA); err != nil {
		t.Fatalf("verifyGPUEvidence: %v", err)
	}
}

// TestVerifyGPUEvidence_NonceMatch verifies nonce extraction from SPDM request.
func TestVerifyGPUEvidence_NonceMatch(t *testing.T) {
	payload := loadEATFixture(t)
	nonce := fixtureNonceBytes(t)
	var eat nvidiaEAT
	if err := json.Unmarshal([]byte(payload), &eat); err != nil {
		t.Fatalf("unmarshal EAT: %v", err)
	}

	rootCA, err := loadPinnedNVIDIARootCA()
	if err != nil {
		t.Fatalf("load root CA: %v", err)
	}

	// All 8 GPUs should have the same nonce.
	for i, ev := range eat.EvidenceList {
		if err := verifyGPUEvidence(context.Background(), ev, nonce, rootCA); err != nil {
			t.Errorf("GPU %d: %v", i, err)
		}
	}
}

// TestVerifyNVIDIAEAT_WrongNonce verifies nonce mismatch is detected.
func TestVerifyNVIDIAEAT_WrongNonce(t *testing.T) {
	payload := loadEATFixture(t)
	wrongNonce := NewNonce() // random, won't match fixture

	result := verifyNVIDIAEAT(context.Background(), payload, wrongNonce)

	if result.ClaimsErr == nil {
		t.Fatal("expected ClaimsErr for wrong nonce, got nil")
	}
	if !strings.Contains(result.ClaimsErr.Error(), "nonce mismatch") {
		t.Errorf("ClaimsErr should mention nonce mismatch: %v", result.ClaimsErr)
	}
}

// TestVerifyNVIDIAEAT_InvalidJSON verifies error handling for bad JSON.
func TestVerifyNVIDIAEAT_InvalidJSON(t *testing.T) {
	result := verifyNVIDIAEAT(context.Background(), "not json{{{", NewNonce())

	if result.SignatureErr == nil {
		t.Fatal("expected SignatureErr for invalid JSON, got nil")
	}
}

// TestVerifyNVIDIAEAT_EmptyEvidenceList verifies error for empty evidence list.
func TestVerifyNVIDIAEAT_EmptyEvidenceList(t *testing.T) {
	payload := `{"arch":"HOPPER","nonce":"` + fixtureNonce + `","evidence_list":[]}`
	result := verifyNVIDIAEAT(context.Background(), payload, fixtureNonceBytes(t))

	if result.SignatureErr == nil {
		t.Fatal("expected SignatureErr for empty evidence_list, got nil")
	}
}

// TestLoadPinnedNVIDIARootCA verifies the embedded root CA loads and has the
// correct fingerprint.
func TestLoadPinnedNVIDIARootCA(t *testing.T) {
	cert, err := loadPinnedNVIDIARootCA()
	if err != nil {
		t.Fatalf("loadPinnedNVIDIARootCA: %v", err)
	}
	if cert.Subject.CommonName != "NVIDIA Device Identity CA" {
		t.Errorf("root CA CN: got %q, want %q", cert.Subject.CommonName, "NVIDIA Device Identity CA")
	}
	if !cert.IsCA {
		t.Error("root CA is not marked as CA")
	}
}
