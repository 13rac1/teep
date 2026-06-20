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

// TestGPUEvidenceToEAT_Basic verifies the JSON envelope structure.
func TestGPUEvidenceToEAT_Basic(t *testing.T) {
	evidence := []GPUEvidence{
		{Arch: "HOPPER", Certificate: "cert1", Evidence: "ev1"},
		{Arch: "HOPPER", Certificate: "cert2", Evidence: "ev2"},
	}
	out := GPUEvidenceToEAT(evidence, "testnonce")
	if !strings.Contains(out, `"arch":"HOPPER"`) {
		t.Errorf("expected arch field, got: %s", out)
	}
	if !strings.Contains(out, `"nonce":"testnonce"`) {
		t.Errorf("expected nonce field, got: %s", out)
	}
	if !strings.Contains(out, `"evidence_list"`) {
		t.Errorf("expected evidence_list field, got: %s", out)
	}
	t.Logf("GPUEvidenceToEAT output: %s", out)
}

// TestGPUEvidenceToEAT_Empty verifies zero-evidence case.
func TestGPUEvidenceToEAT_Empty(t *testing.T) {
	out := GPUEvidenceToEAT([]GPUEvidence{}, "nonce")
	if !strings.Contains(out, `"arch":""`) {
		t.Errorf("expected empty arch for no evidence, got: %s", out)
	}
}

// ---------------------------------------------------------------------------
// verifySPDMEvidence — error branches
// ---------------------------------------------------------------------------

func TestVerifySPDMEvidence_TooShort(t *testing.T) {
	err := verifySPDMEvidence(context.Background(), make([]byte, 10), Nonce{}, nil)
	if err == nil {
		t.Fatal("expected error for too-short evidence")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("error should mention too short: %v", err)
	}
}

func TestVerifySPDMEvidence_WrongRequestVersion(t *testing.T) {
	evidence := make([]byte, spdmGetMeasurementsLen+100)
	evidence[0] = 0x99 // wrong version
	err := verifySPDMEvidence(context.Background(), evidence, Nonce{}, nil)
	if err == nil {
		t.Fatal("expected error for wrong request version")
	}
	if !strings.Contains(err.Error(), "request SPDM version") {
		t.Errorf("error should mention request SPDM version: %v", err)
	}
}

func TestVerifySPDMEvidence_WrongRequestCode(t *testing.T) {
	evidence := make([]byte, spdmGetMeasurementsLen+100)
	evidence[0] = spdmVersion11
	evidence[1] = 0x99 // wrong request code
	err := verifySPDMEvidence(context.Background(), evidence, Nonce{}, nil)
	if err == nil {
		t.Fatal("expected error for wrong request code")
	}
	if !strings.Contains(err.Error(), "request code") {
		t.Errorf("error should mention request code: %v", err)
	}
}

func TestVerifySPDMEvidence_NonceMismatch(t *testing.T) {
	evidence := make([]byte, spdmGetMeasurementsLen+100)
	evidence[0] = spdmVersion11
	evidence[1] = spdmGetMeasurements
	// Nonce at bytes [4:36] is all zeros — won't match a random nonce.
	nonce := NewNonce()
	err := verifySPDMEvidence(context.Background(), evidence, nonce, nil)
	if err == nil {
		t.Fatal("expected error for nonce mismatch")
	}
	if !strings.Contains(err.Error(), "nonce mismatch") {
		t.Errorf("error should mention nonce mismatch: %v", err)
	}
}

func TestVerifySPDMEvidence_WrongResponseVersion(t *testing.T) {
	nonce := Nonce{}
	evidence := make([]byte, spdmGetMeasurementsLen+100)
	evidence[0] = spdmVersion11
	evidence[1] = spdmGetMeasurements
	// Set nonce to match (all zeros).
	// Response starts at offset 37.
	evidence[spdmGetMeasurementsLen] = 0x99 // wrong response version
	err := verifySPDMEvidence(context.Background(), evidence, nonce, nil)
	if err == nil {
		t.Fatal("expected error for wrong response version")
	}
	if !strings.Contains(err.Error(), "response SPDM version") {
		t.Errorf("error should mention response SPDM version: %v", err)
	}
}

func TestVerifySPDMEvidence_WrongResponseCode(t *testing.T) {
	nonce := Nonce{}
	evidence := make([]byte, spdmGetMeasurementsLen+100)
	evidence[0] = spdmVersion11
	evidence[1] = spdmGetMeasurements
	evidence[spdmGetMeasurementsLen] = spdmVersion11
	evidence[spdmGetMeasurementsLen+1] = 0x99 // wrong response code
	err := verifySPDMEvidence(context.Background(), evidence, nonce, nil)
	if err == nil {
		t.Fatal("expected error for wrong response code")
	}
	if !strings.Contains(err.Error(), "response code") {
		t.Errorf("error should mention response code: %v", err)
	}
}

func TestVerifySPDMEvidence_ResponseTooShortForNonce(t *testing.T) {
	nonce := Nonce{}
	// Need at least spdmGetMeasurementsLen+10 = 47 total bytes to pass
	// initial length check. Response header is 8 bytes, then measRecordLen=0
	// means offset=8, and we need offset+32=40 to be > response length.
	// Response is evidence[37:], so we need response length < 40.
	// Total: 37 + 20 = 57 > 47 initial check, but response=20 < 40 for nonce.
	evidence := make([]byte, spdmGetMeasurementsLen+20)
	evidence[0] = spdmVersion11
	evidence[1] = spdmGetMeasurements
	resp := evidence[spdmGetMeasurementsLen:]
	resp[0] = spdmVersion11
	resp[1] = spdmMeasurements
	// measRecordLen = 0 (3 bytes LE at resp[5:8] are zeros)
	// offset = 8 + 0 = 8, need offset+32 = 40 > 20 bytes of response
	err := verifySPDMEvidence(context.Background(), evidence, nonce, nil)
	if err == nil {
		t.Fatal("expected error for response too short for nonce")
	}
	if !strings.Contains(err.Error(), "responder nonce") {
		t.Errorf("error should mention responder nonce: %v", err)
	}
}

// ---------------------------------------------------------------------------
// parseCertChain — error branches
// ---------------------------------------------------------------------------

func TestParseCertChain_InvalidBase64(t *testing.T) {
	_, err := parseCertChain("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestParseCertChain_NoCertificates(t *testing.T) {
	// Valid base64 that decodes to non-PEM content.
	_, err := parseCertChain("bm90LXBlbS1kYXRh") // "not-pem-data"
	if err == nil {
		t.Fatal("expected error for no certificates")
	}
	if !strings.Contains(err.Error(), "no certificates") {
		t.Errorf("error should mention no certificates: %v", err)
	}
}

// ---------------------------------------------------------------------------
// VerifyNVIDIAGPUDirect — error branches
// ---------------------------------------------------------------------------

func TestVerifyNVIDIAGPUDirect_EmptyEvidence(t *testing.T) {
	result := VerifyNVIDIAGPUDirect(context.Background(), []GPUEvidence{}, NewNonce())
	if result.SignatureErr == nil {
		t.Fatal("expected SignatureErr for empty evidence")
	}
	if !strings.Contains(result.SignatureErr.Error(), "empty") {
		t.Errorf("error should mention empty: %v", result.SignatureErr)
	}
}

func TestVerifyNVIDIAGPUDirect_BadCertificate(t *testing.T) {
	evidence := []GPUEvidence{
		{Arch: "HOPPER", Certificate: "bm90LXBlbS1kYXRh", Evidence: "dGVzdA=="},
	}
	result := VerifyNVIDIAGPUDirect(context.Background(), evidence, NewNonce())
	if result.SignatureErr == nil {
		t.Fatal("expected SignatureErr for bad certificate")
	}
}
