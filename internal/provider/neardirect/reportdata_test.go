package neardirect_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/neardirect"
)

// buildNEARReportData constructs a valid NEAR-scheme REPORTDATA from
// signing address bytes, TLS fingerprint bytes, and nonce.
func buildNEARReportData(addrBytes, fpBytes []byte, nonce attestation.Nonce) [64]byte {
	hash := sha256.Sum256(append(addrBytes, fpBytes...))
	var rd [64]byte
	copy(rd[:32], hash[:])
	copy(rd[32:64], nonce[:])
	return rd
}

func TestReportDataVerifier_CorrectBinding(t *testing.T) {
	addrBytes := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	fpBytes := make([]byte, 32)
	for i := range fpBytes {
		fpBytes[i] = byte(0xa0 + i)
	}
	nonce := attestation.NewNonce()
	reportData := buildNEARReportData(addrBytes, fpBytes, nonce)

	raw := &attestation.RawAttestation{
		SigningAlgo:    "ed25519",
		SigningKey:     hex.EncodeToString(addrBytes),
		SigningAddress: hex.EncodeToString(addrBytes),
		TLSFingerprint: hex.EncodeToString(fpBytes),
	}

	v := neardirect.ReportDataVerifier{}
	detail, err := v.VerifyReportData(reportData, raw, nonce)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if detail == "" {
		t.Error("expected non-empty detail on success")
	}
	t.Logf("detail: %s", detail)
}

func TestReportDataVerifier_0xPrefixedAddress(t *testing.T) {
	addrBytes := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	fpBytes := make([]byte, 32)
	for i := range fpBytes {
		fpBytes[i] = byte(i)
	}
	nonce := attestation.NewNonce()
	reportData := buildNEARReportData(addrBytes, fpBytes, nonce)

	raw := &attestation.RawAttestation{
		SigningAlgo:    "ed25519",
		SigningKey:     hex.EncodeToString(addrBytes),
		SigningAddress: "0x" + hex.EncodeToString(addrBytes),
		TLSFingerprint: hex.EncodeToString(fpBytes),
	}

	v := neardirect.ReportDataVerifier{}
	_, err := v.VerifyReportData(reportData, raw, nonce)
	if err != nil {
		t.Fatalf("unexpected error with 0x prefix: %v", err)
	}
}

func TestReportDataVerifier_WrongAddress(t *testing.T) {
	addrBytes := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	fpBytes := make([]byte, 32)
	for i := range fpBytes {
		fpBytes[i] = byte(0xa0 + i)
	}
	nonce := attestation.NewNonce()
	reportData := buildNEARReportData(addrBytes, fpBytes, nonce)

	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 1
	wrongAddr := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	raw := &attestation.RawAttestation{
		SigningAlgo:    "ed25519",
		SigningKey:     hex.EncodeToString(wrongAddr),
		SigningAddress: hex.EncodeToString(wrongAddr),
		TLSFingerprint: hex.EncodeToString(fpBytes),
	}

	v := neardirect.ReportDataVerifier{}
	_, err := v.VerifyReportData(reportData, raw, nonce)
	if err == nil {
		t.Fatal("expected error for wrong signing address, got nil")
	}
	t.Logf("got expected error: %v", err)
	if !strings.Contains(err.Error(), "REPORTDATA[0:32]") {
		t.Errorf("error should mention REPORTDATA[0:32] hash mismatch, got: %v", err)
	}
}

func TestReportDataVerifier_WrongFingerprint(t *testing.T) {
	addrBytes := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	fpBytes := make([]byte, 32)
	for i := range fpBytes {
		fpBytes[i] = byte(0xa0 + i)
	}
	nonce := attestation.NewNonce()
	reportData := buildNEARReportData(addrBytes, fpBytes, nonce)

	wrongFP := make([]byte, 32)
	for i := range wrongFP {
		wrongFP[i] = byte(0xff - i)
	}
	raw := &attestation.RawAttestation{
		SigningAlgo:    "ed25519",
		SigningKey:     hex.EncodeToString(addrBytes),
		SigningAddress: hex.EncodeToString(addrBytes),
		TLSFingerprint: hex.EncodeToString(wrongFP), // different 32-byte fingerprint
	}

	v := neardirect.ReportDataVerifier{}
	_, err := v.VerifyReportData(reportData, raw, nonce)
	if err == nil {
		t.Fatal("expected error for wrong TLS fingerprint, got nil")
	}
	t.Logf("got expected error: %v", err)
	if !strings.Contains(err.Error(), "REPORTDATA[0:32]") {
		t.Errorf("error should mention REPORTDATA[0:32] hash mismatch, got: %v", err)
	}
}

func TestReportDataVerifier_WrongNonce(t *testing.T) {
	addrBytes := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	fpBytes := make([]byte, 32)
	for i := range fpBytes {
		fpBytes[i] = byte(0xa0 + i)
	}
	nonce1 := attestation.NewNonce()
	nonce2 := attestation.NewNonce()
	reportData := buildNEARReportData(addrBytes, fpBytes, nonce1)

	raw := &attestation.RawAttestation{
		SigningAlgo:    "ed25519",
		SigningKey:     hex.EncodeToString(addrBytes),
		SigningAddress: hex.EncodeToString(addrBytes),
		TLSFingerprint: hex.EncodeToString(fpBytes),
	}

	v := neardirect.ReportDataVerifier{}
	_, err := v.VerifyReportData(reportData, raw, nonce2) // different nonce
	if err == nil {
		t.Fatal("expected error for wrong nonce, got nil")
	}
	t.Logf("got expected error: %v", err)
	if !strings.Contains(err.Error(), "REPORTDATA[32:64]") {
		t.Errorf("error should mention REPORTDATA[32:64] nonce mismatch, got: %v", err)
	}
}

func TestReportDataVerifier_MissingSigningAddress(t *testing.T) {
	raw := &attestation.RawAttestation{
		TLSFingerprint: "aabb",
	}

	v := neardirect.ReportDataVerifier{}
	_, err := v.VerifyReportData([64]byte{}, raw, attestation.Nonce{})
	if err == nil {
		t.Error("expected error for missing signing_address, got nil")
	}
}

func TestReportDataVerifier_MissingTLSFingerprint(t *testing.T) {
	raw := &attestation.RawAttestation{
		SigningAddress: "aabb",
	}

	v := neardirect.ReportDataVerifier{}
	_, err := v.VerifyReportData([64]byte{}, raw, attestation.Nonce{})
	if err == nil {
		t.Error("expected error for missing tls_cert_fingerprint, got nil")
	}
}

func TestReportDataVerifier_ModelKey(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 1
	other := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	nonce := attestation.NewNonce()
	fingerprint := make([]byte, 32)
	reportData := buildNEARReportData(key, fingerprint, nonce)
	for _, tc := range []struct {
		name      string
		mutate    func(*attestation.RawAttestation)
		wantError bool
	}{
		{"substituted_key", func(raw *attestation.RawAttestation) { raw.SigningKey = hex.EncodeToString(other) }, true},
		{"missing_key", func(raw *attestation.RawAttestation) { raw.SigningKey = "" }, true},
		{"malformed_key", func(raw *attestation.RawAttestation) { raw.SigningKey = strings.Repeat("zz", 32) }, true},
		{"short_key", func(raw *attestation.RawAttestation) { raw.SigningKey = "ab" }, true},
		{"missing_algorithm", func(raw *attestation.RawAttestation) { raw.SigningAlgo = "" }, true},
		{"ecdsa_algorithm", func(raw *attestation.RawAttestation) { raw.SigningAlgo = "ecdsa" }, true},
		{"missing_address", func(raw *attestation.RawAttestation) { raw.SigningAddress = "" }, true},
		{"ecdsa_address", func(raw *attestation.RawAttestation) { raw.SigningAddress = strings.Repeat("ab", 20) }, true},
		{"malformed_address", func(raw *attestation.RawAttestation) { raw.SigningAddress = strings.Repeat("zz", 32) }, true},
		{"uppercase_key", func(raw *attestation.RawAttestation) { raw.SigningKey = strings.ToUpper(raw.SigningKey) }, false},
		{"uppercase_address", func(raw *attestation.RawAttestation) { raw.SigningAddress = strings.ToUpper(raw.SigningAddress) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := &attestation.RawAttestation{SigningAlgo: "ed25519", SigningKey: hex.EncodeToString(key), SigningAddress: hex.EncodeToString(key), TLSFingerprint: hex.EncodeToString(fingerprint)}
			tc.mutate(raw)
			_, err := (neardirect.ReportDataVerifier{}).VerifyReportData(reportData, raw, nonce)
			if (err != nil) != tc.wantError {
				t.Fatalf("binding error = %v, want error %v", err, tc.wantError)
			}
		})
	}
}
