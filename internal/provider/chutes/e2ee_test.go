package chutes_test

import (
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider/chutes"
)

func mlkemModelPubB64(t *testing.T) string {
	t.Helper()
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768: %v", err)
	}
	return base64.StdEncoding.EncodeToString(dk.EncapsulationKey().Bytes())
}

func chutesRaw(t *testing.T, pubB64, instanceID, e2eNonce string) *attestation.RawAttestation {
	t.Helper()
	return &attestation.RawAttestation{
		SigningKey: pubB64,
		InstanceID: instanceID,
		E2ENonce:   e2eNonce,
		ChuteID:    "chutes-model-uuid",
	}
}

func chutesChatBody(t *testing.T) []byte {
	t.Helper()
	body := map[string]any{
		"model":    "chutes-model",
		"messages": []map[string]string{{"role": "user", "content": "Hello"}},
		"stream":   true,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestChutesE2EE_EncryptRequest(t *testing.T) {
	pubB64 := mlkemModelPubB64(t)
	raw := chutesRaw(t, pubB64, "inst-1", "nonce-1")

	enc := chutes.NewE2EE()
	er, err := enc.EncryptRequest(chutesChatBody(t), raw, e2ee.EndpointChat)
	if err != nil {
		t.Fatalf("EncryptRequest: %v", err)
	}

	if er.Session != nil {
		t.Error("expected nil Decryptor for Chutes (uses ChutesE2EE instead)")
	}
	if er.EHBP != nil {
		t.Error("expected nil EHBP for Chutes")
	}
	if er.Chutes == nil {
		t.Fatal("expected non-nil ChutesE2EE")
	}
	defer er.Chutes.Session.Zero()

	t.Logf("ChuteID=%q InstanceID=%q E2ENonce=%q payload_len=%d",
		er.Chutes.ChuteID, er.Chutes.InstanceID, er.Chutes.E2ENonce, len(er.Body))

	if er.Chutes.ChuteID != "chutes-model-uuid" {
		t.Errorf("ChuteID = %q, want chutes-model-uuid", er.Chutes.ChuteID)
	}
	if er.Chutes.InstanceID != "inst-1" {
		t.Errorf("InstanceID = %q, want inst-1", er.Chutes.InstanceID)
	}
	if er.Chutes.E2ENonce != "nonce-1" {
		t.Errorf("E2ENonce = %q, want nonce-1", er.Chutes.E2ENonce)
	}
	if er.Chutes.Session == nil {
		t.Fatal("expected non-nil Session")
	}
	if len(er.Body) == 0 {
		t.Fatal("encrypted payload is empty")
	}
	// Payload should be binary (ML-KEM-768 ct + ChaCha20 blob), not JSON.
	// Check length rather than first byte — the first byte is random and
	// happens to be '{' or '[' with probability ~1/128, causing flakes.
	// ML-KEM-768 ct = 1088 bytes, nonce = 12, tag = 16; minimum > 1100.
	if len(er.Body) < 1100 {
		t.Errorf("encrypted payload too short (%d bytes), expected binary blob ≥1100", len(er.Body))
	}
	if json.Valid(er.Body) {
		t.Error("encrypted payload is valid JSON, expected binary blob")
	}
}

func TestChutesE2EE_EncryptRequest_MissingInstanceID(t *testing.T) {
	pubB64 := mlkemModelPubB64(t)
	raw := chutesRaw(t, pubB64, "", "nonce-1")
	enc := chutes.NewE2EE()
	_, err := enc.EncryptRequest(chutesChatBody(t), raw, e2ee.EndpointChat)
	if err == nil {
		t.Fatal("expected error for missing InstanceID")
	}
	t.Logf("error (expected): %v", err)
}

func TestChutesE2EE_EncryptRequest_MissingE2ENonce(t *testing.T) {
	pubB64 := mlkemModelPubB64(t)
	raw := chutesRaw(t, pubB64, "inst-1", "")
	enc := chutes.NewE2EE()
	_, err := enc.EncryptRequest(chutesChatBody(t), raw, e2ee.EndpointChat)
	if err == nil {
		t.Fatal("expected error for missing E2ENonce")
	}
	t.Logf("error (expected): %v", err)
}

func TestChutesE2EE_EncryptRequest_MissingChuteID(t *testing.T) {
	pubB64 := mlkemModelPubB64(t)
	raw := &attestation.RawAttestation{
		SigningKey: pubB64,
		InstanceID: "inst-1",
		E2ENonce:   "nonce-1",
		ChuteID:    "",
	}
	enc := chutes.NewE2EE()
	_, err := enc.EncryptRequest(chutesChatBody(t), raw, e2ee.EndpointChat)
	if err == nil {
		t.Fatal("expected error for missing ChuteID")
	}
	t.Logf("error (expected): %v", err)
}

func TestChutesE2EE_EncryptRequest_InvalidSigningKey(t *testing.T) {
	raw := chutesRaw(t, "not-base64!", "inst-1", "nonce-1")
	enc := chutes.NewE2EE()
	_, err := enc.EncryptRequest(chutesChatBody(t), raw, e2ee.EndpointChat)
	if err == nil {
		t.Fatal("expected error for invalid signing key")
	}
	t.Logf("error (expected): %v", err)
}

func TestChutesE2EE_EncryptRequest_NonJSONBody(t *testing.T) {
	pubB64 := mlkemModelPubB64(t)
	raw := chutesRaw(t, pubB64, "inst-1", "nonce-1")
	enc := chutes.NewE2EE()
	// EncryptChatRequestChutes needs valid JSON to inject e2e_response_pk,
	// so a non-JSON body must fail.
	_, err := enc.EncryptRequest([]byte("not json"), raw, e2ee.EndpointChat)
	if err == nil {
		t.Fatal("expected error for non-JSON body")
	}
}
