package chutes_test

import (
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
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
	encPayload, decryptor, meta, err := enc.EncryptRequest(chutesChatBody(t), raw, "/v1/chat/completions")
	if err != nil {
		t.Fatalf("EncryptRequest: %v", err)
	}

	if decryptor != nil {
		t.Error("expected nil Decryptor for Chutes (uses ChutesE2EE instead)")
	}
	if meta == nil {
		t.Fatal("expected non-nil ChutesE2EE")
	}
	defer meta.Session.Zero()

	t.Logf("ChuteID=%q InstanceID=%q E2ENonce=%q payload_len=%d",
		meta.ChuteID, meta.InstanceID, meta.E2ENonce, len(encPayload))

	if meta.ChuteID != "chutes-model-uuid" {
		t.Errorf("ChuteID = %q, want chutes-model-uuid", meta.ChuteID)
	}
	if meta.InstanceID != "inst-1" {
		t.Errorf("InstanceID = %q, want inst-1", meta.InstanceID)
	}
	if meta.E2ENonce != "nonce-1" {
		t.Errorf("E2ENonce = %q, want nonce-1", meta.E2ENonce)
	}
	if meta.Session == nil {
		t.Fatal("expected non-nil Session")
	}
	if len(encPayload) == 0 {
		t.Fatal("encrypted payload is empty")
	}
	// Payload should be binary, not JSON.
	if encPayload[0] == '{' || encPayload[0] == '[' {
		t.Error("encrypted payload appears to be JSON, expected binary blob")
	}
}

func TestChutesE2EE_EncryptRequest_MissingInstanceID(t *testing.T) {
	pubB64 := mlkemModelPubB64(t)
	raw := chutesRaw(t, pubB64, "", "nonce-1")
	enc := chutes.NewE2EE()
	_, _, _, err := enc.EncryptRequest(chutesChatBody(t), raw, "/v1/chat/completions")
	if err == nil {
		t.Fatal("expected error for missing InstanceID")
	}
	t.Logf("error (expected): %v", err)
}

func TestChutesE2EE_EncryptRequest_MissingE2ENonce(t *testing.T) {
	pubB64 := mlkemModelPubB64(t)
	raw := chutesRaw(t, pubB64, "inst-1", "")
	enc := chutes.NewE2EE()
	_, _, _, err := enc.EncryptRequest(chutesChatBody(t), raw, "/v1/chat/completions")
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
	_, _, _, err := enc.EncryptRequest(chutesChatBody(t), raw, "/v1/chat/completions")
	if err == nil {
		t.Fatal("expected error for missing ChuteID")
	}
	t.Logf("error (expected): %v", err)
}

func TestChutesE2EE_EncryptRequest_InvalidSigningKey(t *testing.T) {
	raw := chutesRaw(t, "not-base64!", "inst-1", "nonce-1")
	enc := chutes.NewE2EE()
	_, _, _, err := enc.EncryptRequest(chutesChatBody(t), raw, "/v1/chat/completions")
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
	_, _, _, err := enc.EncryptRequest([]byte("not json"), raw, "/v1/chat/completions")
	if err == nil {
		t.Fatal("expected error for non-JSON body")
	}
}
