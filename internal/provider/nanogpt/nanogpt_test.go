package nanogpt_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/nanogpt"
)

// validAttestationJSON is a structurally complete NanoGPT dstack attestation
// response matching the actual format returned by models like TEE/gemma-3-27b-it.
// Field names match the real API: signing_public_key (not signing_key),
// event_log as a JSON string (not array), quote duplicates intel_quote, etc.
const validAttestationJSON = `{
	"nonce": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
	"request_nonce": "1122334455667788aabbccddeeff00111122334455667788aabbccddeeff0011",
	"signing_public_key": "a6c0596e48e124f9b567e41fe3968d74d0fb845140e47abc11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff0011223344556677",
	"signing_address": "0x96a98Ca1F41a57c1911f08acAb8fdcE3C26c9E79",
	"signing_algo": "ecdsa",
	"intel_quote": "dGVzdHF1b3Rl",
	"quote": "dGVzdHF1b3Rl",
	"nvidia_payload": "eyJhbGciOiJSUzI1NiJ9.test.payload",
	"event_log": "[{\"digest\":\"d6d8d853b6454f838d98c5573d6a098c\",\"event\":\"\",\"event_payload\":\"095464785461626c65\",\"event_type\":2147483659,\"imr\":0},{\"digest\":\"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\",\"event\":\"\",\"event_payload\":\"0a1b2c3d4e5f\",\"event_type\":2147483649,\"imr\":1}]",
	"info": {
		"app_cert": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		"app_id": "test-app-id",
		"app_name": "dstack-nvidia-0.5.5",
		"compose_hash": "242a6272abcdef01",
		"device_id": "aa781567bbccddee",
		"instance_id": "inst-12345678",
		"key_provider_info": "kms",
		"mr_aggregated": "aabbccdd",
		"os_image_hash": "9b69bb16aabbccdd",
		"tcb_info": {},
		"vm_config": "tdx-vm"
	},
	"vm_config": "{\"cpu\":8,\"mem\":32768}",
	"all_attestations": [{}]
}`

// makeAttestationServer starts an httptest server that serves body as the
// attestation response with the given HTTP status code.
func makeAttestationServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestAttester_FetchAttestation_Success(t *testing.T) {
	srv := makeAttestationServer(t, http.StatusOK, validAttestationJSON)
	defer srv.Close()

	a := nanogpt.NewAttester(srv.URL, "test-api-key")
	nonce := attestation.NewNonce()

	raw, err := a.FetchAttestation(context.Background(), "TEE/llama-3.3-70b-instruct", nonce)
	if err != nil {
		t.Fatalf("FetchAttestation returned unexpected error: %v", err)
	}

	if raw.IntelQuote == "" {
		t.Error("IntelQuote is empty, want non-empty")
	}
	if raw.NvidiaPayload == "" {
		t.Error("NvidiaPayload is empty, want non-empty")
	}
	if raw.SigningKey == "" {
		t.Error("SigningKey is empty, want non-empty (mapped from signing_public_key)")
	}
	if raw.SigningAddress != "0x96a98Ca1F41a57c1911f08acAb8fdcE3C26c9E79" {
		t.Errorf("SigningAddress = %q, want %q", raw.SigningAddress, "0x96a98Ca1F41a57c1911f08acAb8fdcE3C26c9E79")
	}
	if raw.RawBody == nil {
		t.Error("RawBody is nil, want non-nil")
	}
}

func TestAttester_FetchAttestation_ExtendedFields(t *testing.T) {
	srv := makeAttestationServer(t, http.StatusOK, validAttestationJSON)
	defer srv.Close()

	a := nanogpt.NewAttester(srv.URL, "test-api-key")
	raw, err := a.FetchAttestation(context.Background(), "TEE/llama-3.3-70b-instruct", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	checks := []struct {
		name string
		got  string
		want string
	}{
		{"SigningAlgo", raw.SigningAlgo, "ecdsa"},
		{"AppName", raw.AppName, "dstack-nvidia-0.5.5"},
		{"ComposeHash", raw.ComposeHash, "242a6272abcdef01"},
		{"OSImageHash", raw.OSImageHash, "9b69bb16aabbccdd"},
		{"DeviceID", raw.DeviceID, "aa781567bbccddee"},
	}
	for _, tc := range checks {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
	if raw.EventLogCount != 2 {
		t.Errorf("EventLogCount = %d, want 2", raw.EventLogCount)
	}
	if len(raw.EventLog) != 2 {
		t.Errorf("len(EventLog) = %d, want 2", len(raw.EventLog))
	}
}

func TestAttester_FetchAttestation_EchoesNonce(t *testing.T) {
	var capturedNonce string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedNonce = r.URL.Query().Get("nonce")
		resp := map[string]any{
			"nonce":              capturedNonce,
			"signing_public_key": "a6c0596e48e124f9aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011",
			"signing_address":    "0xdeadbeef",
			"intel_quote":        "dGVzdA==",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	a := nanogpt.NewAttester(srv.URL, "key")
	nonce := attestation.NewNonce()

	raw, err := a.FetchAttestation(context.Background(), "TEE/test", nonce)
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if capturedNonce != nonce.Hex() {
		t.Errorf("server received nonce %q, want %q", capturedNonce, nonce.Hex())
	}
	if raw.Nonce != nonce.Hex() {
		t.Errorf("RawAttestation.Nonce = %q, want %q", raw.Nonce, nonce.Hex())
	}
}

func TestAttester_FetchAttestation_SendsAuthHeader(t *testing.T) {
	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validAttestationJSON))
	}))
	defer srv.Close()

	a := nanogpt.NewAttester(srv.URL, "my-secret-key")
	_, err := a.FetchAttestation(context.Background(), "TEE/model", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	want := "Bearer my-secret-key"
	if capturedAuth != want {
		t.Errorf("Authorization header = %q, want %q", capturedAuth, want)
	}
}

func TestAttester_FetchAttestation_SendsModelParam(t *testing.T) {
	var capturedModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedModel = r.URL.Query().Get("model")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validAttestationJSON))
	}))
	defer srv.Close()

	a := nanogpt.NewAttester(srv.URL, "key")
	_, err := a.FetchAttestation(context.Background(), "TEE/llama-3.3-70b-instruct", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if capturedModel != "TEE/llama-3.3-70b-instruct" {
		t.Errorf("model query param = %q, want %q", capturedModel, "TEE/llama-3.3-70b-instruct")
	}
}

func TestAttester_FetchAttestation_HTTP500(t *testing.T) {
	srv := makeAttestationServer(t, http.StatusInternalServerError, `{"error":"internal server error"}`)
	defer srv.Close()

	a := nanogpt.NewAttester(srv.URL, "key")
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

func TestAttester_FetchAttestation_HTTP401(t *testing.T) {
	srv := makeAttestationServer(t, http.StatusUnauthorized, `{"error":"unauthorized"}`)
	defer srv.Close()

	a := nanogpt.NewAttester(srv.URL, "bad-key")
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for HTTP 401, got nil")
	}
}

func TestAttester_FetchAttestation_InvalidJSON(t *testing.T) {
	srv := makeAttestationServer(t, http.StatusOK, `not json at all`)
	defer srv.Close()

	a := nanogpt.NewAttester(srv.URL, "key")
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestAttester_FetchAttestation_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	a := nanogpt.NewAttester(srv.URL, "key")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := a.FetchAttestation(ctx, "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestAttester_FetchAttestation_InvalidBaseURL(t *testing.T) {
	a := nanogpt.NewAttester("://bad url\x00", "key")
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for invalid base URL, got nil")
	}
}

func TestAttester_FetchAttestation_UnknownFields(t *testing.T) {
	// Add an extra field not in the response struct. jsonstrict.UnmarshalWarn
	// should log a warning but not return an error.
	jsonWithExtra := `{
		"nonce": "aabb",
		"signing_public_key": "a6c0596e48e124f9",
		"intel_quote": "dGVzdA==",
		"unknown_extra_field": "should not cause error"
	}`
	srv := makeAttestationServer(t, http.StatusOK, jsonWithExtra)
	defer srv.Close()

	a := nanogpt.NewAttester(srv.URL, "key")
	raw, err := a.FetchAttestation(context.Background(), "TEE/test", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation with unknown field returned error: %v", err)
	}
	if raw.Nonce != "aabb" {
		t.Errorf("Nonce = %q, want %q", raw.Nonce, "aabb")
	}
}

func TestAttester_FetchAttestation_EmptyResponse(t *testing.T) {
	srv := makeAttestationServer(t, http.StatusOK, `{}`)
	defer srv.Close()

	a := nanogpt.NewAttester(srv.URL, "key")
	raw, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation with empty body returned error: %v", err)
	}
	if raw.Nonce != "" {
		t.Errorf("Nonce = %q for empty response, want empty", raw.Nonce)
	}
	if raw.SigningKey != "" {
		t.Errorf("SigningKey = %q for empty response, want empty", raw.SigningKey)
	}
}
