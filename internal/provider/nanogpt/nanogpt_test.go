package nanogpt_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/nanogpt"
)

// validAttestationJSON is a structurally complete NanoGPT dstack attestation
// response matching the actual format returned by models like TEE/gemma-3-27b-it.
// Field names match the real API: signing_public_key (not signing_key),
// event_log as a JSON string (not array), quote duplicates intel_quote, etc.
const validAttestationJSON = `{
	"request_nonce": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
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
	if len(raw.SigningKey) != 130 || raw.SigningKey[:2] != "04" {
		t.Errorf("SigningKey should be 130 hex chars with 04 prefix, got len=%d prefix=%q", len(raw.SigningKey), raw.SigningKey[:2])
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
			"request_nonce":      capturedNonce,
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
		"request_nonce": "aabb",
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
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for empty JSON response")
	}
	t.Logf("error: %v", err)
	if !strings.Contains(err.Error(), "unsupported attestation format") {
		t.Errorf("error should mention unsupported format: %v", err)
	}
}

func TestAttester_FetchAttestation_TCBInfoAsString(t *testing.T) {
	// tcb_info as a JSON-encoded string (double-encoded), which some dstack
	// versions produce.
	jsonBody := `{
		"request_nonce": "aabb",
		"signing_public_key": "a6c0596e48e124f9b567e41fe3968d74d0fb845140e47abc11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff0011223344556677",
		"intel_quote": "dGVzdA==",
		"info": {
			"app_name": "dstack-nvidia-0.5.5",
			"device_id": "dev1",
			"tcb_info": "{\"app_compose\":\"version: 3\",\"compose_hash\":\"aabb\",\"os_image_hash\":\"os1\"}"
		}
	}`
	srv := makeAttestationServer(t, http.StatusOK, jsonBody)
	defer srv.Close()

	a := nanogpt.NewAttester(srv.URL, "key")
	raw, err := a.FetchAttestation(context.Background(), "TEE/test", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}
	if raw.AppCompose != "version: 3" {
		t.Errorf("AppCompose = %q, want %q (parsed from string-encoded tcb_info)", raw.AppCompose, "version: 3")
	}
	if raw.DeviceID != "dev1" {
		t.Errorf("DeviceID = %q, want %q", raw.DeviceID, "dev1")
	}
}

func TestAttester_FetchAttestation_EventLogAsArray(t *testing.T) {
	// event_log as a direct JSON array (not string-encoded).
	jsonBody := `{
		"request_nonce": "aabb",
		"signing_public_key": "a6c0596e48e124f9b567e41fe3968d74d0fb845140e47abc11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff0011223344556677",
		"intel_quote": "dGVzdA==",
		"event_log": [
			{"digest":"d6d8d853b6454f838d98c5573d6a098c","event":"","event_payload":"095464785461626c65","event_type":2147483659,"imr":0}
		]
	}`
	srv := makeAttestationServer(t, http.StatusOK, jsonBody)
	defer srv.Close()

	a := nanogpt.NewAttester(srv.URL, "key")
	raw, err := a.FetchAttestation(context.Background(), "TEE/test", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}
	if raw.EventLogCount != 1 {
		t.Errorf("EventLogCount = %d, want 1", raw.EventLogCount)
	}
	if len(raw.EventLog) != 1 {
		t.Errorf("len(EventLog) = %d, want 1", len(raw.EventLog))
	}
}

func TestParseAttestationResponse_UnsupportedFormats(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantFmt string
	}{
		{"tinfoil", `{"format":"https://tinfoil.sh/predicate/tdx-guest/v2","body":"H4s...","nonce":"aa"}`, "tinfoil"},
		{"chutes", `{"attestation_type":"chutes","nonce":"aa","all_attestations":[]}`, "chutes"},
		{"gateway", `{"gateway_attestation":{"intel_quote":"ab"},"model_attestations":[],"nonce":"aa"}`, "gateway"},
		{"unknown", `{"something":"else"}`, "unknown"},
		{"invalid", `not json`, "invalid"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := nanogpt.ParseAttestationResponse([]byte(tc.body))
			if err == nil {
				t.Fatal("expected error for unsupported format")
			}
			t.Logf("error: %v", err)
			wantMsg := fmt.Sprintf("unsupported attestation format %q", tc.wantFmt)
			if !strings.Contains(err.Error(), wantMsg) {
				t.Errorf("error %q should contain %q", err, wantMsg)
			}
		})
	}
}

func TestParseAttestationResponse_DstackAccepted(t *testing.T) {
	raw, err := nanogpt.ParseAttestationResponse([]byte(validAttestationJSON))
	if err != nil {
		t.Fatalf("dstack format should be accepted: %v", err)
	}
	if raw.IntelQuote == "" {
		t.Error("IntelQuote should be populated")
	}
}

func TestSupplyChainPolicy(t *testing.T) {
	p := nanogpt.SupplyChainPolicy()
	if p == nil {
		t.Fatal("SupplyChainPolicy() returned nil")
	}
	if len(p.Images) != 10 {
		t.Errorf("len(Images) = %d, want 10", len(p.Images))
	}
	for _, img := range p.Images {
		if !img.ModelTier {
			t.Errorf("image %q: ModelTier should be true", img.Repo)
		}
		if img.Provenance != attestation.ComposeBindingOnly {
			t.Errorf("image %q: Provenance = %v, want ComposeBindingOnly", img.Repo, img.Provenance)
		}
	}
	if p.HasGatewayImages() {
		t.Error("NanoGPT policy should have no gateway images")
	}
}
