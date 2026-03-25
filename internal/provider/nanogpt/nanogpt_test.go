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

// validAttestationJSON is a structurally complete NanoGPT attestation response
// covering all fields. The signing_key and intel_quote are intentionally short
// placeholder values -- real attestation verification happens in the attestation
// package.
const validAttestationJSON = `{
	"verified": true,
	"nonce": "aabbccddeeff00112233445566778899aabbccddeeff001122334455667788990000000000000000000000000000000000000000000000000000000000000000",
	"model": "TEE/llama-3.3-70b-instruct",
	"tee_provider": "TDX+NVIDIA",
	"signing_key": "04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"signing_address": "0xdeadbeef",
	"intel_quote": "dGVzdHF1b3Rl",
	"nvidia_payload": "eyJhbGciOiJSUzI1NiJ9.test.payload",
	"event_log": [
		{"digest": "d6d8d853b6454f838d98c5573d6a098c", "event": "", "event_payload": "095464785461626c65", "event_type": 2147483659, "imr": 0},
		{"digest": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", "event": "", "event_payload": "0a1b2c3d4e5f", "event_type": 2147483649, "imr": 1}
	],
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
	"upstream_model": "meta-llama/Llama-3.3-70B-Instruct",
	"signing_algo": "ecdsa",
	"tee_hardware": "intel-tdx",
	"nonce_source": "client",
	"candidates_available": 4,
	"candidates_evaluated": 1
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

	if !raw.Verified {
		t.Error("Verified = false, want true")
	}
	if raw.Model != "TEE/llama-3.3-70b-instruct" {
		t.Errorf("Model = %q, want %q", raw.Model, "TEE/llama-3.3-70b-instruct")
	}
	if raw.TEEProvider != "TDX+NVIDIA" {
		t.Errorf("TEEProvider = %q, want %q", raw.TEEProvider, "TDX+NVIDIA")
	}
	if raw.IntelQuote == "" {
		t.Error("IntelQuote is empty, want non-empty")
	}
	if raw.NvidiaPayload == "" {
		t.Error("NvidiaPayload is empty, want non-empty")
	}
	if raw.SigningKey == "" {
		t.Error("SigningKey is empty, want non-empty")
	}
	if raw.SigningAddress != "0xdeadbeef" {
		t.Errorf("SigningAddress = %q, want %q", raw.SigningAddress, "0xdeadbeef")
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
		{"TEEHardware", raw.TEEHardware, "intel-tdx"},
		{"SigningAlgo", raw.SigningAlgo, "ecdsa"},
		{"UpstreamModel", raw.UpstreamModel, "meta-llama/Llama-3.3-70B-Instruct"},
		{"AppName", raw.AppName, "dstack-nvidia-0.5.5"},
		{"ComposeHash", raw.ComposeHash, "242a6272abcdef01"},
		{"OSImageHash", raw.OSImageHash, "9b69bb16aabbccdd"},
		{"DeviceID", raw.DeviceID, "aa781567bbccddee"},
		{"NonceSource", raw.NonceSource, "client"},
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
	if raw.CandidatesAvail != 4 {
		t.Errorf("CandidatesAvail = %d, want 4", raw.CandidatesAvail)
	}
	if raw.CandidatesEval != 1 {
		t.Errorf("CandidatesEval = %d, want 1", raw.CandidatesEval)
	}
}

func TestAttester_FetchAttestation_EchoesNonce(t *testing.T) {
	var capturedNonce string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedNonce = r.URL.Query().Get("nonce")
		resp := map[string]any{
			"verified":     true,
			"nonce":        capturedNonce,
			"model":        "TEE/test",
			"tee_provider": "TDX",
			"signing_key":  "04aabbcc",
			"intel_quote":  "dGVzdA==",
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
	t.Logf("HTTP 500 error: %v", err)
}

func TestAttester_FetchAttestation_HTTP401(t *testing.T) {
	srv := makeAttestationServer(t, http.StatusUnauthorized, `{"error":"unauthorized"}`)
	defer srv.Close()

	a := nanogpt.NewAttester(srv.URL, "bad-key")
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for HTTP 401, got nil")
	}
	t.Logf("HTTP 401 error: %v", err)
}

func TestAttester_FetchAttestation_InvalidJSON(t *testing.T) {
	srv := makeAttestationServer(t, http.StatusOK, `not json at all`)
	defer srv.Close()

	a := nanogpt.NewAttester(srv.URL, "key")
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	t.Logf("invalid JSON error: %v", err)
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
	t.Logf("cancelled context error: %v", err)
}

func TestAttester_FetchAttestation_InvalidBaseURL(t *testing.T) {
	a := nanogpt.NewAttester("://bad url\x00", "key")
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for invalid base URL, got nil")
	}
	t.Logf("invalid base URL error: %v", err)
}

func TestAttester_FetchAttestation_UnknownFields(t *testing.T) {
	// Add an extra field not in the response struct. jsonstrict.UnmarshalWarn
	// should log a warning but not return an error.
	jsonWithExtra := `{
		"verified": true,
		"nonce": "aabb",
		"model": "TEE/test",
		"tee_provider": "TDX",
		"signing_key": "04aabbcc",
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
	if raw.Model != "TEE/test" {
		t.Errorf("Model = %q, want %q", raw.Model, "TEE/test")
	}
	t.Log("unknown field parsed without error (warning expected in logs)")
}

func TestAttester_FetchAttestation_EmptyResponse(t *testing.T) {
	srv := makeAttestationServer(t, http.StatusOK, `{}`)
	defer srv.Close()

	a := nanogpt.NewAttester(srv.URL, "key")
	raw, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation with empty body returned error: %v", err)
	}
	if raw.Verified {
		t.Error("Verified = true for empty response, want false")
	}
	if raw.Model != "" {
		t.Errorf("Model = %q for empty response, want empty", raw.Model)
	}
	t.Log("empty response parsed without panic")
}
