package venice_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider/venice"
)

// validAttestationJSON is a structurally complete Venice attestation response
// covering all 20 fields. The signing_key and intel_quote are intentionally
// short placeholder values — real attestation verification happens in the
// attestation package.
const validAttestationJSON = `{
	"verified": true,
	"nonce": "aabbccddeeff00112233445566778899aabbccddeeff001122334455667788990000000000000000000000000000000000000000000000000000000000000000",
	"model": "e2ee-qwen3-5-122b-a10b",
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
	"server_verification": {"tdx": {"valid": true, "signatureValid": true, "certificateChainValid": true, "rootCaPinned": true, "attestationKeyMatch": true, "reportData": "", "measurements": {"mrtd": "", "mrconfigid": "", "mrowner": "", "mrownerconfig": "", "rtmr0": "", "rtmr1": "", "rtmr2": "", "rtmr3": "", "tdAttributes": "", "xfam": ""}, "crlCheck": {"checked": true, "revoked": false}}, "nvidia": {"valid": true, "signatureVerified": true, "certificateChainStatus": {"valid": true, "intermediatePinned": true, "leafCertExpiry": ""}}, "signingAddressBinding": {"bound": true, "reportDataAddress": ""}, "nonceBinding": {"bound": true, "method": "raw"}, "nvidiaNonceBinding": {"bound": true, "method": "nvidia_payload"}, "verifiedAt": "2026-03-22T13:41:02.018Z", "verificationDurationMs": 327},
	"model_name": "Qwen/Qwen3.5-122B-A10B",
	"upstream_model": "Qwen/Qwen3.5-122B-A10B",
	"signing_algo": "ecdsa",
	"tee_hardware": "intel-tdx",
	"nonce_source": "client",
	"candidates_available": 6,
	"candidates_evaluated": 1,
	"signing_public_key": "04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"request_nonce": "aabbccddeeff00112233445566778899aabbccddeeff001122334455667788990000000000000000000000000000000000000000000000000000000000000000"
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

	a := venice.NewAttester(srv.URL, "test-api-key")
	nonce := attestation.NewNonce()

	raw, err := a.FetchAttestation(context.Background(), "e2ee-qwen3-5-122b-a10b", nonce)
	if err != nil {
		t.Fatalf("FetchAttestation returned unexpected error: %v", err)
	}

	if !raw.Verified {
		t.Error("Verified = false, want true")
	}
	if raw.Model != "e2ee-qwen3-5-122b-a10b" {
		t.Errorf("Model = %q, want %q", raw.Model, "e2ee-qwen3-5-122b-a10b")
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
}

func TestAttester_FetchAttestation_ExtendedFields(t *testing.T) {
	srv := makeAttestationServer(t, http.StatusOK, validAttestationJSON)
	defer srv.Close()

	a := venice.NewAttester(srv.URL, "test-api-key")
	raw, err := a.FetchAttestation(context.Background(), "e2ee-qwen3-5-122b-a10b", attestation.NewNonce())
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
		{"UpstreamModel", raw.UpstreamModel, "Qwen/Qwen3.5-122B-A10B"},
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
	if raw.CandidatesAvail != 6 {
		t.Errorf("CandidatesAvail = %d, want 6", raw.CandidatesAvail)
	}
	if raw.CandidatesEval != 1 {
		t.Errorf("CandidatesEval = %d, want 1", raw.CandidatesEval)
	}
}

func TestAttester_FetchAttestation_EchoesNonce(t *testing.T) {
	// The server captures the nonce query parameter and echoes it back.
	var capturedNonce string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedNonce = r.URL.Query().Get("nonce")
		resp := map[string]any{
			"verified":       true,
			"nonce":          capturedNonce,
			"model":          "e2ee-test",
			"tee_provider":   "TDX",
			"signing_key":    "04" + "aa" + "bb" + "cc", // placeholder
			"intel_quote":    "dGVzdA==",
			"nvidia_payload": "",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	a := venice.NewAttester(srv.URL, "key")
	nonce := attestation.NewNonce()

	raw, err := a.FetchAttestation(context.Background(), "e2ee-test", nonce)
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

	a := venice.NewAttester(srv.URL, "my-secret-key")
	_, err := a.FetchAttestation(context.Background(), "e2ee-model", attestation.NewNonce())
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

	a := venice.NewAttester(srv.URL, "key")
	_, err := a.FetchAttestation(context.Background(), "e2ee-qwen3-5-122b-a10b", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if capturedModel != "e2ee-qwen3-5-122b-a10b" {
		t.Errorf("model query param = %q, want %q", capturedModel, "e2ee-qwen3-5-122b-a10b")
	}
}

func TestAttester_FetchAttestation_HTTP500(t *testing.T) {
	srv := makeAttestationServer(t, http.StatusInternalServerError, `{"error":"internal server error"}`)
	defer srv.Close()

	a := venice.NewAttester(srv.URL, "key")
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

func TestAttester_FetchAttestation_HTTP401(t *testing.T) {
	srv := makeAttestationServer(t, http.StatusUnauthorized, `{"error":"unauthorized"}`)
	defer srv.Close()

	a := venice.NewAttester(srv.URL, "bad-key")
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for HTTP 401, got nil")
	}
}

func TestAttester_FetchAttestation_InvalidJSON(t *testing.T) {
	srv := makeAttestationServer(t, http.StatusOK, `not json at all`)
	defer srv.Close()

	a := venice.NewAttester(srv.URL, "key")
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestAttester_FetchAttestation_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block indefinitely — the cancelled context should abort before this matters.
		<-r.Context().Done()
	}))
	defer srv.Close()

	a := venice.NewAttester(srv.URL, "key")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := a.FetchAttestation(ctx, "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestAttester_FetchAttestation_InvalidBaseURL(t *testing.T) {
	// A base URL with a control character that makes url.Parse fail.
	a := venice.NewAttester("://bad url\x00", "key")
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for invalid base URL, got nil")
	}
}

// --- Preparer tests ---

func TestPreparer_PrepareRequest_SetsHeaders(t *testing.T) {
	p := venice.NewPreparer("test-api-key")

	// Generate two distinct sessions: one for the client, one to supply a real
	// model public key (must be a valid secp256k1 point).
	clientSession, err := e2ee.NewVeniceSession()
	if err != nil {
		t.Fatalf("NewSession (client): %v", err)
	}
	modelSession, err := e2ee.NewVeniceSession()
	if err != nil {
		t.Fatalf("NewSession (model): %v", err)
	}
	modelKey := modelSession.PublicKeyHex // guaranteed valid secp256k1 point

	if err := clientSession.SetModelKey(modelKey); err != nil {
		t.Fatalf("SetModelKey: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, "https://api.venice.ai/api/v1/chat/completions", http.NoBody)
	if err := p.PrepareRequest(req, clientSession); err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}

	if got := req.Header.Get("X-Venice-Tee-Client-Pub-Key"); got != clientSession.PublicKeyHex {
		t.Errorf("X-Venice-TEE-Client-Pub-Key = %q, want %q", got, clientSession.PublicKeyHex)
	}
	if got := req.Header.Get("X-Venice-Tee-Model-Pub-Key"); got != modelKey {
		t.Errorf("X-Venice-TEE-Model-Pub-Key = %q, want %q", got, modelKey)
	}
	if got := req.Header.Get("X-Venice-Tee-Signing-Algo"); got != "ecdsa" {
		t.Errorf("X-Venice-TEE-Signing-Algo = %q, want %q", got, "ecdsa")
	}
	if got := req.Header.Get("Authorization"); got != "Bearer test-api-key" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer test-api-key")
	}
}

func TestPreparer_PrepareRequest_EmptyModelKey(t *testing.T) {
	p := venice.NewPreparer("key")
	session, err := e2ee.NewVeniceSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	// Do NOT call SetModelKey — ModelKeyHex is empty.

	req, _ := http.NewRequest(http.MethodPost, "https://api.venice.ai/", http.NoBody)
	err = p.PrepareRequest(req, session)
	if err == nil {
		t.Fatal("expected error for empty ModelKeyHex, got nil")
	}
}

func TestPreparer_PrepareRequest_EmptyPublicKeyHex(t *testing.T) {
	p := venice.NewPreparer("key")
	// Construct a session with ModelKeyHex set but PublicKeyHex empty.
	// This shouldn't happen in normal usage (NewSession always sets PublicKeyHex),
	// but we guard against it defensively.
	modelSession, err := e2ee.NewVeniceSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	session := &e2ee.Session{
		ModelKeyHex:  modelSession.PublicKeyHex, // valid key
		PublicKeyHex: "",                        // deliberately empty
	}

	req, _ := http.NewRequest(http.MethodPost, "https://api.venice.ai/", http.NoBody)
	err = p.PrepareRequest(req, session)
	if err == nil {
		t.Fatal("expected error for empty PublicKeyHex, got nil")
	}
}
