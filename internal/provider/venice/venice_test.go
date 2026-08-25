package venice_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
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

func TestParseAttestationResponse_EventLogString(t *testing.T) {
	// Venice sometimes returns event_log as a JSON-encoded string instead of
	// a direct array. Test that eventLogFlexible handles this.
	eventLogArray := `[{"digest":"d6d8d853","event":"","event_payload":"09","event_type":2147483659,"imr":0}]`
	body := strings.Replace(validAttestationJSON,
		`"event_log": [`+"\n"+
			"\t\t"+`{"digest": "d6d8d853b6454f838d98c5573d6a098c", "event": "", "event_payload": "095464785461626c65", "event_type": 2147483659, "imr": 0},`+"\n"+
			"\t\t"+`{"digest": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", "event": "", "event_payload": "0a1b2c3d4e5f", "event_type": 2147483649, "imr": 1}`+"\n"+
			"\t"+`]`,
		`"event_log": `+mustMarshal(t, eventLogArray),
		1)

	raw, err := venice.ParseAttestationResponse(context.Background(), []byte(body))
	if err != nil {
		t.Fatalf("ParseAttestationResponse: %v", err)
	}
	t.Logf("EventLogCount = %d", raw.EventLogCount)
	if raw.EventLogCount != 1 {
		t.Errorf("EventLogCount = %d, want 1", raw.EventLogCount)
	}
}

func TestParseAttestationResponse_EventLogInvalid(t *testing.T) {
	// event_log that is neither an array nor a string should error.
	body := strings.Replace(validAttestationJSON,
		`"event_log": [`+"\n"+
			"\t\t"+`{"digest": "d6d8d853b6454f838d98c5573d6a098c", "event": "", "event_payload": "095464785461626c65", "event_type": 2147483659, "imr": 0},`+"\n"+
			"\t\t"+`{"digest": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", "event": "", "event_payload": "0a1b2c3d4e5f", "event_type": 2147483649, "imr": 1}`+"\n"+
			"\t"+`]`,
		`"event_log": 42`,
		1)

	_, err := venice.ParseAttestationResponse(context.Background(), []byte(body))
	if err == nil {
		t.Fatal("expected error for numeric event_log, got nil")
	}
	t.Logf("expected error: %v", err)
}

// mustMarshal JSON-encodes v, failing the test on error.
func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(b)
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

// --- ACI/1 format tests ---
//
// validACI1JSON is synthetic — it matches the observed ACI/1 structure but
// is not a captured live response. Captured fixtures and end-to-end ACI/1
// replay coverage live in internal/integration.

const validACI1JSON = `{
	"api_version": "aci/1",
	"workload_id": "sha256:3def476b0000000000000000000000000000000000000000000000000000abcd",
	"workload_keyset_digest": "sha256:abcdef0123456789",
	"attestation": {
		"vendor": "private-ai-gateway-dev",
		"tee_type": "tdx",
		"workload_keyset": {
			"workload_identity": {
				"public_key": {"algo": "ecdsa-secp256k1", "public_key": "04aabb"},
				"subject": null
			},
			"keyset_epoch": {"version": 1, "not_after": 18446744073709552000},
			"receipt_signing_keys": [{"key_id": "receipt-v1", "algo": "ecdsa-secp256k1", "public_key": "04ccdd"}],
			"e2ee_public_keys": [{"key_id": "e2ee-v1", "algo": "secp256k1-aes-256-gcm", "public_key": "04eeff"}],
			"tls_public_keys": [{"domain": "test.example.com", "spki_sha256": "aabbccdd"}]
		},
		"report_data": "0000000000000000000000000000000000000000000000000000000000000000",
		"keyset_endorsement": {"algo": "ecdsa-secp256k1", "value": "aabbccdd"},
		"source_provenance": {
			"repo_url": "https://github.com/Dstack-TEE/private-ai-gateway.git",
			"repo_commit": "1b43f76e43c2459856faebe9cd97d8e01cb0df0c",
			"image_digest": null,
			"image_provenance": null
		},
		"freshness": {"fetched_at": 1782772332, "stale_after": 1782775932},
		"evidence": {
			"quote": "dGVzdHF1b3Rl",
			"quote_report_data": "79a5061e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000aa",
			"event_log": [
				{"digest": "d6d8d853b6454f838d98c5573d6a098c", "event": "", "event_payload": "095464785461626c65", "event_type": 2147483659, "imr": 0},
				{"digest": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", "event": "", "event_payload": "0a1b2c3d4e5f", "event_type": 2147483649, "imr": 1}
			],
			"vm_config": "tdx-vm-aci",
			"key_custody": {"provider": "dstack-kms", "keys": [{"role": "identity", "path": "aci/identity/v1", "purpose": "aci.identity.v1", "algo": "ecdsa-secp256k1", "public_key": "04aabb", "signature_chain": ["aabb", "ccdd"]}]},
			"downstream_tls_binding": {"domain": "test.example.com", "spki_sha256": "aabbccdd"}
		}
	},
	"service_capabilities": {"supported_e2ee_versions": ["2"]},
	"intel_quote": "dGVzdHF1b3Rl",
	"nvidia_payload": "eyJhbGciOiJSUzI1NiJ9.test.payload",
	"signing_public_key": "04943cea0baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"signing_algo": "ecdsa",
	"signing_address": "0x79a5061ebbbbbbbb",
	"verified": true,
	"nonce": "aabbccddeeff00112233445566778899",
	"model": "e2ee-glm-5-2-p",
	"tee_provider": "phala",
	"tee_hardware": "intel-tdx",
	"nonce_source": "client",
	"upstream_model": "z-ai/glm-5.2",
	"server_verification": {"tdx": {"valid": true, "signatureValid": true, "certificateChainValid": true, "rootCaPinned": true, "attestationKeyMatch": true, "reportData": "", "measurements": {"mrtd": "", "mrconfigid": "", "mrowner": "", "mrownerconfig": "", "rtmr0": "", "rtmr1": "", "rtmr2": "", "rtmr3": "", "tdAttributes": "", "xfam": ""}, "crlCheck": {"checked": true, "revoked": false}}, "nvidia": {"valid": true, "signatureVerified": true, "certificateChainStatus": {"valid": true, "intermediatePinned": true, "leafCertExpiry": ""}}, "signingAddressBinding": {"bound": true, "reportDataAddress": ""}, "nonceBinding": {"bound": true, "method": "raw"}, "nvidiaNonceBinding": {"bound": true, "method": "nvidia_payload"}, "verifiedAt": "2026-06-29T01:00:00.000Z", "verificationDurationMs": 300},
	"candidates_evaluated": 1,
	"candidates_available": 3
}`

func TestParseACI1_Success(t *testing.T) {
	raw, err := venice.ParseAttestationResponse(context.Background(), []byte(validACI1JSON))
	if err != nil {
		t.Fatalf("ParseAttestationResponse(ACI/1): %v", err)
	}

	checks := []struct {
		name string
		got  string
		want string
	}{
		{"BackendFormat", string(raw.BackendFormat), string(attestation.FormatACI1)},
		{"TEEProvider", raw.TEEProvider, "phala"},
		{"SigningKey", raw.SigningKey, "04943cea0baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"SigningAddress", raw.SigningAddress, "0x79a5061ebbbbbbbb"},
		{"IntelQuote", raw.IntelQuote, "dGVzdHF1b3Rl"},
		{"SigningAlgo", raw.SigningAlgo, "ecdsa"},
		{"Nonce", raw.Nonce, "aabbccddeeff00112233445566778899"},
		{"Model", raw.Model, "e2ee-glm-5-2-p"},
		{"TEEHardware", raw.TEEHardware, "intel-tdx"},
		{"NonceSource", raw.NonceSource, "client"},
		{"UpstreamModel", raw.UpstreamModel, "z-ai/glm-5.2"},
	}
	for _, tc := range checks {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
	if !raw.Verified {
		t.Error("Verified = false, want true")
	}
	if raw.NvidiaPayload == "" {
		t.Error("NvidiaPayload is empty, want non-empty")
	}
	if raw.CandidatesAvail != 3 {
		t.Errorf("CandidatesAvail = %d, want 3", raw.CandidatesAvail)
	}
	if raw.CandidatesEval != 1 {
		t.Errorf("CandidatesEval = %d, want 1", raw.CandidatesEval)
	}
	if raw.ACISourceRepoURL != "https://github.com/Dstack-TEE/private-ai-gateway.git" {
		t.Errorf("ACISourceRepoURL = %q, want the private-ai-gateway repo", raw.ACISourceRepoURL)
	}
	if raw.ACIWorkloadKeyset == nil {
		t.Error("ACIWorkloadKeyset is nil, want populated for keyset endorsement verification")
	}
}

func TestParseACI1_EventLog(t *testing.T) {
	raw, err := venice.ParseAttestationResponse(context.Background(), []byte(validACI1JSON))
	if err != nil {
		t.Fatalf("ParseAttestationResponse(ACI/1): %v", err)
	}

	if raw.EventLogCount != 2 {
		t.Errorf("EventLogCount = %d, want 2", raw.EventLogCount)
	}
	if len(raw.EventLog) != 2 {
		t.Fatalf("len(EventLog) = %d, want 2", len(raw.EventLog))
	}
	if raw.EventLog[0].IMR != 0 {
		t.Errorf("EventLog[0].IMR = %d, want 0", raw.EventLog[0].IMR)
	}
	if raw.EventLog[1].IMR != 1 {
		t.Errorf("EventLog[1].IMR = %d, want 1", raw.EventLog[1].IMR)
	}
}

func TestParseACI1_NoComposeFields(t *testing.T) {
	raw, err := venice.ParseAttestationResponse(context.Background(), []byte(validACI1JSON))
	if err != nil {
		t.Fatalf("ParseAttestationResponse(ACI/1): %v", err)
	}

	// ACI/1 has no compose manifest — compose-related fields should be
	// empty, so the compose-based supply chain factors evaluate to Fail
	// (not NotApplicable) rather than being silently skipped.
	if raw.AppCompose != "" {
		t.Errorf("AppCompose = %q, want empty for ACI/1", raw.AppCompose)
	}
	if raw.ComposeHash != "" {
		t.Errorf("ComposeHash = %q, want empty for ACI/1", raw.ComposeHash)
	}
	if raw.AppName != "" {
		t.Errorf("AppName = %q, want empty for ACI/1", raw.AppName)
	}
}

func TestParseACI1_InvalidJSON(t *testing.T) {
	body := `{"api_version": "aci/1", "attestation": {invalid}`
	_, err := venice.ParseAttestationResponse(context.Background(), []byte(body))
	if err == nil {
		t.Fatal("expected error for invalid ACI/1 JSON, got nil")
	}
}

func TestParseACI1_UnknownAPIVersion(t *testing.T) {
	// A recognized-looking but unsupported api_version must fail loudly, not
	// silently fall back to dstack parsing (the body also has intel_quote).
	body := `{"api_version": "aci/2", "intel_quote": "dGVzdHF1b3Rl"}`
	_, err := venice.ParseAttestationResponse(context.Background(), []byte(body))
	if err == nil {
		t.Fatal("expected error for unrecognized api_version, got nil")
	}
}

func TestParseDstack_StillWorks(t *testing.T) {
	// Regression: dstack format must still parse correctly after adding ACI/1 detection.
	raw, err := venice.ParseAttestationResponse(context.Background(), []byte(validAttestationJSON))
	if err != nil {
		t.Fatalf("ParseAttestationResponse(dstack): %v", err)
	}

	if raw.BackendFormat != attestation.FormatDstack {
		t.Errorf("BackendFormat = %q, want %q", raw.BackendFormat, attestation.FormatDstack)
	}
	if !raw.Verified {
		t.Error("Verified = false, want true")
	}
	if raw.Model != "e2ee-qwen3-5-122b-a10b" {
		t.Errorf("Model = %q, want %q", raw.Model, "e2ee-qwen3-5-122b-a10b")
	}
}

// --- Preparer tests ---

func TestPreparer_PrepareRequest_SetsHeaders(t *testing.T) {
	p := venice.NewPreparer("test-api-key")

	e2eeHeaders := make(http.Header)
	e2eeHeaders.Set("X-Venice-Tee-Client-Pub-Key", "04abcdef")
	e2eeHeaders.Set("X-Venice-Tee-Model-Pub-Key", "04123456")
	e2eeHeaders.Set("X-Venice-Tee-Signing-Algo", "ecdsa")

	req, _ := http.NewRequest(http.MethodPost, "https://api.venice.ai/api/v1/chat/completions", http.NoBody)
	if err := p.PrepareRequest(req, e2eeHeaders, nil, false, ""); err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}

	if got := req.Header.Get("X-Venice-Tee-Client-Pub-Key"); got != "04abcdef" {
		t.Errorf("X-Venice-TEE-Client-Pub-Key = %q, want %q", got, "04abcdef")
	}
	if got := req.Header.Get("X-Venice-Tee-Model-Pub-Key"); got != "04123456" {
		t.Errorf("X-Venice-TEE-Model-Pub-Key = %q, want %q", got, "04123456")
	}
	if got := req.Header.Get("X-Venice-Tee-Signing-Algo"); got != "ecdsa" {
		t.Errorf("X-Venice-TEE-Signing-Algo = %q, want %q", got, "ecdsa")
	}
	if got := req.Header.Get("Authorization"); got != "Bearer test-api-key" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer test-api-key")
	}
}

func TestPreparer_PrepareRequest_NilHeaders(t *testing.T) {
	p := venice.NewPreparer("test-api-key")

	req, _ := http.NewRequest(http.MethodPost, "https://api.venice.ai/", http.NoBody)
	if err := p.PrepareRequest(req, nil, nil, false, ""); err != nil {
		t.Fatalf("PrepareRequest with nil headers: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer test-api-key" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer test-api-key")
	}
}

func TestAttester_SetClient(t *testing.T) {
	a := venice.NewAttester("https://api.venice.ai", "key")
	a.SetClient(&http.Client{})
	t.Log("SetClient accepted non-nil client")
}

// Detect returns "" for three different conditions. The parse error must say
// which one, so an operator can tell a malformed body from a version teep
// does not support.
func TestParseAttestationResponse_UnrecognizedFormatErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"invalid json", `{"api_version":`, "not valid JSON"},
		{"unsupported version", `{"api_version":"aci/2","intel_quote":"aa"}`, `unsupported attestation api_version "aci/2"`},
		{"no known keys", `{"unrelated":"value"}`, "no known format keys found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := venice.ParseAttestationResponse(t.Context(), []byte(tt.body))
			if err == nil {
				t.Fatalf("ParseAttestationResponse(%s) returned no error", tt.body)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.want)
			}
		})
	}
}
