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
// replay coverage live in internal/integration; a live keyset/custody
// sample is pinned in keyset_test.go (testdata/aci_keyset_live.json).

const validACI1JSON = `{
	"api_version": "aci/1",
	"workload_keyset_digest": "sha256:abcdef0123456789",
	"attestation": {
		"tee_type": "tdx",
		"workload_keyset": {
			"subject": null,
			"not_after": 1790265204,
			"receipt_signing_keys": [{"key_id": "dstack-kms-receipt-ed25519-v1", "algo": "ed25519", "public_key": "110f3824"}],
			"e2ee_public_keys": [{"key_id": "dstack-kms-e2ee-v1", "algo": "secp256k1-aes-256-gcm-hkdf-sha256", "public_key": "04943cea0baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
			"tls_public_keys": [{"spki_sha256": "aabbccdd", "domain": "test.example.com"}]
		},
		"report_data": "79a5061e00000000000000000000000000000000000000000000000000000000",
		"source_provenance": {
			"repo_url": "https://github.com/Dstack-TEE/private-ai-gateway.git",
			"repo_commit": "ac7dd5fc0a95f21f86f75dacf812614656e9ae6a",
			"image_digest": null,
			"image_provenance": null
		},
		"evidence": {
			"quote": "dGVzdHF1b3Rl",
			"quote_report_data": "79a5061e00000000000000000000000000000000000000000000000000000000",
			"event_log": "[{\"imr\":0,\"event_type\":2147483659,\"digest\":\"d6d8d853b6454f838d98c5573d6a098c\",\"event\":\"\",\"event_payload\":\"095464785461626c65\"},{\"imr\":3,\"event_type\":134217729,\"digest\":\"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\",\"event\":\"app-id\",\"event_payload\":\"fdb7a14e5a6675f752e2cb69c9067a98ca402918\"}]",
			"vm_config": "{\"os_image_hash\":\"bd369a8c\",\"cpu_count\":16,\"memory_size\":34359738368,\"qemu_version\":\"8.2.2\",\"num_gpus\":0,\"num_nvswitches\":0,\"image\":\"dstack-dev-0.5.11\",\"spec_version\":1}",
			"app_compose": "{\"manifest_version\":2,\"name\":\"private-ai-gateway\",\"docker_compose_file\":\"services: {}\"}",
			"key_custody": {
				"provider": "dstack-kms",
				"keys": [{"role": "e2ee-secp256k1", "path": "aci/e2ee/v1", "purpose": "aci.e2ee.v1", "algo": "secp256k1-aes-256-gcm-hkdf-sha256", "public_key": "04943cea0baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "kms_public_key": "03943cea0baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "signature_chain": ["aabb", "ccdd"]}]
			},
			"downstream_tls_binding": {"domain": "test.example.com", "spki_sha256": "aabbccdd"}
		}
	},
	"service_capabilities": {"supported_e2ee_versions": ["2"], "serving": "aggregator"},
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
		{"SigningAlgo", raw.SigningAlgo, "ecdsa"},
		{"Nonce", raw.Nonce, "aabbccddeeff00112233445566778899"},
		{"Model", raw.Model, "e2ee-glm-5-2-p"},
		{"NonceSource", raw.NonceSource, "client"},
		{"UpstreamModel", raw.UpstreamModel, "z-ai/glm-5.2"},
		{"ACIWorkloadKeysetDigest", raw.ACIWorkloadKeysetDigest, "sha256:abcdef0123456789"},
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
		t.Error("ACIWorkloadKeyset is nil, want populated for keyset verification")
	}
	if raw.ACIKeyCustody == nil {
		t.Error("ACIKeyCustody is nil, want populated for custody chain verification")
	}
}

// TestParseACI1_GatewayEvidence: the ACI/1 quote, event log, and compose
// manifest describe the private-ai-gateway CVM, not the inference host, so
// they populate the Gateway* fields; the core fields stay empty and
// TEEHardware is cleared so the report does not present the gateway's
// platform as the endpoint's.
func TestParseACI1_GatewayEvidence(t *testing.T) {
	raw, err := venice.ParseAttestationResponse(context.Background(), []byte(validACI1JSON))
	if err != nil {
		t.Fatalf("ParseAttestationResponse(ACI/1): %v", err)
	}

	if raw.GatewayIntelQuote != "dGVzdHF1b3Rl" {
		t.Errorf("GatewayIntelQuote = %q, want the evidence quote", raw.GatewayIntelQuote)
	}
	if raw.IntelQuote != "" {
		t.Errorf("IntelQuote = %q, want empty — the quote describes the gateway", raw.IntelQuote)
	}
	if raw.TEEHardware != "" {
		t.Errorf("TEEHardware = %q, want cleared for a gateway-only attestation", raw.TEEHardware)
	}
	if raw.GatewayNonceHex != raw.Nonce {
		t.Errorf("GatewayNonceHex = %q, want the echoed client nonce %q", raw.GatewayNonceHex, raw.Nonce)
	}
	if raw.GatewayAppCompose == "" {
		t.Error("GatewayAppCompose is empty, want the gateway compose manifest")
	}
	if raw.ACIDownstreamTLSDomain != "test.example.com" || raw.ACIDownstreamTLSSPKI != "aabbccdd" {
		t.Errorf("downstream TLS binding = %q/%q, want test.example.com/aabbccdd",
			raw.ACIDownstreamTLSDomain, raw.ACIDownstreamTLSSPKI)
	}
}

func TestParseACI1_EventLog(t *testing.T) {
	raw, err := venice.ParseAttestationResponse(context.Background(), []byte(validACI1JSON))
	if err != nil {
		t.Fatalf("ParseAttestationResponse(ACI/1): %v", err)
	}

	if len(raw.GatewayEventLog) != 2 {
		t.Fatalf("len(GatewayEventLog) = %d, want 2", len(raw.GatewayEventLog))
	}
	if raw.GatewayEventLog[0].IMR != 0 {
		t.Errorf("GatewayEventLog[0].IMR = %d, want 0", raw.GatewayEventLog[0].IMR)
	}
	if raw.GatewayEventLog[1].Event != "app-id" {
		t.Errorf("GatewayEventLog[1].Event = %q, want app-id", raw.GatewayEventLog[1].Event)
	}
	if len(raw.EventLog) != 0 || raw.EventLogCount != 0 {
		t.Errorf("core EventLog has %d entries (count %d), want 0 — the log describes the gateway",
			len(raw.EventLog), raw.EventLogCount)
	}
}

func TestParseACI1_NoModelComposeFields(t *testing.T) {
	raw, err := venice.ParseAttestationResponse(context.Background(), []byte(validACI1JSON))
	if err != nil {
		t.Fatalf("ParseAttestationResponse(ACI/1): %v", err)
	}

	// ACI/1 publishes no manifest for the machine serving inference — the
	// model-tier compose fields stay empty, so the model-tier supply chain
	// factors evaluate to Fail (never NotApplicable). The gateway's own
	// manifest is in GatewayAppCompose.
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

func TestParseACI1_InvalidEventLog(t *testing.T) {
	body := strings.Replace(validACI1JSON,
		`"event_log": "[{`, `"event_log": "not-json[{`, 1)
	_, err := venice.ParseAttestationResponse(context.Background(), []byte(body))
	if err == nil {
		t.Fatal("expected error for an undecodable evidence.event_log, got nil")
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
