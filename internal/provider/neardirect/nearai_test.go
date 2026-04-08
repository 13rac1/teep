package neardirect_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/neardirect"
)

// validFlatResponseJSON simulates the flat (non-array) response form.
const validFlatResponseJSON = `{
	"verified": true,
	"model_name": "llama-3.1-70b",
	"intel_quote": "dGVzdHF1b3Rl",
	"nvidia_payload": "eyJhbGciOiJSUzI1NiJ9.test.sig",
	"signing_public_key": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	"request_nonce": ""
}`

func makeServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestAttester_FetchAttestation_ArrayResponse_ExactMatch(t *testing.T) {
	// Array response with two models — we request the second one.
	body := `{
		"verified": true,
		"model_attestations": [
			{
				"model_name": "llama-3.1-70b",
				"intel_quote": "cXVvdGUx",
				"nvidia_payload": "jwt1",
				"signing_public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			},
			{
				"model_name": "llama-3.1-405b",
				"intel_quote": "cXVvdGUy",
				"nvidia_payload": "jwt2",
				"signing_public_key": "04bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			}
		]
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := neardirect.NewAttester(srv.URL, "key")
	nonce := attestation.NewNonce()

	raw, err := a.FetchAttestation(context.Background(), "llama-3.1-405b", nonce)
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if raw.Model != "llama-3.1-405b" {
		t.Errorf("Model = %q, want %q", raw.Model, "llama-3.1-405b")
	}
	if raw.IntelQuote != "cXVvdGUy" {
		t.Errorf("IntelQuote = %q, want second entry's quote", raw.IntelQuote)
	}
}

func TestAttester_FetchAttestation_ArrayResponse_NoMatch(t *testing.T) {
	// Array response, but we request a model not in the list.
	// Should return an error instead of silently falling back.
	body := `{
		"verified": true,
		"model_attestations": [
			{
				"model_name": "llama-3.1-70b",
				"intel_quote": "cXVvdGUx",
				"nvidia_payload": "jwt1",
				"signing_public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			}
		]
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := neardirect.NewAttester(srv.URL, "key")
	_, err := a.FetchAttestation(context.Background(), "unknown-model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for model not in attestation list")
	}
	t.Logf("got expected error: %v", err)
}

func TestAttester_FetchAttestation_FlatResponse(t *testing.T) {
	srv := makeServer(t, http.StatusOK, validFlatResponseJSON)
	defer srv.Close()

	a := neardirect.NewAttester(srv.URL, "key")
	raw, err := a.FetchAttestation(context.Background(), "llama-3.1-70b", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if raw.Model != "llama-3.1-70b" {
		t.Errorf("Model = %q, want %q", raw.Model, "llama-3.1-70b")
	}
	if raw.IntelQuote != "dGVzdHF1b3Rl" {
		t.Errorf("IntelQuote = %q, want %q", raw.IntelQuote, "dGVzdHF1b3Rl")
	}
	if raw.TEEProvider != "TDX+NVIDIA" {
		t.Errorf("TEEProvider = %q, want %q", raw.TEEProvider, "TDX+NVIDIA")
	}
}

func TestAttester_FetchAttestation_SetsAuthHeaderAndQueryParams(t *testing.T) {
	var capturedAuth string
	var capturedQuery string
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		capturedQuery = r.URL.RawQuery
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validFlatResponseJSON))
	}))
	defer srv.Close()

	nonce := attestation.NewNonce()
	a := neardirect.NewAttester(srv.URL, "nearai-secret")
	_, err := a.FetchAttestation(context.Background(), "llama-3.1-70b", nonce)
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if capturedAuth != "Bearer nearai-secret" {
		t.Errorf("Authorization = %q, want %q", capturedAuth, "Bearer nearai-secret")
	}
	if capturedPath != "/v1/attestation/report" {
		t.Errorf("Path = %q, want %q", capturedPath, "/v1/attestation/report")
	}

	// Parse query params to verify each one is set correctly.
	params, err := url.ParseQuery(capturedQuery)
	if err != nil {
		t.Fatalf("ParseQuery(%q): %v", capturedQuery, err)
	}
	if got := params.Get("nonce"); got != nonce.Hex() {
		t.Errorf("nonce param = %q, want %q", got, nonce.Hex())
	}
	if got := params.Get("include_tls_fingerprint"); got != "true" {
		t.Errorf("include_tls_fingerprint param = %q, want %q", got, "true")
	}
	if got := params.Get("signing_algo"); got != "ed25519" {
		t.Errorf("signing_algo param = %q, want %q", got, "ed25519")
	}
}

func TestAttester_FetchAttestation_HTTP500(t *testing.T) {
	srv := makeServer(t, http.StatusInternalServerError, `{"error":"server error"}`)
	defer srv.Close()

	a := neardirect.NewAttester(srv.URL, "key")
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

func TestAttester_FetchAttestation_InvalidJSON(t *testing.T) {
	srv := makeServer(t, http.StatusOK, `not json`)
	defer srv.Close()

	a := neardirect.NewAttester(srv.URL, "key")
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

	a := neardirect.NewAttester(srv.URL, "key")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := a.FetchAttestation(ctx, "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestAttester_FetchAttestation_TEEProviderIsSet(t *testing.T) {
	// Both array and flat responses should set TEEProvider = "TDX+NVIDIA".
	body := `{
		"verified": true,
		"model_attestations": [
			{
				"model_name": "m",
				"intel_quote": "dA==",
				"nvidia_payload": "j",
				"signing_public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			}
		]
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := neardirect.NewAttester(srv.URL, "key")
	raw, err := a.FetchAttestation(context.Background(), "m", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}
	if raw.TEEProvider != "TDX+NVIDIA" {
		t.Errorf("TEEProvider = %q, want %q", raw.TEEProvider, "TDX+NVIDIA")
	}
}

func TestAttester_FetchAttestation_NewFieldsPropagated(t *testing.T) {
	body := `{
		"verified": true,
		"model_attestations": [
			{
				"model_name": "llama-3.1-70b",
				"intel_quote": "cXVvdGUx",
				"nvidia_payload": "jwt1",
				"signing_public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"signing_address": "0xdeadbeef01020304050607080910111213141516",
				"signing_algo": "ed25519",
				"tls_cert_fingerprint": "aabbccdd",
				"request_nonce": "abc123"
			}
		]
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := neardirect.NewAttester(srv.URL, "key")
	raw, err := a.FetchAttestation(context.Background(), "llama-3.1-70b", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if raw.SigningAddress != "0xdeadbeef01020304050607080910111213141516" {
		t.Errorf("SigningAddress = %q, want 0xdeadbeef...", raw.SigningAddress)
	}
	if raw.SigningAlgo != "ed25519" {
		t.Errorf("SigningAlgo = %q, want %q", raw.SigningAlgo, "ed25519")
	}
	if raw.TLSFingerprint != "aabbccdd" {
		t.Errorf("TLSFingerprint = %q, want %q", raw.TLSFingerprint, "aabbccdd")
	}
	if raw.Nonce != "abc123" {
		t.Errorf("Nonce = %q, want %q", raw.Nonce, "abc123")
	}
}

func TestAttester_FetchAttestation_FlatResponse_NewFields(t *testing.T) {
	body := `{
		"verified": true,
		"model_name": "llama-3.1-70b",
		"intel_quote": "dGVzdA==",
		"nvidia_payload": "jwt",
		"signing_public_key": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"signing_address": "0x1234",
		"signing_algo": "ed25519",
		"tls_cert_fingerprint": "deadbeef",
		"request_nonce": "test-nonce"
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := neardirect.NewAttester(srv.URL, "key")
	raw, err := a.FetchAttestation(context.Background(), "llama-3.1-70b", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if raw.SigningAddress != "0x1234" {
		t.Errorf("SigningAddress = %q, want %q", raw.SigningAddress, "0x1234")
	}
	if raw.TLSFingerprint != "deadbeef" {
		t.Errorf("TLSFingerprint = %q, want %q", raw.TLSFingerprint, "deadbeef")
	}
	if raw.Nonce != "test-nonce" {
		t.Errorf("Nonce = %q, want %q", raw.Nonce, "test-nonce")
	}
}

func TestAttester_FetchAttestation_AllAttestations_UsesNewFieldNames(t *testing.T) {
	body := `{
		"all_attestations": [
			{
				"model_name": "openai/gpt-oss-120b",
				"intel_quote": "cXVvdGU=",
				"nvidia_payload": "jwt",
				"signing_public_key": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				"signing_address": "0x1111111111111111111111111111111111111111",
				"signing_algo": "ed25519",
				"tls_cert_fingerprint": "deadbeef",
				"request_nonce": "abc123"
			}
		]
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := neardirect.NewAttester(srv.URL, "key")
	raw, err := a.FetchAttestation(context.Background(), "openai/gpt-oss-120b", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if raw.Model != "openai/gpt-oss-120b" {
		t.Errorf("Model = %q, want %q", raw.Model, "openai/gpt-oss-120b")
	}
	if raw.SigningKey == "" {
		t.Fatal("SigningKey should be populated from signing_public_key")
	}
	if raw.Nonce != "abc123" {
		t.Errorf("Nonce = %q, want %q", raw.Nonce, "abc123")
	}
}

func TestAttester_FetchAttestation_TooManyAttestations(t *testing.T) {
	// Build a response with more entries than maxAttestationEntries (256).
	var sb strings.Builder
	for i := range 257 {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"model_name":"m-%d","intel_quote":"q","signing_public_key":"%s"}`,
			i, "aa"+fmt.Sprintf("%062d", i))
	}
	body := fmt.Sprintf(`{"verified":true,"model_attestations":[%s]}`, sb.String())

	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := neardirect.NewAttester(srv.URL, "key")
	_, err := a.FetchAttestation(context.Background(), "m-0", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for too many attestation entries")
	}
	t.Logf("got expected error: %v", err)
}

func TestAttester_FetchAttestation_MalformedEventLogEntry(t *testing.T) {
	body := `{
		"verified": true,
		"model_name": "test-model",
		"intel_quote": "dGVzdA==",
		"nvidia_payload": "jwt",
		"signing_public_key": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"event_log": [123]
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := neardirect.NewAttester(srv.URL, "key")
	_, err := a.FetchAttestation(context.Background(), "test-model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for malformed event_log entry")
	}
	if !strings.Contains(err.Error(), "event_log") {
		t.Fatalf("error should mention event_log, got: %v", err)
	}
}

func TestAttester_FetchAttestation_Ed25519KeyPassedThrough(t *testing.T) {
	// Ed25519 signing keys are 64 hex chars and must be passed through as-is.
	ed25519Key := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	body := `{
		"verified": true,
		"model_name": "test-model",
		"intel_quote": "dGVzdA==",
		"nvidia_payload": "jwt",
		"signing_public_key": "` + ed25519Key + `",
		"request_nonce": "abc"
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := neardirect.NewAttester(srv.URL, "key")
	raw, err := a.FetchAttestation(context.Background(), "test-model", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if raw.SigningKey != ed25519Key {
		t.Errorf("SigningKey = %q (len %d), want 64-char ed25519 key", raw.SigningKey, len(raw.SigningKey))
	}
}

// --- tcbInfo / appCompose tests ---

func TestExtractAppCompose(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"nil", nil, ""},
		{"empty", []byte(``), ""},
		{"non_json", []byte(`not json`), ""},
		{"object_with_app_compose", []byte(`{"app_compose":"version: '3'"}`), "version: '3'"},
		{"object_missing_app_compose", []byte(`{"other_field":"value"}`), ""},
		{
			"json_string_wrapping",
			[]byte(`"{\"app_compose\":\"wrapped content\"}"`),
			"wrapped content",
		},
		{"number", []byte(`42`), ""},
		{"array", []byte(`[1,2,3]`), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := neardirect.ExtractAppCompose(tc.data)
			if got != tc.want {
				t.Errorf("ExtractAppCompose(%s) = %q, want %q", tc.data, got, tc.want)
			}
		})
	}
}

// --- Preparer tests ---

func TestPreparer_PrepareRequest_SetsAuthHeader(t *testing.T) {
	p := neardirect.NewPreparer("nearai-key")
	req, _ := http.NewRequest(http.MethodPost, "https://api.near.ai/v1/chat/completions", http.NoBody)

	if err := p.PrepareRequest(req, nil, nil, false, ""); err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer nearai-key" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer nearai-key")
	}
}

func TestPreparer_PrepareRequest_NoSessionRequired(t *testing.T) {
	// NEAR AI's PrepareRequest ignores session — should not error.
	p := neardirect.NewPreparer("key")
	req, _ := http.NewRequest(http.MethodPost, "https://api.near.ai/", http.NoBody)

	if err := p.PrepareRequest(req, nil, nil, false, ""); err != nil {
		t.Fatalf("PrepareRequest with nil session: %v", err)
	}
}
