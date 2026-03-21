package nearai_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/nearai"
)

// validFlatResponseJSON simulates the flat (non-array) response form.
const validFlatResponseJSON = `{
	"verified": true,
	"model": "llama-3.1-70b",
	"intel_quote": "dGVzdHF1b3Rl",
	"nvidia_payload": "eyJhbGciOiJSUzI1NiJ9.test.sig",
	"signing_key": "04bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	"nonce": ""
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
				"model": "llama-3.1-70b",
				"intel_quote": "cXVvdGUx",
				"nvidia_payload": "jwt1",
				"signing_key": "04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			},
			{
				"model": "llama-3.1-405b",
				"intel_quote": "cXVvdGUy",
				"nvidia_payload": "jwt2",
				"signing_key": "04bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			}
		]
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := nearai.NewAttester(srv.URL, "key")
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

func TestAttester_FetchAttestation_ArrayResponse_FallsBackToFirst(t *testing.T) {
	// Array response, but we request a model not in the list.
	// The first entry should be returned as fallback.
	body := `{
		"verified": true,
		"model_attestations": [
			{
				"model": "llama-3.1-70b",
				"intel_quote": "cXVvdGUx",
				"nvidia_payload": "jwt1",
				"signing_key": "04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			}
		]
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := nearai.NewAttester(srv.URL, "key")
	raw, err := a.FetchAttestation(context.Background(), "unknown-model", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if raw.Model != "llama-3.1-70b" {
		t.Errorf("Model = %q, want %q (first-entry fallback)", raw.Model, "llama-3.1-70b")
	}
}

func TestAttester_FetchAttestation_FlatResponse(t *testing.T) {
	srv := makeServer(t, http.StatusOK, validFlatResponseJSON)
	defer srv.Close()

	a := nearai.NewAttester(srv.URL, "key")
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
	a := nearai.NewAttester(srv.URL, "nearai-secret")
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
	if got := params.Get("signing_algo"); got != "ecdsa" {
		t.Errorf("signing_algo param = %q, want %q", got, "ecdsa")
	}
}

func TestAttester_FetchAttestation_HTTP500(t *testing.T) {
	srv := makeServer(t, http.StatusInternalServerError, `{"error":"server error"}`)
	defer srv.Close()

	a := nearai.NewAttester(srv.URL, "key")
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

func TestAttester_FetchAttestation_InvalidJSON(t *testing.T) {
	srv := makeServer(t, http.StatusOK, `not json`)
	defer srv.Close()

	a := nearai.NewAttester(srv.URL, "key")
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

	a := nearai.NewAttester(srv.URL, "key")
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
				"model": "m",
				"intel_quote": "dA==",
				"nvidia_payload": "j",
				"signing_key": "04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			}
		]
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := nearai.NewAttester(srv.URL, "key")
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
				"model": "llama-3.1-70b",
				"intel_quote": "cXVvdGUx",
				"nvidia_payload": "jwt1",
				"signing_key": "04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"signing_address": "0xdeadbeef01020304050607080910111213141516",
				"signing_algo": "ecdsa",
				"tls_cert_fingerprint": "aabbccdd",
				"nonce": "abc123"
			}
		]
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := nearai.NewAttester(srv.URL, "key")
	raw, err := a.FetchAttestation(context.Background(), "llama-3.1-70b", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if raw.SigningAddress != "0xdeadbeef01020304050607080910111213141516" {
		t.Errorf("SigningAddress = %q, want 0xdeadbeef...", raw.SigningAddress)
	}
	if raw.SigningAlgo != "ecdsa" {
		t.Errorf("SigningAlgo = %q, want %q", raw.SigningAlgo, "ecdsa")
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
		"model": "llama-3.1-70b",
		"intel_quote": "dGVzdA==",
		"nvidia_payload": "jwt",
		"signing_key": "04bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"signing_address": "0x1234",
		"signing_algo": "ecdsa",
		"tls_cert_fingerprint": "deadbeef",
		"nonce": "test-nonce"
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := nearai.NewAttester(srv.URL, "key")
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
				"signing_public_key": "04cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				"signing_address": "0x1111111111111111111111111111111111111111",
				"signing_algo": "ecdsa",
				"tls_cert_fingerprint": "deadbeef",
				"request_nonce": "abc123"
			}
		]
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := nearai.NewAttester(srv.URL, "key")
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

func TestAttester_FetchAttestation_NormalizesUnprefixedKey(t *testing.T) {
	// NEAR AI may return signing_public_key without the "04" uncompressed prefix.
	// The parser should normalize 128-char keys by prepending "04".
	rawKey := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	body := `{
		"verified": true,
		"model": "test-model",
		"intel_quote": "dGVzdA==",
		"nvidia_payload": "jwt",
		"signing_public_key": "` + rawKey + `",
		"nonce": "abc"
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := nearai.NewAttester(srv.URL, "key")
	raw, err := a.FetchAttestation(context.Background(), "test-model", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if raw.SigningKey != "04"+rawKey {
		t.Errorf("SigningKey = %q (len %d), want '04' prefix + 128 chars (len 130)", raw.SigningKey, len(raw.SigningKey))
	}
}

// --- Preparer tests ---

func TestPreparer_PrepareRequest_SetsAuthHeader(t *testing.T) {
	p := nearai.NewPreparer("nearai-key")
	req, _ := http.NewRequest(http.MethodPost, "https://api.near.ai/v1/chat/completions", http.NoBody)

	session, err := attestation.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	if err := p.PrepareRequest(req, session); err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer nearai-key" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer nearai-key")
	}
}

func TestPreparer_PrepareRequest_NoSessionRequired(t *testing.T) {
	// NEAR AI's PrepareRequest should not error when session has no model key.
	p := nearai.NewPreparer("key")
	req, _ := http.NewRequest(http.MethodPost, "https://api.near.ai/", http.NoBody)
	session, err := attestation.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// ModelKeyHex is empty — should not error for NEAR AI.
	if err := p.PrepareRequest(req, session); err != nil {
		t.Fatalf("PrepareRequest with empty session: %v", err)
	}
}
