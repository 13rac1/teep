package phalacloud_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/phalacloud"
)

func makeServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestAttester_FetchAttestation_FlatResponse(t *testing.T) {
	body := `{
		"verified": true,
		"model": "phala/deepseek-chat-v3-0324",
		"intel_quote": "dGVzdHF1b3Rl",
		"nvidia_payload": "{\"nonce\":\"abc\"}",
		"signing_address": "0xdeadbeef00010203040506070809",
		"signing_algo": "ecdsa",
		"nonce": "abc123"
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := phalacloud.NewAttester(srv.URL, "test-key")
	nonce := attestation.NewNonce()

	raw, err := a.FetchAttestation(context.Background(), "phala/deepseek-chat-v3-0324", nonce)
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}
	if raw.Model != "phala/deepseek-chat-v3-0324" {
		t.Errorf("Model = %q, want %q", raw.Model, "phala/deepseek-chat-v3-0324")
	}
	if raw.IntelQuote != "dGVzdHF1b3Rl" {
		t.Errorf("IntelQuote = %q, want %q", raw.IntelQuote, "dGVzdHF1b3Rl")
	}
}

func TestAttester_FetchAttestation_AllAttestationsFormat(t *testing.T) {
	// Phala Cloud may return all_attestations for multi-node deployments.
	body := `{
		"all_attestations": [
			{
				"model": "phala/deepseek-chat-v3-0324",
				"intel_quote": "cXVvdGUx",
				"nvidia_payload": "{\"nonce\":\"abc\"}",
				"signing_address": "0xaabbccddee"
			},
			{
				"model": "phala/llama-3.1-8b",
				"intel_quote": "cXVvdGUy",
				"nvidia_payload": "{\"nonce\":\"def\"}",
				"signing_address": "0xffeeddccbb"
			}
		]
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := phalacloud.NewAttester(srv.URL, "test-key")
	nonce := attestation.NewNonce()

	raw, err := a.FetchAttestation(context.Background(), "phala/llama-3.1-8b", nonce)
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}
	if raw.IntelQuote != "cXVvdGUy" {
		t.Errorf("IntelQuote = %q, want second entry", raw.IntelQuote)
	}
}

func TestAttester_FetchAttestation_ModelNotFound(t *testing.T) {
	body := `{
		"all_attestations": [
			{
				"model": "phala/deepseek-chat-v3-0324",
				"intel_quote": "cXVvdGUx"
			}
		]
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := phalacloud.NewAttester(srv.URL, "test-key")
	_, err := a.FetchAttestation(context.Background(), "phala/unknown-model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for model not in attestation list")
	}
}

func TestAttester_FetchAttestation_HTTP500(t *testing.T) {
	srv := makeServer(t, http.StatusInternalServerError, `{"error": "server error"}`)
	defer srv.Close()

	a := phalacloud.NewAttester(srv.URL, "test-key")
	_, err := a.FetchAttestation(context.Background(), "phala/test", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error should mention HTTP status, got: %v", err)
	}
}

func TestAttester_SendsCorrectQueryParams(t *testing.T) {
	var requestURL string
	var authHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURL = r.URL.String()
		authHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"model": "phala/test", "intel_quote": "abc"}`))
	}))
	defer srv.Close()

	a := phalacloud.NewAttester(srv.URL, "sk-test-key-123")
	nonce := attestation.NewNonce()

	_, err := a.FetchAttestation(context.Background(), "phala/test-model", nonce)
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if !strings.Contains(requestURL, "model=phala%2Ftest-model") &&
		!strings.Contains(requestURL, "model=phala/test-model") {
		t.Errorf("request URL should contain model param, got: %s", requestURL)
	}
	if !strings.Contains(requestURL, "nonce="+nonce.Hex()) {
		t.Errorf("request URL should contain nonce param, got: %s", requestURL)
	}
	if authHeader != "Bearer sk-test-key-123" {
		t.Errorf("Authorization header = %q, want %q", authHeader, "Bearer sk-test-key-123")
	}
}

func TestPreparer_SetsAuthHeader(t *testing.T) {
	p := phalacloud.NewPreparer("sk-test-123")
	req, _ := http.NewRequest(http.MethodPost, "https://api.phala.network/v1/chat/completions", http.NoBody)

	if err := p.PrepareRequest(req, nil); err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}
	if req.Header.Get("Authorization") != "Bearer sk-test-123" {
		t.Errorf("Authorization = %q, want %q", req.Header.Get("Authorization"), "Bearer sk-test-123")
	}
}
