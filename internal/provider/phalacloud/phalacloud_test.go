package phalacloud_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
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

// fakeQuoteBase64 returns a minimal base64-encoded TDX quote for tests.
func fakeQuoteBase64() string {
	return base64.StdEncoding.EncodeToString([]byte("fake-tdx-quote-bytes"))
}

// fakeQuoteHex returns the hex encoding of the same fake quote bytes.
func fakeQuoteHex() string {
	return hex.EncodeToString([]byte("fake-tdx-quote-bytes"))
}

func TestAttester_FetchAttestation_ChutesFormat(t *testing.T) {
	quote := fakeQuoteBase64()
	body := `{
		"attestation_type": "chutes",
		"nonce": "aabb000000000000000000000000000000000000000000000000000000000000",
		"all_attestations": [
			{
				"instance_id": "inst-001",
				"nonce": "aabb000000000000000000000000000000000000000000000000000000000000",
				"e2e_pubkey": "dGVzdC1wdWJrZXk=",
				"intel_quote": "` + quote + `",
				"gpu_evidence": [
					{"certificate": "cert1", "evidence": "ev1", "arch": "HOPPER"}
				]
			}
		]
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := phalacloud.NewAttester(srv.URL, "test-key")
	nonce := attestation.NewNonce()

	raw, err := a.FetchAttestation(context.Background(), "phala/test-model", nonce)
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}
	if raw.BackendFormat != attestation.FormatChutes {
		t.Errorf("BackendFormat = %q, want %q", raw.BackendFormat, attestation.FormatChutes)
	}
	if raw.IntelQuote != fakeQuoteHex() {
		t.Errorf("IntelQuote = %q, want hex-decoded base64 = %q", raw.IntelQuote, fakeQuoteHex())
	}
	if raw.SigningKey != "dGVzdC1wdWJrZXk=" {
		t.Errorf("SigningKey = %q, want e2e_pubkey value", raw.SigningKey)
	}
	if raw.Nonce != "aabb000000000000000000000000000000000000000000000000000000000000" {
		t.Errorf("Nonce = %q, want server nonce", raw.Nonce)
	}
	if raw.TEEProvider != "TDX+NVIDIA" {
		t.Errorf("TEEProvider = %q, want TDX+NVIDIA", raw.TEEProvider)
	}
	if raw.TEEHardware != "intel-tdx" {
		t.Errorf("TEEHardware = %q, want intel-tdx", raw.TEEHardware)
	}
	if raw.NonceSource != "server" {
		t.Errorf("NonceSource = %q, want server", raw.NonceSource)
	}
}

func TestParseAttestationResponse_DstackFormat(t *testing.T) {
	// A dstack-format response (like Venice/NanoGPT backends return).
	body := []byte(`{
		"signing_public_key": "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
		"signing_address": "0xdeadbeef",
		"signing_algo": "ecdsa",
		"intel_quote": "deadbeef",
		"nvidia_payload": "",
		"event_log": [],
		"info": {
			"app_cert": "",
			"app_id": "",
			"app_name": "test-app",
			"compose_hash": "abc123",
			"device_id": "dev1",
			"instance_id": "",
			"key_provider_info": "",
			"mr_aggregated": "",
			"os_image_hash": "os123",
			"tcb_info": {
				"app_compose": "{}",
				"compose_hash": "",
				"device_id": "",
				"event_log": [],
				"mrtd": "",
				"os_image_hash": "",
				"rtmr0": "",
				"rtmr1": "",
				"rtmr2": "",
				"rtmr3": ""
			},
			"vm_config": ""
		},
		"request_nonce": "aabb",
		"quote": "",
		"vm_config": ""
	}`)

	raw, err := phalacloud.ParseAttestationResponse(body)
	if err != nil {
		t.Fatalf("ParseAttestationResponse: %v", err)
	}
	if raw.BackendFormat != attestation.FormatDstack {
		t.Errorf("BackendFormat = %q, want %q", raw.BackendFormat, attestation.FormatDstack)
	}
	if raw.AppName != "test-app" {
		t.Errorf("AppName = %q, want %q", raw.AppName, "test-app")
	}
}

func TestParseAttestationResponse_UnsupportedTinfoil(t *testing.T) {
	body := []byte(`{"format":"tinfoil","data":"stuff"}`)
	_, err := phalacloud.ParseAttestationResponse(body)
	if err == nil {
		t.Fatal("expected error for tinfoil format")
	}
	if !strings.Contains(err.Error(), "tinfoil") {
		t.Errorf("error should mention tinfoil, got: %v", err)
	}
}

func TestParseAttestationResponse_UnrecognizedFormat(t *testing.T) {
	body := []byte(`{"unknown_key":"value"}`)
	_, err := phalacloud.ParseAttestationResponse(body)
	if err == nil {
		t.Fatal("expected error for unrecognized format")
	}
	if !strings.Contains(err.Error(), "unrecognized") {
		t.Errorf("error should mention unrecognized, got: %v", err)
	}
}

func TestAttester_FetchAttestation_MultipleAttestations(t *testing.T) {
	quote1 := base64.StdEncoding.EncodeToString([]byte("quote-one"))
	quote2 := base64.StdEncoding.EncodeToString([]byte("quote-two"))
	body := `{
		"attestation_type": "chutes",
		"nonce": "ccdd000000000000000000000000000000000000000000000000000000000000",
		"all_attestations": [
			{
				"instance_id": "inst-001",
				"nonce": "ccdd000000000000000000000000000000000000000000000000000000000000",
				"e2e_pubkey": "key1",
				"intel_quote": "` + quote1 + `",
				"gpu_evidence": []
			},
			{
				"instance_id": "inst-002",
				"nonce": "ccdd000000000000000000000000000000000000000000000000000000000000",
				"e2e_pubkey": "key2",
				"intel_quote": "` + quote2 + `",
				"gpu_evidence": []
			}
		]
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := phalacloud.NewAttester(srv.URL, "test-key")
	raw, err := a.FetchAttestation(context.Background(), "phala/test", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}
	wantHex := hex.EncodeToString([]byte("quote-one"))
	if raw.IntelQuote != wantHex {
		t.Errorf("IntelQuote = %q, want first entry hex = %q", raw.IntelQuote, wantHex)
	}
	if raw.CandidatesAvail != 2 {
		t.Errorf("CandidatesAvail = %d, want 2", raw.CandidatesAvail)
	}
}

func TestAttester_FetchAttestation_EmptyAttestations(t *testing.T) {
	body := `{
		"attestation_type": "chutes",
		"nonce": "0000000000000000000000000000000000000000000000000000000000000000",
		"all_attestations": []
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := phalacloud.NewAttester(srv.URL, "test-key")
	_, err := a.FetchAttestation(context.Background(), "phala/test", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for empty all_attestations")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error should mention empty, got: %v", err)
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

func TestAttester_FetchAttestation_InvalidBase64Quote(t *testing.T) {
	body := `{
		"attestation_type": "chutes",
		"nonce": "0000000000000000000000000000000000000000000000000000000000000000",
		"all_attestations": [
			{
				"instance_id": "inst-001",
				"nonce": "0000000000000000000000000000000000000000000000000000000000000000",
				"e2e_pubkey": "key1",
				"intel_quote": "!!!not-valid-base64!!!",
				"gpu_evidence": []
			}
		]
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := phalacloud.NewAttester(srv.URL, "test-key")
	_, err := a.FetchAttestation(context.Background(), "phala/test", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for invalid base64 intel_quote")
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Errorf("error should mention base64, got: %v", err)
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
		quote := fakeQuoteBase64()
		_, _ = w.Write([]byte(`{
			"attestation_type": "chutes",
			"nonce": "0000000000000000000000000000000000000000000000000000000000000000",
			"all_attestations": [{
				"instance_id": "i",
				"nonce": "0000000000000000000000000000000000000000000000000000000000000000",
				"e2e_pubkey": "k",
				"intel_quote": "` + quote + `",
				"gpu_evidence": []
			}]
		}`))
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

func TestParseAttestationResponse_InvalidJSON(t *testing.T) {
	_, err := phalacloud.ParseAttestationResponse([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestPreparer_SetsAuthHeader(t *testing.T) {
	p := phalacloud.NewPreparer("sk-test-123")
	req, _ := http.NewRequest(http.MethodPost, "https://api.redpill.ai/v1/chat/completions", http.NoBody)

	if err := p.PrepareRequest(req, nil); err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}
	if req.Header.Get("Authorization") != "Bearer sk-test-123" {
		t.Errorf("Authorization = %q, want %q", req.Header.Get("Authorization"), "Bearer sk-test-123")
	}
}
