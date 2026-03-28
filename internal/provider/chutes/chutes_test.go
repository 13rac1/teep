package chutes_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/chutes"
)

func fakeQuoteBase64() string {
	return base64.StdEncoding.EncodeToString([]byte("fake-tdx-quote-bytes"))
}

func fakeQuoteHex() string {
	return hex.EncodeToString([]byte("fake-tdx-quote-bytes"))
}

// --- ParseAttestationResponse unit tests ---

func TestParseAttestationResponse_Success(t *testing.T) {
	quote := fakeQuoteBase64()
	nonce := attestation.NewNonce()

	instancesBody := []byte(`{
		"instances": [
			{"instance_id": "inst-001", "e2e_pubkey": "dGVzdC1wdWJrZXk=", "nonces": ["n1"]}
		]
	}`)
	evidenceBody := []byte(`{
		"evidence": [
			{
				"quote": "` + quote + `",
				"gpu_evidence": [
					{"certificate": "cert1", "evidence": "ev1", "arch": "HOPPER"}
				],
				"instance_id": "inst-001",
				"certificate": "dGxzLWNlcnQ="
			}
		],
		"failed_instance_ids": []
	}`)

	raw, err := chutes.ParseAttestationResponse(instancesBody, evidenceBody, nonce)
	if err != nil {
		t.Fatalf("ParseAttestationResponse: %v", err)
	}
	if raw.BackendFormat != attestation.FormatChutes {
		t.Errorf("BackendFormat = %q, want %q", raw.BackendFormat, attestation.FormatChutes)
	}
	if raw.IntelQuote != fakeQuoteHex() {
		t.Errorf("IntelQuote = %q, want %q", raw.IntelQuote, fakeQuoteHex())
	}
	if raw.SigningKey != "dGVzdC1wdWJrZXk=" {
		t.Errorf("SigningKey = %q, want e2e_pubkey", raw.SigningKey)
	}
	if raw.Nonce != nonce.Hex() {
		t.Errorf("Nonce = %q, want %q", raw.Nonce, nonce.Hex())
	}
	if raw.NonceSource != "client" {
		t.Errorf("NonceSource = %q, want client", raw.NonceSource)
	}
	if raw.SigningAlgo != "ml-kem-768" {
		t.Errorf("SigningAlgo = %q, want ml-kem-768", raw.SigningAlgo)
	}
	if raw.TEEProvider != "TDX+NVIDIA" {
		t.Errorf("TEEProvider = %q, want TDX+NVIDIA", raw.TEEProvider)
	}
	if raw.TEEHardware != "intel-tdx" {
		t.Errorf("TEEHardware = %q, want intel-tdx", raw.TEEHardware)
	}
	if len(raw.GPUEvidence) != 1 {
		t.Fatalf("GPUEvidence length = %d, want 1", len(raw.GPUEvidence))
	}
	if raw.GPUEvidence[0].Certificate != "cert1" {
		t.Errorf("GPUEvidence[0].Certificate = %q, want cert1", raw.GPUEvidence[0].Certificate)
	}
	if raw.GPUEvidence[0].Evidence != "ev1" {
		t.Errorf("GPUEvidence[0].Evidence = %q, want ev1", raw.GPUEvidence[0].Evidence)
	}
	if raw.GPUEvidence[0].Arch != "HOPPER" {
		t.Errorf("GPUEvidence[0].Arch = %q, want HOPPER", raw.GPUEvidence[0].Arch)
	}
}

func TestParseAttestationResponse_MultipleInstances(t *testing.T) {
	quote := fakeQuoteBase64()
	nonce := attestation.NewNonce()

	instancesBody := []byte(`{
		"instances": [
			{"instance_id": "inst-001", "e2e_pubkey": "key1", "nonces": []},
			{"instance_id": "inst-002", "e2e_pubkey": "key2", "nonces": []}
		]
	}`)
	evidenceBody := []byte(`{
		"evidence": [
			{"quote": "` + quote + `", "gpu_evidence": [], "instance_id": "inst-001", "certificate": ""},
			{"quote": "` + quote + `", "gpu_evidence": [], "instance_id": "inst-002", "certificate": ""}
		],
		"failed_instance_ids": []
	}`)

	raw, err := chutes.ParseAttestationResponse(instancesBody, evidenceBody, nonce)
	if err != nil {
		t.Fatalf("ParseAttestationResponse: %v", err)
	}
	if raw.CandidatesAvail != 2 {
		t.Errorf("CandidatesAvail = %d, want 2", raw.CandidatesAvail)
	}
	if raw.CandidatesEval != 1 {
		t.Errorf("CandidatesEval = %d, want 1", raw.CandidatesEval)
	}
	if raw.SigningKey != "key1" {
		t.Errorf("SigningKey = %q, want key1 (first instance)", raw.SigningKey)
	}
}

func TestParseAttestationResponse_NoInstances(t *testing.T) {
	nonce := attestation.NewNonce()
	_, err := chutes.ParseAttestationResponse(
		[]byte(`{"instances": []}`),
		[]byte(`{"evidence": [{"quote": "", "gpu_evidence": [], "instance_id": "i", "certificate": ""}]}`),
		nonce,
	)
	if err == nil {
		t.Fatal("expected error for no instances")
	}
	if !strings.Contains(err.Error(), "no instances") {
		t.Errorf("error should mention no instances, got: %v", err)
	}
}

func TestParseAttestationResponse_NoEvidence(t *testing.T) {
	nonce := attestation.NewNonce()
	_, err := chutes.ParseAttestationResponse(
		[]byte(`{"instances": [{"instance_id": "i", "e2e_pubkey": "k", "nonces": []}]}`),
		[]byte(`{"evidence": [], "failed_instance_ids": ["i"]}`),
		nonce,
	)
	if err == nil {
		t.Fatal("expected error for no evidence")
	}
	if !strings.Contains(err.Error(), "no evidence") {
		t.Errorf("error should mention no evidence, got: %v", err)
	}
}

func TestParseAttestationResponse_InstanceMismatch(t *testing.T) {
	nonce := attestation.NewNonce()
	_, err := chutes.ParseAttestationResponse(
		[]byte(`{"instances": [{"instance_id": "inst-AAA", "e2e_pubkey": "k", "nonces": []}]}`),
		[]byte(`{"evidence": [{"quote": "", "gpu_evidence": [], "instance_id": "inst-ZZZ", "certificate": ""}], "failed_instance_ids": []}`),
		nonce,
	)
	if err == nil {
		t.Fatal("expected error for instance mismatch")
	}
	if !strings.Contains(err.Error(), "not found in e2e instances") {
		t.Errorf("error should mention instance not found, got: %v", err)
	}
}

func TestParseAttestationResponse_InvalidBase64Quote(t *testing.T) {
	nonce := attestation.NewNonce()
	_, err := chutes.ParseAttestationResponse(
		[]byte(`{"instances": [{"instance_id": "i", "e2e_pubkey": "k", "nonces": []}]}`),
		[]byte(`{"evidence": [{"quote": "!!!bad!!!", "gpu_evidence": [], "instance_id": "i", "certificate": ""}], "failed_instance_ids": []}`),
		nonce,
	)
	if err == nil {
		t.Fatal("expected error for invalid base64 quote")
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Errorf("error should mention base64, got: %v", err)
	}
}

func TestParseAttestationResponse_EmptyQuote(t *testing.T) {
	nonce := attestation.NewNonce()
	raw, err := chutes.ParseAttestationResponse(
		[]byte(`{"instances": [{"instance_id": "i", "e2e_pubkey": "k", "nonces": []}]}`),
		[]byte(`{"evidence": [{"quote": "", "gpu_evidence": [], "instance_id": "i", "certificate": ""}], "failed_instance_ids": []}`),
		nonce,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw.IntelQuote != "" {
		t.Errorf("IntelQuote should be empty, got %q", raw.IntelQuote)
	}
}

func TestParseAttestationResponse_InvalidJSON(t *testing.T) {
	nonce := attestation.NewNonce()
	_, err := chutes.ParseAttestationResponse([]byte(`not json`), []byte(`{}`), nonce)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// --- FetchAttestation integration tests ---

// twoStepServer creates a test server that handles both the /e2e/instances/
// and /chutes/.../evidence endpoints.
func twoStepServer(t *testing.T, instancesResp, evidenceResp string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("request: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.HasPrefix(r.URL.Path, "/e2e/instances/"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(instancesResp))
		case strings.Contains(r.URL.Path, "/evidence"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(evidenceResp))
		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestFetchAttestation_Success(t *testing.T) {
	quote := fakeQuoteBase64()
	srv := twoStepServer(t,
		`{"instances": [{"instance_id": "inst-001", "e2e_pubkey": "dGVzdC1wdWJrZXk=", "nonces": ["n1"]}]}`,
		`{"evidence": [{"quote": "`+quote+`", "gpu_evidence": [{"certificate": "cert1", "evidence": "ev1", "arch": "HOPPER"}], "instance_id": "inst-001", "certificate": "dGxzLWNlcnQ="}], "failed_instance_ids": []}`,
	)
	defer srv.Close()

	a := chutes.NewAttester(srv.URL, "test-key")
	nonce := attestation.NewNonce()
	raw, err := a.FetchAttestation(context.Background(), "default", nonce)
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}
	if raw.IntelQuote != fakeQuoteHex() {
		t.Errorf("IntelQuote = %q, want %q", raw.IntelQuote, fakeQuoteHex())
	}
	if raw.SigningKey != "dGVzdC1wdWJrZXk=" {
		t.Errorf("SigningKey = %q, want e2e_pubkey", raw.SigningKey)
	}
}

func TestFetchAttestation_InstancesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error": "server error"}`))
	}))
	defer srv.Close()

	a := chutes.NewAttester(srv.URL, "test-key")
	_, err := a.FetchAttestation(context.Background(), "default", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error should mention HTTP status, got: %v", err)
	}
}

func TestFetchAttestation_SendsCorrectRequests(t *testing.T) {
	var requests []string
	var authHeaders []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.RequestURI())
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.HasPrefix(r.URL.Path, "/e2e/instances/"):
			_, _ = w.Write([]byte(`{"instances": [{"instance_id": "i", "e2e_pubkey": "k", "nonces": []}]}`))
		case strings.Contains(r.URL.Path, "/evidence"):
			quote := fakeQuoteBase64()
			_, _ = w.Write([]byte(`{"evidence": [{"quote": "` + quote + `", "gpu_evidence": [], "instance_id": "i", "certificate": ""}], "failed_instance_ids": []}`))
		}
	}))
	defer srv.Close()

	a := chutes.NewAttester(srv.URL, "sk-test-123")
	nonce := attestation.NewNonce()
	_, err := a.FetchAttestation(context.Background(), "deepseek-ai/DeepSeek-V3", nonce)
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if len(requests) != 2 {
		t.Fatalf("expected 2 requests, got %d: %v", len(requests), requests)
	}

	// Step 1: instances request
	if !strings.Contains(requests[0], "/e2e/instances/") {
		t.Errorf("first request should be instances, got: %s", requests[0])
	}

	// Step 2: evidence request with nonce
	if !strings.Contains(requests[1], "/chutes/") || !strings.Contains(requests[1], "/evidence") {
		t.Errorf("second request should be evidence, got: %s", requests[1])
	}
	if !strings.Contains(requests[1], "nonce="+nonce.Hex()) {
		t.Errorf("evidence request should contain nonce, got: %s", requests[1])
	}

	// Both requests should have auth
	for i, auth := range authHeaders {
		if auth != "Bearer sk-test-123" {
			t.Errorf("request %d Authorization = %q, want Bearer sk-test-123", i, auth)
		}
	}
}

func TestPreparer_SetsAuthHeader(t *testing.T) {
	p := chutes.NewPreparer("sk-test-123")
	req, _ := http.NewRequest(http.MethodPost, "https://llm.chutes.ai/v1/chat/completions", http.NoBody)

	if err := p.PrepareRequest(req, nil); err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}
	if req.Header.Get("Authorization") != "Bearer sk-test-123" {
		t.Errorf("Authorization = %q, want %q", req.Header.Get("Authorization"), "Bearer sk-test-123")
	}
}
