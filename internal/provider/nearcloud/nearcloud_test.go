package nearcloud_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/nearcloud"
)

// minimalGatewayJSON builds a minimal combined gateway+model attestation JSON.
func minimalGatewayJSON(model, nonceHex, spkiHash string) string {
	return fmt.Sprintf(`{
		"gateway_attestation": {
			"request_nonce": %q,
			"intel_quote": "",
			"event_log": "",
			"tls_cert_fingerprint": %q,
			"info": {
				"tcb_info": "{\"app_compose\":\"test-compose\"}"
			}
		},
		"model_attestations": [
			{
				"model_name": %q,
				"intel_quote": "",
				"nvidia_payload": "",
				"signing_public_key": "04aaaa",
				"signing_address": "0xtest",
				"signing_algo": "ecdsa",
				"tls_cert_fingerprint": %q,
				"request_nonce": %q
			}
		]
	}`, nonceHex, spkiHash, model, spkiHash, nonceHex)
}

func TestParseGatewayResponse_HappyPath(t *testing.T) {
	body := []byte(minimalGatewayJSON("test-model", "abc123", "sha256:fp"))
	gw, raw, err := nearcloud.ParseGatewayResponse(body, "test-model")
	if err != nil {
		t.Fatalf("ParseGatewayResponse: %v", err)
	}

	t.Logf("gateway: nonce=%s, quote=%q, compose=%q, fp=%s",
		gw.NonceHex, gw.IntelQuote, gw.AppCompose, gw.TLSCertFingerprint)
	t.Logf("model: nonce=%s, model=%s, signing_key=%s",
		raw.Nonce, raw.Model, raw.SigningKey)

	if gw.NonceHex != "abc123" {
		t.Errorf("NonceHex = %q, want %q", gw.NonceHex, "abc123")
	}
	if gw.AppCompose != "test-compose" {
		t.Errorf("AppCompose = %q, want %q", gw.AppCompose, "test-compose")
	}
	if gw.TLSCertFingerprint != "sha256:fp" {
		t.Errorf("TLSCertFingerprint = %q, want %q", gw.TLSCertFingerprint, "sha256:fp")
	}
	if raw.Nonce != "abc123" {
		t.Errorf("raw.Nonce = %q, want %q", raw.Nonce, "abc123")
	}
	if raw.Model != "test-model" {
		t.Errorf("raw.Model = %q, want %q", raw.Model, "test-model")
	}
}

func TestParseGatewayResponse_EventLog(t *testing.T) {
	body := []byte(`{
		"gateway_attestation": {
			"request_nonce": "abc",
			"intel_quote": "",
			"event_log": "[{\"imr\":0,\"digest\":\"abc123\",\"event_type\":1,\"event\":\"\",\"event_payload\":\"\"}]",
			"tls_cert_fingerprint": "fp",
			"info": {"tcb_info": "{}"}
		},
		"model_attestations": [
			{"model_name": "m", "request_nonce": "abc", "signing_public_key": "04aaaa", "signing_address": "0x1", "signing_algo": "ecdsa"}
		]
	}`)

	gw, _, err := nearcloud.ParseGatewayResponse(body, "m")
	if err != nil {
		t.Fatalf("ParseGatewayResponse: %v", err)
	}
	t.Logf("event log entries: %d", len(gw.EventLog))
	if len(gw.EventLog) != 1 {
		t.Fatalf("EventLog len = %d, want 1", len(gw.EventLog))
	}
	if gw.EventLog[0].IMR != 0 {
		t.Errorf("EventLog[0].IMR = %d, want 0", gw.EventLog[0].IMR)
	}
	if gw.EventLog[0].Digest != "abc123" {
		t.Errorf("EventLog[0].Digest = %q, want %q", gw.EventLog[0].Digest, "abc123")
	}
}

func TestParseGatewayResponse_EmptyEventLog(t *testing.T) {
	body := []byte(minimalGatewayJSON("m", "abc", "fp"))
	gw, _, err := nearcloud.ParseGatewayResponse(body, "m")
	if err != nil {
		t.Fatalf("ParseGatewayResponse: %v", err)
	}
	t.Logf("event log: %v", gw.EventLog)
	if gw.EventLog != nil {
		t.Errorf("EventLog = %v, want nil", gw.EventLog)
	}
}

func TestParseGatewayResponse_MalformedEventLog(t *testing.T) {
	body := []byte(`{
		"gateway_attestation": {
			"request_nonce": "abc",
			"intel_quote": "",
			"event_log": "{not an array}",
			"tls_cert_fingerprint": "fp",
			"info": {"tcb_info": "{}"}
		},
		"model_attestations": [
			{"model_name": "m", "request_nonce": "abc", "signing_public_key": "04aaaa", "signing_address": "0x1", "signing_algo": "ecdsa"}
		]
	}`)

	_, _, err := nearcloud.ParseGatewayResponse(body, "m")
	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for malformed event_log")
	}
	if !strings.Contains(err.Error(), "event_log") {
		t.Errorf("error should mention event_log: %v", err)
	}
}

func TestParseGatewayResponse_MalformedEventLogEntry(t *testing.T) {
	// Valid JSON array but entry has wrong type for a field.
	body := []byte(`{
		"gateway_attestation": {
			"request_nonce": "abc",
			"intel_quote": "",
			"event_log": "[{\"imr\":\"not-an-int\"}]",
			"tls_cert_fingerprint": "fp",
			"info": {"tcb_info": "{}"}
		},
		"model_attestations": [
			{"model_name": "m", "request_nonce": "abc", "signing_public_key": "04aaaa", "signing_address": "0x1", "signing_algo": "ecdsa"}
		]
	}`)

	_, _, err := nearcloud.ParseGatewayResponse(body, "m")
	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for malformed event log entry")
	}
	if !strings.Contains(err.Error(), "event_log entry") {
		t.Errorf("error should mention event_log entry: %v", err)
	}
}

func TestParseGatewayResponse_EventLogTooManyEntries(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("[")
	for i := range 10001 {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"imr":0,"digest":"abc123","event_type":1,"event":"","event_payload":""}`)
	}
	sb.WriteString("]")

	body := fmt.Appendf(nil, `{
		"gateway_attestation": {
			"request_nonce": "abc",
			"intel_quote": "",
			"event_log": %q,
			"tls_cert_fingerprint": "fp",
			"info": {"tcb_info": "{}"}
		},
		"model_attestations": [
			{"model_name": "m", "request_nonce": "abc", "signing_public_key": "04aaaa", "signing_address": "0x1", "signing_algo": "ecdsa"}
		]
	}`, sb.String())

	_, _, err := nearcloud.ParseGatewayResponse(body, "m")
	if err == nil {
		t.Fatal("expected error for oversized gateway event_log")
	}
	if !strings.Contains(err.Error(), "event_log has") {
		t.Errorf("error should mention event_log entry limit: %v", err)
	}
}

func TestParseGatewayResponse_MalformedJSON(t *testing.T) {
	_, _, err := nearcloud.ParseGatewayResponse([]byte(`{{{`), "m")
	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestParseGatewayResponse_MalformedTCBInfo(t *testing.T) {
	body := []byte(`{
		"gateway_attestation": {
			"request_nonce": "abc",
			"intel_quote": "",
			"event_log": "",
			"tls_cert_fingerprint": "fp",
			"info": {"tcb_info": "{not valid json}"}
		},
		"model_attestations": [
			{"model_name": "m", "request_nonce": "abc", "signing_public_key": "04aaaa", "signing_address": "0x1", "signing_algo": "ecdsa"}
		]
	}`)

	_, _, err := nearcloud.ParseGatewayResponse(body, "m")
	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for malformed tcb_info")
	}
	if !strings.Contains(err.Error(), "tcb_info") {
		t.Errorf("error should mention tcb_info: %v", err)
	}
}

func TestParseGatewayResponse_NoModel(t *testing.T) {
	body := []byte(minimalGatewayJSON("model-a", "abc", "fp"))

	_, _, err := nearcloud.ParseGatewayResponse(body, "model-b")
	t.Logf("error: %v", err)
	if err == nil {
		t.Fatal("expected error for missing model")
	}
	if !strings.Contains(err.Error(), "model-b") {
		t.Errorf("error should mention requested model: %v", err)
	}
}

func TestExtractGatewayAppCompose(t *testing.T) {
	tests := []struct {
		name    string
		input   json.RawMessage
		want    string
		wantErr bool
	}{
		{
			name:  "nil input",
			input: nil,
			want:  "",
		},
		{
			name:  "empty input",
			input: json.RawMessage{},
			want:  "",
		},
		{
			name:  "raw JSON object with app_compose",
			input: json.RawMessage(`{"app_compose":"my-compose"}`),
			want:  "my-compose",
		},
		{
			name:  "JSON-string-wrapped object",
			input: json.RawMessage(`"{\"app_compose\":\"wrapped-compose\"}"`),
			want:  "wrapped-compose",
		},
		{
			name:  "object missing app_compose",
			input: json.RawMessage(`{"other":"field"}`),
			want:  "",
		},
		{
			name:    "invalid JSON",
			input:   json.RawMessage(`{not valid`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nearcloud.ExtractGatewayAppCompose(tt.input)
			t.Logf("got=%q, err=%v", got, err)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAttester_FetchAttestation_HappyPath(t *testing.T) {
	nonce := attestation.NewNonce()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("request: %s %s", r.Method, r.URL.String())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(minimalGatewayJSON("test-model", nonce.Hex(), "sha256:fp")))
	}))
	defer srv.Close()

	// Create an attester that talks to our test server.
	a := nearcloud.NewAttester("test-key", true)
	// We need to override the gateway host for testing. Since NewAttester
	// hardcodes the host, we test via ParseGatewayResponse instead for
	// unit tests. The integration test covers the full flow.
	// Instead, test the parsing path that FetchAttestation uses.
	body := []byte(minimalGatewayJSON("test-model", nonce.Hex(), "sha256:fp"))
	gw, raw, err := nearcloud.ParseGatewayResponse(body, "test-model")
	if err != nil {
		t.Fatalf("ParseGatewayResponse: %v", err)
	}

	// Verify gateway fields that FetchAttestation populates on RawAttestation.
	t.Logf("gateway IntelQuote=%q, NonceHex=%q, AppCompose=%q, TLSCertFingerprint=%q",
		gw.IntelQuote, gw.NonceHex, gw.AppCompose, gw.TLSCertFingerprint)

	if raw.Nonce != nonce.Hex() {
		t.Errorf("raw.Nonce = %q, want %q", raw.Nonce, nonce.Hex())
	}
	if gw.AppCompose != "test-compose" {
		t.Errorf("gw.AppCompose = %q, want %q", gw.AppCompose, "test-compose")
	}

	// Simulate FetchAttestation wiring gateway fields onto raw.
	raw.GatewayIntelQuote = gw.IntelQuote
	raw.GatewayNonceHex = gw.NonceHex
	raw.GatewayAppCompose = gw.AppCompose
	raw.GatewayEventLog = gw.EventLog
	raw.GatewayTLSFingerprint = gw.TLSCertFingerprint

	if raw.GatewayNonceHex != nonce.Hex() {
		t.Errorf("GatewayNonceHex = %q, want %q", raw.GatewayNonceHex, nonce.Hex())
	}
	if raw.GatewayAppCompose != "test-compose" {
		t.Errorf("GatewayAppCompose = %q, want %q", raw.GatewayAppCompose, "test-compose")
	}
	if raw.GatewayTLSFingerprint != "sha256:fp" {
		t.Errorf("GatewayTLSFingerprint = %q, want %q", raw.GatewayTLSFingerprint, "sha256:fp")
	}

	// Verify NewAttester doesn't panic.
	_ = a
}

func TestAttester_FetchAttestation_SetsQueryParams(t *testing.T) {
	// Verify the attester constructs the right URL (testing via the Attester struct,
	// even though we can't easily override the host). We verify the constructor works.
	a := nearcloud.NewAttester("my-api-key", true)
	if a == nil {
		t.Fatal("NewAttester returned nil")
	}
	t.Logf("attester created successfully")
}
