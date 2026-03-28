package chutes_test

import (
	"encoding/base64"
	"encoding/hex"
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

func TestParseAttestationResponse_ChutesFormat(t *testing.T) {
	quote := fakeQuoteBase64()
	body := []byte(`{
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
	}`)

	raw, err := chutes.ParseAttestationResponse(body)
	if err != nil {
		t.Fatalf("ParseAttestationResponse: %v", err)
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

func TestParseAttestationResponse_MultipleAttestations(t *testing.T) {
	quote1 := base64.StdEncoding.EncodeToString([]byte("quote-one"))
	quote2 := base64.StdEncoding.EncodeToString([]byte("quote-two"))
	body := []byte(`{
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
	}`)

	raw, err := chutes.ParseAttestationResponse(body)
	if err != nil {
		t.Fatalf("ParseAttestationResponse: %v", err)
	}
	wantHex := hex.EncodeToString([]byte("quote-one"))
	if raw.IntelQuote != wantHex {
		t.Errorf("IntelQuote = %q, want first entry hex = %q", raw.IntelQuote, wantHex)
	}
	if raw.CandidatesAvail != 2 {
		t.Errorf("CandidatesAvail = %d, want 2", raw.CandidatesAvail)
	}
}

func TestParseAttestationResponse_EmptyAttestations(t *testing.T) {
	body := []byte(`{
		"attestation_type": "chutes",
		"nonce": "0000000000000000000000000000000000000000000000000000000000000000",
		"all_attestations": []
	}`)
	_, err := chutes.ParseAttestationResponse(body)
	if err == nil {
		t.Fatal("expected error for empty all_attestations")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error should mention empty, got: %v", err)
	}
}

func TestParseAttestationResponse_InvalidJSON(t *testing.T) {
	_, err := chutes.ParseAttestationResponse([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseAttestationResponse_InvalidBase64Quote(t *testing.T) {
	body := []byte(`{
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
	}`)
	_, err := chutes.ParseAttestationResponse(body)
	if err == nil {
		t.Fatal("expected error for invalid base64 intel_quote")
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Errorf("error should mention base64, got: %v", err)
	}
}

func TestParseAttestationResponse_EmptyIntelQuote(t *testing.T) {
	body := []byte(`{
		"attestation_type": "chutes",
		"nonce": "0000000000000000000000000000000000000000000000000000000000000000",
		"all_attestations": [{
			"instance_id": "i",
			"nonce": "0000000000000000000000000000000000000000000000000000000000000000",
			"e2e_pubkey": "k",
			"intel_quote": "",
			"gpu_evidence": []
		}]
	}`)
	raw, err := chutes.ParseAttestationResponse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw.IntelQuote != "" {
		t.Errorf("IntelQuote should be empty, got %q", raw.IntelQuote)
	}
}
