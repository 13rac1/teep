package provider_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
)

// chutesFormatJSON builds a valid chutesResponse JSON blob with the given
// number of attestations. The first attestation uses the provided fields.
func chutesFormatJSON(t *testing.T, nonce, instanceID, e2ePubKey, intelQuoteB64 string, count int) []byte {
	t.Helper()

	type att struct {
		InstanceID  string                    `json:"instance_id"`
		Nonce       string                    `json:"nonce"`
		E2EPubKey   string                    `json:"e2e_pubkey"`
		IntelQuote  string                    `json:"intel_quote"`
		GPUEvidence []attestation.GPUEvidence `json:"gpu_evidence"`
	}

	attestations := make([]att, count)
	for i := range attestations {
		attestations[i] = att{
			InstanceID: instanceID,
			Nonce:      nonce,
			E2EPubKey:  e2ePubKey,
			IntelQuote: intelQuoteB64,
		}
		if i > 0 {
			attestations[i].InstanceID = instanceID + "-" + strings.Repeat("x", i)
		}
	}

	resp := map[string]any{
		"attestation_type": "TDX",
		"nonce":            nonce,
		"all_attestations": attestations,
	}

	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal chutes format: %v", err)
	}
	return b
}

func TestParseChutesFormat_HappyPath(t *testing.T) {
	quoteBytes := []byte("fake-tdx-quote-data-for-testing")
	quoteB64 := base64.StdEncoding.EncodeToString(quoteBytes)

	body := chutesFormatJSON(t, "test-nonce", "inst-42", "ml-kem-pub-key", quoteB64, 1)
	t.Logf("input body: %s", body)

	raw, err := provider.ParseChutesFormat(body, "test")
	if err != nil {
		t.Fatalf("ParseChutesFormat: %v", err)
	}

	t.Logf("BackendFormat=%q TEEProvider=%q SigningAlgo=%q TEEHardware=%q NonceSource=%q",
		raw.BackendFormat, raw.TEEProvider, raw.SigningAlgo, raw.TEEHardware, raw.NonceSource)
	t.Logf("SigningKey=%q Nonce=%q IntelQuote_prefix=%q",
		raw.SigningKey, raw.Nonce, safePrefix(raw.IntelQuote, 20))
	t.Logf("CandidatesAvail=%d CandidatesEval=%d", raw.CandidatesAvail, raw.CandidatesEval)

	if raw.BackendFormat != attestation.FormatChutes {
		t.Errorf("BackendFormat = %q, want %q", raw.BackendFormat, attestation.FormatChutes)
	}
	if raw.TEEProvider != "TDX+NVIDIA" {
		t.Errorf("TEEProvider = %q, want TDX+NVIDIA", raw.TEEProvider)
	}
	if raw.SigningAlgo != "ml-kem-768" {
		t.Errorf("SigningAlgo = %q, want ml-kem-768", raw.SigningAlgo)
	}
	if raw.TEEHardware != "intel-tdx" {
		t.Errorf("TEEHardware = %q, want intel-tdx", raw.TEEHardware)
	}
	if raw.NonceSource != "server" {
		t.Errorf("NonceSource = %q, want server", raw.NonceSource)
	}
	if raw.SigningKey != "ml-kem-pub-key" {
		t.Errorf("SigningKey = %q, want ml-kem-pub-key", raw.SigningKey)
	}
	if raw.Nonce != "test-nonce" {
		t.Errorf("Nonce = %q, want test-nonce", raw.Nonce)
	}
	// IntelQuote should be hex (not base64).
	if strings.Contains(raw.IntelQuote, "=") {
		t.Error("IntelQuote still contains base64 padding")
	}
	if raw.IntelQuote == "" {
		t.Error("IntelQuote is empty, expected hex")
	}
	if raw.CandidatesAvail != 1 {
		t.Errorf("CandidatesAvail = %d, want 1", raw.CandidatesAvail)
	}
	if raw.CandidatesEval != 1 {
		t.Errorf("CandidatesEval = %d, want 1", raw.CandidatesEval)
	}
	if raw.RawBody == nil {
		t.Error("RawBody is nil")
	}
}

func TestParseChutesFormat_EmptyAttestations(t *testing.T) {
	body := []byte(`{"attestation_type":"TDX","nonce":"n","all_attestations":[]}`)
	_, err := provider.ParseChutesFormat(body, "test")
	t.Logf("empty attestations error: %v", err)
	if err == nil {
		t.Fatal("expected error for empty all_attestations")
	}
}

func TestParseChutesFormat_TooManyAttestations(t *testing.T) {
	body := chutesFormatJSON(t, "n", "i", "k", "", 257)
	_, err := provider.ParseChutesFormat(body, "test")
	t.Logf("too many attestations error: %v", err)
	if err == nil {
		t.Fatal("expected error for 257 attestations (max 256)")
	}
}

func TestParseChutesFormat_TooManyGPUEvidence(t *testing.T) {
	// Build manually with 65 GPU evidence entries.
	gpus := make([]attestation.GPUEvidence, 65)
	for i := range gpus {
		gpus[i] = attestation.GPUEvidence{Certificate: "cert", Evidence: "ev"}
	}

	type att struct {
		InstanceID  string                    `json:"instance_id"`
		Nonce       string                    `json:"nonce"`
		E2EPubKey   string                    `json:"e2e_pubkey"`
		IntelQuote  string                    `json:"intel_quote"`
		GPUEvidence []attestation.GPUEvidence `json:"gpu_evidence"`
	}

	resp := map[string]any{
		"attestation_type": "TDX",
		"nonce":            "n",
		"all_attestations": []att{{
			InstanceID:  "i",
			E2EPubKey:   "k",
			GPUEvidence: gpus,
		}},
	}
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	_, err = provider.ParseChutesFormat(body, "test")
	t.Logf("too many GPU evidence error: %v", err)
	if err == nil {
		t.Fatal("expected error for 65 GPU evidence entries (max 64)")
	}
}

func TestParseChutesFormat_InvalidBase64Quote(t *testing.T) {
	body := chutesFormatJSON(t, "n", "i", "k", "not-valid-base64!!!", 1)
	_, err := provider.ParseChutesFormat(body, "test")
	t.Logf("invalid base64 error: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid base64 intel_quote")
	}
}

func TestParseChutesFormat_EmptyIntelQuote(t *testing.T) {
	body := chutesFormatJSON(t, "n", "i", "k", "", 1)
	raw, err := provider.ParseChutesFormat(body, "test")
	if err != nil {
		t.Fatalf("ParseChutesFormat: %v", err)
	}
	t.Logf("empty intel_quote: IntelQuote=%q", raw.IntelQuote)
	if raw.IntelQuote != "" {
		t.Errorf("IntelQuote = %q, want empty", raw.IntelQuote)
	}
}

func TestParseChutesFormat_InvalidJSON(t *testing.T) {
	_, err := provider.ParseChutesFormat([]byte("garbage{{{"), "test")
	t.Logf("invalid JSON error: %v", err)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseChutesFormat_MultipleAttestations(t *testing.T) {
	body := chutesFormatJSON(t, "n", "inst-1", "k", "", 3)
	raw, err := provider.ParseChutesFormat(body, "test")
	if err != nil {
		t.Fatalf("ParseChutesFormat: %v", err)
	}
	t.Logf("multiple attestations: CandidatesAvail=%d CandidatesEval=%d",
		raw.CandidatesAvail, raw.CandidatesEval)

	if raw.CandidatesAvail != 3 {
		t.Errorf("CandidatesAvail = %d, want 3", raw.CandidatesAvail)
	}
	if raw.CandidatesEval != 1 {
		t.Errorf("CandidatesEval = %d, want 1", raw.CandidatesEval)
	}
}

func TestParseChutesFormat_MaxBoundary(t *testing.T) {
	// 256 attestations should succeed (at the boundary).
	body := chutesFormatJSON(t, "n", "i", "k", "", 256)
	raw, err := provider.ParseChutesFormat(body, "test")
	if err != nil {
		t.Fatalf("ParseChutesFormat with 256 entries: %v", err)
	}
	t.Logf("max boundary: CandidatesAvail=%d", raw.CandidatesAvail)
	if raw.CandidatesAvail != 256 {
		t.Errorf("CandidatesAvail = %d, want 256", raw.CandidatesAvail)
	}
}

func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
