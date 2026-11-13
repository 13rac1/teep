package nanogpt_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/chutes/chutestest"
	"github.com/13rac1/teep/internal/provider/nanogpt"
)

// realEvidenceNonce is the nonce of the attestation request of
// testdata/chutes_evidence_qwen3.6-27b_2026-11-12.json: NanoGPT's answer for
// TEE/qwen3.6-27b on 2026-11-12, cut to its first 2 of 6 instances.
const realEvidenceNonce = "0d8048137820f6a9e12ccdd5a1cbf8a043269e2c35f83ba18846bf3534fdae2e"

func TestParseChutesEvidence_RealBody(t *testing.T) {
	body, err := os.ReadFile("testdata/chutes_evidence_qwen3.6-27b_2026-11-12.json")
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := attestation.ParseNonce(realEvidenceNonce)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := nanogpt.ParseAttestationResponse(context.Background(), body, nonce)
	if err != nil {
		t.Fatalf("ParseAttestationResponse: %v", err)
	}
	t.Logf("instance %s, %d/%d evaluated, %d GPUs", raw.InstanceID, raw.CandidatesEval, raw.CandidatesAvail, len(raw.GPUEvidence))
	if raw.BackendFormat != attestation.FormatChutes || raw.InstanceID != "6144b3c6-35ca-4c61-b6c8-5931c8ea15e2" {
		t.Errorf("BackendFormat = %q, InstanceID = %q", raw.BackendFormat, raw.InstanceID)
	}
	if raw.CandidatesAvail != 2 || raw.CandidatesEval != 1 {
		t.Errorf("candidates = %d/%d evaluated, want 1/2", raw.CandidatesEval, raw.CandidatesAvail)
	}
	if raw.SigningKey != "" {
		t.Errorf("SigningKey = %q, want none: the response names no E2EE key", raw.SigningKey)
	}
	if raw.IntelQuote == "" || len(raw.GPUEvidence) != 1 {
		t.Errorf("IntelQuote empty = %v, GPU evidence = %d, want a quote and 1 GPU", raw.IntelQuote == "", len(raw.GPUEvidence))
	}
	if len(raw.UnknownFields) != 0 || len(raw.MissingFields) != 0 {
		t.Errorf("UnknownFields = %q, MissingFields = %q, want none", raw.UnknownFields, raw.MissingFields)
	}

	// Each entry states the nonce of the request in its attested_body.
	if _, err := nanogpt.ParseAttestationResponse(context.Background(), body, attestation.NewNonce()); err == nil ||
		!strings.Contains(err.Error(), "attested_body nonce is not the nonce") {
		t.Errorf("ParseAttestationResponse(other nonce) err = %v, want the attested_body nonce failure", err)
	}
}

func evidenceIDs(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("inst-%d", i)
	}
	return ids
}

func TestParseChutesEvidence_InstanceBound(t *testing.T) {
	nonce := attestation.NewNonce()
	raw, err := nanogpt.ParseAttestationResponse(context.Background(),
		chutestest.Marshal(t, chutestest.Evidence(nonce, evidenceIDs(64)...)), nonce)
	if err != nil {
		t.Fatalf("64 instances: %v", err)
	}
	if raw.CandidatesAvail != 64 {
		t.Errorf("CandidatesAvail = %d, want 64", raw.CandidatesAvail)
	}
	_, err = nanogpt.ParseAttestationResponse(context.Background(),
		chutestest.Marshal(t, chutestest.Evidence(nonce, evidenceIDs(65)...)), nonce)
	if err == nil || !strings.Contains(err.Error(), "65 instances, max 64") {
		t.Fatalf("65 instances: err = %v, want the instance bound", err)
	}
}

func TestParseChutesEvidence_Refused(t *testing.T) {
	nonce := attestation.NewNonce()
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
		want   string
	}{
		{"duplicate instance id", func(d map[string]any) { chutestest.Entry(d, 1)["instance_id"] = "inst-0" }, "instance inst-0 is in evidence and in evidence"},
		{"no failed_instance_ids", func(d map[string]any) { delete(d, "failed_instance_ids") }, "no failed_instance_ids"},
		{"entry without attested_body", func(d map[string]any) { delete(chutestest.Entry(d, 0), "attested_body") }, "attested_body is not base64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := chutestest.Evidence(nonce, evidenceIDs(2)...)
			tc.change(doc)
			_, err := nanogpt.ParseAttestationResponse(context.Background(), chutestest.Marshal(t, doc), nonce)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A member that teep does not know is returned for the response_schema
// factor, not refused.
func TestParseChutesEvidence_UnknownMember(t *testing.T) {
	nonce := attestation.NewNonce()
	doc := chutestest.Evidence(nonce, evidenceIDs(1)...)
	doc["region"] = "eu"
	raw, err := nanogpt.ParseAttestationResponse(context.Background(), chutestest.Marshal(t, doc), nonce)
	if err != nil {
		t.Fatalf("ParseAttestationResponse: %v", err)
	}
	if strings.Join(raw.UnknownFields, " ") != "region" {
		t.Errorf("UnknownFields = %q, want [region]", raw.UnknownFields)
	}
}

// The attestation_type form of the Chutes format keeps its own parser.
func TestParseAttestationResponse_ChutesAttestationType(t *testing.T) {
	body := `{"attestation_type":"TDX","nonce":"n","all_attestations":[{"instance_id":"i","nonce":"n","e2e_pubkey":"k","intel_quote":"","gpu_evidence":[]}]}`
	raw, err := nanogpt.ParseAttestationResponse(context.Background(), []byte(body), attestation.NewNonce())
	if err != nil {
		t.Fatalf("ParseAttestationResponse: %v", err)
	}
	if raw.SigningKey != "k" {
		t.Errorf("SigningKey = %q, want k from the attestation_type parser", raw.SigningKey)
	}
}

// The attestation body is bounded at 8 MiB: a body of 8 MiB is read, a
// body one byte longer is refused before parsing.
func TestAttester_FetchAttestation_BodyBound(t *testing.T) {
	const limit = 8 << 20
	nonce := attestation.NewNonce()
	evidence := chutestest.Marshal(t, chutestest.Evidence(nonce, evidenceIDs(1)...))
	for _, tc := range []struct {
		size int
		want string
	}{
		{limit, ""},
		{limit + 1, "exceeds size limit 8388608"},
	} {
		t.Run(strconv.Itoa(tc.size), func(t *testing.T) {
			// JSON allows white space after the value.
			body := append(bytes.Clone(evidence), bytes.Repeat([]byte(" "), tc.size-len(evidence))...)
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
			}))
			defer srv.Close()
			a := nanogpt.NewAttester(srv.URL, "key")
			a.SetClient(srv.Client())
			_, err := a.FetchAttestation(context.Background(), "TEE/model", nonce)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("FetchAttestation: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
