package nanogpt_test

import (
	"context"
	"testing"

	"github.com/13rac1/teep/internal/provider/nanogpt"
)

func FuzzParseAttestationResponse(f *testing.F) {
	// Dstack format.
	f.Add([]byte(`{"intel_quote":"deadbeef","signing_public_key":"key1","signing_address":"0x1","signing_algo":"ecdsa","request_nonce":"aabb","event_log":[],"info":{"app_name":"app","tcb_info":{"app_compose":"{}"}}}`))

	// Dstack with all_attestations.
	f.Add([]byte(`{"intel_quote":"aa","all_attestations":[{"intel_quote":"bb","signing_public_key":"k2","event_log":[],"info":{"tcb_info":{"app_compose":"{}"}}}]}`))

	// Chutes format.
	f.Add([]byte(`{"attestation_type":"chutes","nonce":"abc","all_attestations":[{"instance_id":"i1","nonce":"n1","e2e_pubkey":"pk1","intel_quote":"dGVzdA==","gpu_evidence":[]}]}`))

	// Tinfoil (unsupported).
	f.Add([]byte(`{"format":"tinfoil-v1","data":"..."}`))

	// Gateway (unsupported).
	f.Add([]byte(`{"gateway_attestation":{"intel_quote":"abc"}}`))

	// event_log as string.
	f.Add([]byte(`{"intel_quote":"cc","event_log":"[{\"imr\":0,\"event\":\"boot\",\"event_type\":\"t\",\"digest\":\"d\"}]","info":{"tcb_info":{"app_compose":"{}"}}}`))

	// Double-encoded tcb_info.
	f.Add([]byte(`{"intel_quote":"dd","info":{"tcb_info":"{\"app_compose\":\"{}\"}"}}`))

	// Edge cases.
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, body []byte) {
		result, err := nanogpt.ParseAttestationResponse(context.Background(), body)
		if err == nil && result == nil {
			t.Error("ParseAttestationResponse returned nil, nil")
		}
	})
}
