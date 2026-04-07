package phalacloud_test

import (
	"context"
	"testing"

	"github.com/13rac1/teep/internal/provider/phalacloud"
)

func FuzzParseAttestationResponse(f *testing.F) {
	// Chutes format.
	f.Add([]byte(`{"attestation_type":"chutes","nonce":"abc","all_attestations":[{"instance_id":"i1","nonce":"n1","e2e_pubkey":"pk1","intel_quote":"dGVzdA==","gpu_evidence":[]}]}`))

	// Dstack format.
	f.Add([]byte(`{"intel_quote":"deadbeef","signing_public_key":"key1","signing_address":"0x1","request_nonce":"aabb","event_log":[],"info":{"app_name":"app","tcb_info":{"app_compose":"{}"}}}`))

	// Tinfoil (unsupported).
	f.Add([]byte(`{"format":"tinfoil-v1","data":"..."}`))

	// Gateway (unsupported).
	f.Add([]byte(`{"gateway_attestation":{"intel_quote":"abc"}}`))

	// Edge cases.
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, body []byte) {
		result, err := phalacloud.ParseAttestationResponse(context.Background(), body)
		if err == nil && result == nil {
			t.Error("ParseAttestationResponse returned nil, nil")
		}
	})
}
