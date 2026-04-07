package neardirect_test

import (
	"context"
	"testing"

	"github.com/13rac1/teep/internal/provider/neardirect"
)

func FuzzParseAttestationResponse(f *testing.F) {
	// Flat response.
	f.Add([]byte(`{"intel_quote":"deadbeef","nvidia_payload":"eyJ0","signing_public_key":"abcd","signing_address":"0x123","signing_algo":"ed25519","tls_cert_fingerprint":"sha256:abc","request_nonce":"aabb","event_log":[],"info":{"tcb_info":{"app_compose":"{}"}}}`), "test-model")

	// model_attestations array.
	f.Add([]byte(`{"model_attestations":[{"model_name":"test-model","intel_quote":"dead","signing_public_key":"key1","request_nonce":"n1","event_log":[],"info":{"tcb_info":{"app_compose":"{}"}}}]}`), "test-model")

	// all_attestations array.
	f.Add([]byte(`{"all_attestations":[{"model_name":"m1","intel_quote":"beef","signing_public_key":"key2","request_nonce":"n2","event_log":[],"info":{"tcb_info":{"app_compose":"{}"}}}]}`), "m1")

	// Double-encoded tcb_info.
	f.Add([]byte(`{"intel_quote":"aa","request_nonce":"bb","info":{"tcb_info":"{\"app_compose\":\"{}\"}"}}`), "")

	// Edge cases.
	f.Add([]byte(`{}`), "")
	f.Add([]byte(`null`), "")
	f.Add([]byte(``), "model")
	f.Add([]byte(`not json`), "model")
	f.Add([]byte(`{"model_attestations":[]}`), "missing-model")

	f.Fuzz(func(t *testing.T, body []byte, model string) {
		result, err := neardirect.ParseAttestationResponse(context.Background(), body, model)
		if err == nil && result == nil {
			t.Error("ParseAttestationResponse returned nil, nil")
		}
	})
}
