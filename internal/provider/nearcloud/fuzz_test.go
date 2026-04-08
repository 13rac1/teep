package nearcloud_test

import (
	"context"
	"testing"

	"github.com/13rac1/teep/internal/provider/nearcloud"
)

func FuzzParseGatewayResponse(f *testing.F) {
	// Gateway with model_attestations.
	f.Add([]byte(`{"gateway_attestation":{"request_nonce":"aabb","intel_quote":"dead","tls_cert_fingerprint":"sha256:abc","info":{"tcb_info":{"app_compose":"{}"}}},"model_attestations":[{"model_name":"m1","intel_quote":"beef","signing_public_key":"key1","request_nonce":"n1","event_log":[],"info":{"tcb_info":{"app_compose":"{}"}}}]}`), "m1")

	// Gateway with event_log string.
	f.Add([]byte(`{"gateway_attestation":{"request_nonce":"cc","intel_quote":"dd","tls_cert_fingerprint":"fp","event_log":"[{\"imr\":0,\"event\":\"boot\",\"event_type\":\"type\",\"digest\":\"abc\"}]","info":{"tcb_info":{"app_compose":"{}"}}},"model_attestations":[{"model_name":"m1","intel_quote":"ee","signing_public_key":"k1","request_nonce":"n1","event_log":[],"info":{"tcb_info":{"app_compose":"{}"}}}]}`), "m1")

	// Empty gateway section.
	f.Add([]byte(`{"gateway_attestation":{}}`), "m1")

	// Edge cases.
	f.Add([]byte(`{}`), "")
	f.Add([]byte(`null`), "")
	f.Add([]byte(``), "model")
	f.Add([]byte(`not json`), "model")
	f.Add([]byte(`{"gateway_attestation":{"intel_quote":"aa","tls_cert_fingerprint":"bb"}}`), "missing")

	f.Fuzz(func(t *testing.T, body []byte, model string) {
		gw, raw, err := nearcloud.ParseGatewayResponse(context.Background(), body, model)
		if err == nil && (gw == nil || raw == nil) {
			t.Errorf("ParseGatewayResponse returned nil result without error: gw=%v raw=%v", gw, raw)
		}
	})
}
