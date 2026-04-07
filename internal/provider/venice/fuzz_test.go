package venice_test

import (
	"context"
	"testing"

	"github.com/13rac1/teep/internal/provider/venice"
)

func FuzzParseAttestationResponse(f *testing.F) {
	// Full response with event_log array.
	f.Add([]byte(`{"verified":true,"nonce":"aabb","model":"llama3","tee_provider":"TDX","signing_public_key":"key1","signing_address":"0x1","intel_quote":"dead","nvidia_payload":"eyJ0","event_log":[{"imr":0,"event":"boot","event_type":"type","digest":"abc"}],"info":{"app_name":"app","compose_hash":"ch","device_id":"d1","tcb_info":{"app_compose":"{}"}}}`))

	// event_log as double-encoded string.
	f.Add([]byte(`{"verified":false,"nonce":"cc","model":"m2","tee_provider":"TDX","signing_public_key":"k2","signing_address":"0x2","intel_quote":"beef","nvidia_payload":"","event_log":"[{\"imr\":0,\"event\":\"boot\",\"event_type\":\"t\",\"digest\":\"d\"}]","info":{"tcb_info":{"app_compose":"{}"}}}`))

	// Double-encoded tcb_info.
	f.Add([]byte(`{"nonce":"dd","model":"m3","intel_quote":"aa","info":{"tcb_info":"{\"app_compose\":\"{}\"}"}}`))

	// server_verification present.
	f.Add([]byte(`{"nonce":"ee","model":"m4","intel_quote":"bb","server_verification":{"tdx":{"valid":true},"nvidia":{"valid":false}},"info":{"tcb_info":{"app_compose":"{}"}}}`))

	// Edge cases.
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"event_log":12345}`))

	f.Fuzz(func(t *testing.T, body []byte) {
		result, err := venice.ParseAttestationResponse(context.Background(), body)
		if err == nil && result == nil {
			t.Error("ParseAttestationResponse returned nil, nil")
		}
	})
}
