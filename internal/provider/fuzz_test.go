package provider_test

import (
	"context"
	"testing"

	"github.com/13rac1/teep/internal/provider"
)

func FuzzUnwrapDoubleEncoded(f *testing.F) {
	f.Add([]byte(`"{"key":"value"}"`))          // double-encoded string
	f.Add([]byte(`{"key":"value"}`))            // direct object
	f.Add([]byte(`"just a string"`))            // plain string
	f.Add([]byte(`not json`))                   // invalid
	f.Add([]byte(``))                           // empty
	f.Add([]byte(`null`))                       // null
	f.Add([]byte(`""`))                         // empty string
	f.Add([]byte(`"\"nested\\\"quotes\\\"\""`)) // nested escaping

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = provider.UnwrapDoubleEncoded(data)
	})
}

func FuzzParseChutesFormat(f *testing.F) {
	f.Add([]byte(`{"attestation_type":"chutes","nonce":"abc","all_attestations":[{"instance_id":"i1","nonce":"n1","e2e_pubkey":"pk1","intel_quote":"dGVzdA==","gpu_evidence":[]}]}`))
	f.Add([]byte(`{"attestation_type":"chutes","nonce":"abc","all_attestations":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"attestation_type":"chutes","all_attestations":[{"intel_quote":"!!!"}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := provider.ParseChutesFormat(context.Background(), data, "fuzz")
		if err == nil && result == nil {
			t.Error("ParseChutesFormat returned nil, nil")
		}
	})
}
