package provider_test

import (
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
