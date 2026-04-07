package formatdetect_test

import (
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/formatdetect"
)

// knownFormats is the set of valid BackendFormat return values (including empty).
var knownFormats = map[attestation.BackendFormat]bool{
	"":                        true,
	attestation.FormatDstack:  true,
	attestation.FormatChutes:  true,
	attestation.FormatTinfoil: true,
	attestation.FormatGateway: true,
	attestation.FormatNear:    true,
}

func FuzzDetect(f *testing.F) {
	// Seeds covering each format marker + edge cases.
	f.Add([]byte(`{"format":"tinfoil-v1"}`))
	f.Add([]byte(`{"attestation_type":"chutes"}`))
	f.Add([]byte(`{"gateway_attestation":{"intel_quote":"abc"}}`))
	f.Add([]byte(`{"intel_quote":"deadbeef"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`"just a string"`))
	f.Add([]byte(``))
	f.Add([]byte(`not json at all`))
	f.Add([]byte(`{"gateway_attestation":null}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		result := formatdetect.Detect(data)
		if !knownFormats[result] {
			t.Errorf("Detect returned unknown format %q", result)
		}
	})
}
