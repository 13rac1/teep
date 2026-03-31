package formatdetect_test

import (
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/formatdetect"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name string
		body string
		want attestation.BackendFormat
	}{
		{
			name: "tinfoil format field",
			body: `{"format":"tinfoil","other":"stuff"}`,
			want: attestation.FormatTinfoil,
		},
		{
			name: "chutes attestation_type",
			body: `{"attestation_type":"chutes","nonce":"abc","all_attestations":[]}`,
			want: attestation.FormatChutes,
		},
		{
			name: "gateway with gateway_attestation",
			body: `{"gateway_attestation":{"intel_quote":"abc"},"model_attestations":[]}`,
			want: attestation.FormatGateway,
		},
		{
			name: "dstack with intel_quote",
			body: `{"intel_quote":"deadbeef","signing_key":"04abc"}`,
			want: attestation.FormatDstack,
		},
		{
			name: "tinfoil takes priority over intel_quote",
			body: `{"format":"tinfoil","intel_quote":"deadbeef"}`,
			want: attestation.FormatTinfoil,
		},
		{
			name: "chutes takes priority over intel_quote",
			body: `{"attestation_type":"chutes","intel_quote":"deadbeef"}`,
			want: attestation.FormatChutes,
		},
		{
			name: "empty body",
			body: `{}`,
			want: "",
		},
		{
			name: "invalid JSON",
			body: `not json`,
			want: "",
		},
		{
			name: "null gateway_attestation is not gateway format",
			body: `{"gateway_attestation":null,"intel_quote":"abc"}`,
			want: attestation.FormatDstack,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatdetect.Detect([]byte(tt.body))
			if got != tt.want {
				t.Errorf("Detect() = %q, want %q", got, tt.want)
			}
		})
	}
}
