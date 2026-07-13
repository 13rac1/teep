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
		{
			name: "present but empty intel_quote is still dstack (key presence, not value)",
			body: `{"model":"test-model","intel_quote":"","signing_key":""}`,
			want: attestation.FormatDstack,
		},
		{
			name: "absent intel_quote key is not dstack",
			body: `{"model":"test-model","signing_key":""}`,
			want: "",
		},
		{
			name: "aci/1 api_version",
			body: `{"api_version":"aci/1","intel_quote":"deadbeef"}`,
			want: attestation.FormatACI1,
		},
		{
			name: "aci/1 takes priority over intel_quote (ACI/1 bodies also carry intel_quote)",
			body: `{"api_version":"aci/1","intel_quote":"deadbeef","attestation":{}}`,
			want: attestation.FormatACI1,
		},
		{
			name: "unknown api_version fails closed, not a silent dstack fallback",
			body: `{"api_version":"aci/2","intel_quote":"deadbeef"}`,
			want: "",
		},
		{
			name: "tinfoil takes priority over aci/1",
			body: `{"format":"tinfoil","api_version":"aci/1","intel_quote":"deadbeef"}`,
			want: attestation.FormatTinfoil,
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
