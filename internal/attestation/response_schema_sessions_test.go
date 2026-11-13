package attestation

import (
	"strings"
	"testing"
)

// response_schema reports the undefined members of the attested sessions
// with those of the attestation document.
func TestEvalResponseSchemaIncludesSessionMembers(t *testing.T) {
	in := &ReportInput{
		Raw:         &RawAttestation{UnknownFields: []string{"future"}},
		ACISessions: &ACISessionResult{UnknownFields: []string{"aci_sessions[0123456789ab].note"}},
	}
	f := assertSingleFactor(t, evalResponseSchema(in), Fail)
	for _, want := range []string{"future", "aci_sessions[0123456789ab].note"} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("detail %q does not name %s", f.Detail, want)
		}
	}
	if len(in.Raw.UnknownFields) != 1 {
		t.Errorf("evalResponseSchema changed the raw attestation: %v", in.Raw.UnknownFields)
	}
	assertSingleFactor(t, evalResponseSchema(&ReportInput{Raw: &RawAttestation{}, ACISessions: &ACISessionResult{}}), Pass)
}
