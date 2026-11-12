package verify

import (
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
)

// The report text states the attested model name when it is not the
// requested one, and whether one name contains the other.
func TestFormatReportAttestedModel(t *testing.T) {
	for _, tc := range []struct {
		match, want string
	}{
		{"", ""},
		{"contains", "Attested model: attested/model (requested requested/model; one name contains the other)"},
		{"differs", "Attested model: attested/model (requested requested/model; neither name contains the other)"},
	} {
		r := &attestation.VerificationReport{Provider: "neardirect", Model: "requested/model", AttestedModelMatch: tc.match}
		if tc.match != "" {
			r.AttestedModel = "attested/model"
		}
		text := FormatReport(r)
		if tc.want == "" {
			if strings.Contains(text, "Attested model") {
				t.Errorf("exact name printed an attested model line: %q", text)
			}
			continue
		}
		if !strings.Contains(text, tc.want) {
			t.Errorf("report %q lacks %q", text, tc.want)
		}
	}
}
