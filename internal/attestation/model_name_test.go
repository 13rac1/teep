package attestation

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// An exact model name logs nothing; a name that contains or is contained in
// the requested one logs at info level; another name logs at warn level.
// Each record names both models.
func TestLogModelNameMatch(t *testing.T) {
	for _, tc := range []struct {
		match, wantLevel string
	}{
		{"", ""},
		{"contains", "INFO"},
		{"differs", "WARN"},
	} {
		var buf bytes.Buffer
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
		LogModelNameMatch(context.Background(), "neardirect", "requested/model", &RawAttestation{Model: "attested/model", ModelNameMatch: tc.match})
		slog.SetDefault(previous)
		out := buf.String()
		if tc.wantLevel == "" {
			if out != "" {
				t.Errorf("exact name logged %q", out)
			}
			continue
		}
		if !strings.Contains(out, "level="+tc.wantLevel) || !strings.Contains(out, "requested_model=requested/model") || !strings.Contains(out, "attested_model=attested/model") {
			t.Errorf("match %q logged %q, want level %s with both names", tc.match, out, tc.wantLevel)
		}
	}
}

// The report carries the attested name only when it is not the requested
// one.
func TestBuildReportAttestedModel(t *testing.T) {
	for _, tc := range []struct {
		match, wantModel string
	}{
		{"", ""},
		{"contains", "attested/model"},
		{"differs", "attested/model"},
	} {
		r := BuildReport(&ReportInput{Provider: "neardirect", Model: "requested/model", Raw: &RawAttestation{Model: "attested/model", ModelNameMatch: tc.match}, Nonce: NewNonce()})
		if r.AttestedModel != tc.wantModel || r.AttestedModelMatch != tc.match {
			t.Errorf("match %q: report attested model %q, match %q", tc.match, r.AttestedModel, r.AttestedModelMatch)
		}
	}
}
