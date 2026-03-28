package multi_test

import (
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/multi"
	"github.com/13rac1/teep/internal/provider"
)

// fakeVerifier is a test stub that returns a fixed detail string.
type fakeVerifier struct {
	detail string
}

func (f fakeVerifier) VerifyReportData([64]byte, *attestation.RawAttestation, attestation.Nonce) (string, error) {
	return f.detail, nil
}

func TestVerifier_DispatchesByFormat(t *testing.T) {
	v := multi.Verifier{
		Verifiers: map[attestation.BackendFormat]provider.ReportDataVerifier{
			attestation.FormatDstack: fakeVerifier{detail: "dstack-ok"},
			attestation.FormatChutes: fakeVerifier{detail: "chutes-ok"},
		},
	}

	tests := []struct {
		format attestation.BackendFormat
		want   string
	}{
		{attestation.FormatDstack, "dstack-ok"},
		{attestation.FormatChutes, "chutes-ok"},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			raw := &attestation.RawAttestation{BackendFormat: tt.format}
			got, err := v.VerifyReportData([64]byte{}, raw, attestation.Nonce{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("detail = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVerifier_UnknownFormat(t *testing.T) {
	v := multi.Verifier{
		Verifiers: map[attestation.BackendFormat]provider.ReportDataVerifier{
			attestation.FormatDstack: fakeVerifier{detail: "dstack-ok"},
		},
	}

	raw := &attestation.RawAttestation{BackendFormat: attestation.FormatTinfoil}
	_, err := v.VerifyReportData([64]byte{}, raw, attestation.Nonce{})
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
	if !strings.Contains(err.Error(), "tinfoil") {
		t.Errorf("error should mention format, got: %v", err)
	}
}

func TestVerifier_EmptyFormat(t *testing.T) {
	v := multi.Verifier{
		Verifiers: map[attestation.BackendFormat]provider.ReportDataVerifier{
			attestation.FormatDstack: fakeVerifier{detail: "dstack-ok"},
		},
	}

	raw := &attestation.RawAttestation{BackendFormat: ""}
	_, err := v.VerifyReportData([64]byte{}, raw, attestation.Nonce{})
	if err == nil {
		t.Fatal("expected error for empty format")
	}
}
