package venice_test

import (
	"testing"

	"github.com/13rac1/teep/internal/provider/venice"
)

func TestACIInapplicableFactors(t *testing.T) {
	f := venice.ACIInapplicableFactors()

	expected := []string{
		"compose_binding",
		"build_transparency_log",
		"provider_signer_recognition",
		"component_signature_recognition",
		"sigstore_verification",
	}
	for _, name := range expected {
		if _, ok := f[name]; !ok {
			t.Errorf("ACIInapplicableFactors() missing %q", name)
		}
	}

	// component_recognition must NOT be inapplicable — ACI/1 uses
	// source_provenance.repo_url for component recognition.
	if _, ok := f["component_recognition"]; ok {
		t.Error("ACIInapplicableFactors() should not include component_recognition")
	}

	// event_log_integrity must NOT be inapplicable — ACI/1 has event logs.
	if _, ok := f["event_log_integrity"]; ok {
		t.Error("ACIInapplicableFactors() should not include event_log_integrity")
	}
}
