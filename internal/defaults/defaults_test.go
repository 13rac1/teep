package defaults_test

import (
	"testing"

	"github.com/13rac1/teep/internal/defaults"
)

func TestMeasurementDefaults_KnownProviders(t *testing.T) {
	providers := []string{"venice", "neardirect", "nearcloud", "nanogpt", "chutes", "tinfoil_v3_cloud", "tinfoil_v3_direct"}

	for _, name := range providers {
		t.Run(name, func(t *testing.T) {
			model, gateway := defaults.MeasurementDefaults(name)
			if len(model.MRSeamAllow) == 0 {
				t.Errorf("model MRSeamAllow should not be empty for %q", name)
			}
			t.Logf("%s: model MRSeam=%d, RTMR0=%d",
				name, len(model.MRSeamAllow), len(model.RTMRAllow[0]))

			if name == "nearcloud" {
				if len(gateway.MRSeamAllow) == 0 {
					t.Error("nearcloud gateway MRSeamAllow should not be empty")
				}
			}
		})
	}
}

func TestMeasurementDefaults_UnknownProvider(t *testing.T) {
	model, gateway := defaults.MeasurementDefaults("nonexistent")
	if len(model.MRSeamAllow) != 0 {
		t.Error("unknown provider should return zero-value model policy")
	}
	if len(gateway.MRSeamAllow) != 0 {
		t.Error("unknown provider should return zero-value gateway policy")
	}
}
