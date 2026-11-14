package phalacloud

import "testing"

// The four models without text output in Phala Cloud's model list of
// 2026-11-14 get their kind; any other model gets the chat probe.
func TestUnprobedKind(t *testing.T) {
	for model, want := range map[string]string{
		"black-forest-labs/flux.2-klein-4b": "image generation",
		"openai/whisper-large-v3":           "audio transcription",
		"mistralai/voxtral-small-24b-2507":  "audio transcription",
		"jaredpalmer/kev-4b":                "/v1/systemone",
	} {
		if kind, ok := UnprobedKind(model); !ok || kind != want {
			t.Errorf("%s: kind %q, %v; want %q", model, kind, ok, want)
		}
	}
	for _, model := range []string{"z-ai/glm-5.3", "openai/whisper-large-v3-turbo", "Jaredpalmer/kev-4b", ""} {
		if kind, ok := UnprobedKind(model); ok {
			t.Errorf("%q is not listed but got %q", model, kind)
		}
	}
}
