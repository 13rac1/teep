package nearroute

import "testing"

// The five non-chat models of 2026-11-14 get their endpoint kind; any other
// model gets the chat probe.
func TestUnprobedKind(t *testing.T) {
	for model, want := range map[string]string{
		"black-forest-labs/FLUX.2-klein-4B": "image generation",
		"Qwen/Qwen3-Embedding-0.6B":         "embeddings",
		"Qwen/Qwen3-Reranker-0.6B":          "reranking",
		"openai/whisper-large-v3":           "audio transcription",
		"openai/privacy-filter":             "an endpoint other than chat completions (unknown)",
	} {
		if kind, ok := UnprobedKind(model); !ok || kind != want {
			t.Errorf("%s: kind %q, %v; want %q", model, kind, ok, want)
		}
	}
	for _, model := range []string{"z-ai/glm-5.3-flash", "qwen/qwen3-embedding-0.6b", "Qwen/Qwen3-Embedding-0.6B-v2", ""} {
		if kind, ok := UnprobedKind(model); ok {
			t.Errorf("%q is not listed but got %q", model, kind)
		}
	}
}
