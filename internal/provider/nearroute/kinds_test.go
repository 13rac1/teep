package nearroute

import "testing"

// The five non-chat models of 2026-11-14 get a full-sentence detail; any
// other model gets the chat probe.
func TestUnprobedDetail(t *testing.T) {
	for model, kind := range map[string]string{
		"black-forest-labs/FLUX.2-klein-4B": "image generation",
		"Qwen/Qwen3-Embedding-0.6B":         "embeddings",
		"Qwen/Qwen3-Reranker-0.6B":          "reranking",
		"openai/whisper-large-v3":           "audio transcription",
		"openai/privacy-filter":             "an endpoint other than chat completions (unknown)",
	} {
		detail, ok := UnprobedDetail(model)
		want := "not probed: the model serves " + kind + "; the verify probe sends a chat completion"
		if !ok || detail != want {
			t.Errorf("%s: detail %q, %v; want %q", model, detail, ok, want)
		}
	}
	for _, model := range []string{"z-ai/glm-5.3-flash", "qwen/qwen3-embedding-0.6b", "Qwen/Qwen3-Embedding-0.6B-v2", ""} {
		if detail, ok := UnprobedDetail(model); ok {
			t.Errorf("%q is not listed but got %q", model, detail)
		}
	}
}
