package tinfoil

import "testing"

// The ten models without chat completions in Tinfoil's model list of
// 2026-11-14 get their endpoint; any other model gets the chat probe.
func TestUnprobedKind(t *testing.T) {
	for model, want := range map[string]string{
		"nomic-embed-text":         "/v1/embeddings",
		"pii-filter":               "/redact",
		"doc-upload":               "/v1/convert/file",
		"whisper-large-v3-turbo":   "/v1/audio/transcriptions",
		"qwen3-tts":                "/v1/audio/speech",
		"voxtral-tts":              "/v1/audio/speech",
		"voxtral-mini-4b-realtime": "/v1/realtime",
		"decision-large":           "/v1/decisions",
		"decision-medium":          "/v1/decisions",
		"decision-small":           "/v1/decisions",
	} {
		if kind, ok := UnprobedKind(model); !ok || kind != want {
			t.Errorf("%s: kind %q, %v; want %q", model, kind, ok, want)
		}
	}
	for _, model := range []string{"gpt-oss-120b", "voxtral-small-24b", "websearch", "Nomic-Embed-Text", ""} {
		if kind, ok := UnprobedKind(model); ok {
			t.Errorf("%q is not listed but got %q", model, kind)
		}
	}
}
