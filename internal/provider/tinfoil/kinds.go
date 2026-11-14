package tinfoil

// unprobedKinds lists, by exact model id, the Tinfoil models that serve no
// chat completions endpoint, with the endpoint that each serves. The E2EE
// probe of teep verify sends a chat completion, which these models answer
// with HTTP 404. A model that is not listed gets the chat probe, so a new
// model without chat completions fails e2ee_usable and is reported.
//
// Read from the `endpoints` field of Tinfoil's model list of 2026-11-14:
// every model whose list has no /v1/chat/completions. Reading that field at
// verification time, in place of this table, is a follow-up change.
var unprobedKinds = map[string]string{
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
}

// UnprobedKind returns the endpoint of a Tinfoil model that serves no chat
// completions endpoint, and false for any other model.
func UnprobedKind(model string) (string, bool) {
	kind, ok := unprobedKinds[model]
	return kind, ok
}
