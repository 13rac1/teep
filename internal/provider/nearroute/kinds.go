package nearroute

// unprobedKinds lists, by exact model id, the NEAR models of owned_by
// "nearai" that serve an endpoint other than chat completions, with the kind
// of that endpoint. The E2EE probe of teep verify sends a chat completion,
// which these models refuse as a malformed request. A model that is not
// listed gets the chat probe, so a new non-chat model fails e2ee_usable and
// is reported.
//
// Observed on 2026-11-14: NEAR answered the chat probe of each with HTTP
// 400 (nearcloud) or 404 (neardirect), and FLUX.2 with 502 or 500.
var unprobedKinds = map[string]string{
	"black-forest-labs/FLUX.2-klein-4B": "image generation",    // /v1/images/generations
	"Qwen/Qwen3-Embedding-0.6B":         "embeddings",          // /v1/embeddings
	"Qwen/Qwen3-Reranker-0.6B":          "reranking",           // /v1/rerank
	"openai/whisper-large-v3":           "audio transcription", // /v1/audio/transcriptions
	// NEAR documents no endpoint for this model, and it refuses chat
	// completions.
	"openai/privacy-filter": "an endpoint other than chat completions (unknown)",
}

// UnprobedKind returns the endpoint kind of a NEAR model that serves an
// endpoint other than chat completions, and false for any other model.
func UnprobedKind(model string) (string, bool) {
	kind, ok := unprobedKinds[model]
	return kind, ok
}
