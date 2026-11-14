package phalacloud

// unprobedKinds lists, by exact model id, the Phala Cloud models whose output
// is not text, with the endpoint kind that each serves. The E2EE probe of
// teep verify sends a chat completion; on 2026-11-14 the gateway answered it
// for jaredpalmer/kev-4b with HTTP 404 "no route available for model". A
// model that is not listed gets the chat probe, so a new model without chat
// completions fails e2ee_usable and is reported.
//
// Read from Phala Cloud's model list of 2026-11-14: every model whose output
// modality is not text. The list has no endpoint field, so the kind follows
// from the modalities, except for jaredpalmer/kev-4b, whose description names
// its endpoint.
var unprobedKinds = map[string]string{
	"black-forest-labs/flux.2-klein-4b": "image generation",    // text → image
	"openai/whisper-large-v3":           "audio transcription", // audio → transcription
	"mistralai/voxtral-small-24b-2507":  "audio transcription", // audio → transcription
	"jaredpalmer/kev-4b":                "/v1/systemone",       // text → decisions; named in the description
}

// UnprobedKind returns the endpoint kind of a Phala Cloud model whose output
// is not text, and false for any other model.
func UnprobedKind(model string) (string, bool) {
	kind, ok := unprobedKinds[model]
	return kind, ok
}
