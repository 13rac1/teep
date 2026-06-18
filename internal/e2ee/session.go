// Package e2ee provides end-to-end encryption primitives and relay functions
// for all TEE provider protocols. Each provider uses a different E2EE scheme:
//
//   - Venice:    secp256k1 ECDH + AES-256-GCM
//   - NearCloud: Ed25519/X25519 ECDH + XChaCha20-Poly1305
//   - Chutes:    ML-KEM-768 + ChaCha20-Poly1305
//
// Dependency flow: attestation → e2ee → provider → proxy → cmd
package e2ee

import "io"

// EndpointType identifies the canonical OpenAI-compatible endpoint for field
// encryption policy routing. These types are independent of provider-specific
// upstream paths; actual paths are documented at call sites.
type EndpointType string

const (
	// EndpointChat is /v1/chat/completions (or /api/v1/chat/completions for Venice).
	EndpointChat EndpointType = "chat"
	// EndpointEmbeddings is /v1/embeddings.
	EndpointEmbeddings EndpointType = "embeddings"
	// EndpointImages is /v1/images/generations.
	EndpointImages EndpointType = "images"
	// EndpointRerank is /v1/rerank.
	EndpointRerank EndpointType = "rerank"
	// EndpointScore is /v1/score.
	EndpointScore EndpointType = "score"
	// EndpointAudio is /v1/audio/transcriptions (multipart).
	EndpointAudio EndpointType = "audio"
	// EndpointResponses is /v1/responses.
	EndpointResponses EndpointType = "responses"
	// EndpointSpeech is /v1/audio/speech.
	EndpointSpeech EndpointType = "speech"
)

// EncField* constants identify the dot-notation sub-field paths within inference
// API JSON structures that are subject to field-level encryption. Each constant
// value is the exact path string passed to Decryptor.IsResponseFieldEncrypted
// and used as case labels in session policy switch statements. Named constants
// prevent silent typo mismatches between relay.go call sites and session policy
// definitions (nearcloud.go, venice.go).
const (
	EncFieldContent              = "content"
	EncFieldContentText          = "content[].text"
	EncFieldRefusal              = "refusal"
	EncFieldName                 = "name"
	EncFieldReasoning            = "reasoning"
	EncFieldReasoningContent     = "reasoning_content"
	EncFieldAudioData            = "audio.data"
	EncFieldFuncCallName         = "function_call.name"
	EncFieldFuncCallArgs         = "function_call.arguments"
	EncFieldToolCallsFuncName    = "tool_calls[].function.name"
	EncFieldToolCallsFuncArgs    = "tool_calls[].function.arguments"
	EncFieldLogprobsContentToken = "logprobs.content[].token"
	EncFieldLogprobsContentBytes = "logprobs.content[].bytes"
	EncFieldLogprobsRefusalToken = "logprobs.refusal[].token" //nolint:gosec // G101 false positive: enc path constant, not a credential
	EncFieldLogprobsRefusalBytes = "logprobs.refusal[].bytes"
	EncFieldB64JSON              = "b64_json"
	EncFieldRevisedPrompt        = "revised_prompt"
	EncFieldEmbedding            = "embedding"
	EncFieldRerankDocumentText   = "results[].document.text"
	EncFieldScore                = "score"
)

// Decryptor is implemented by field-level E2EE sessions used by relay
// decryption (for example, Venice and NearCloud/NearDirect sessions). Chutes
// uses a dedicated full-body relay path via ChutesE2EE/ChutesSession.
//
// It provides the minimum surface that relay functions and the proxy need to
// decrypt response content and clean up key material.
type Decryptor interface {
	IsEncryptedChunk(val string) bool
	Decrypt(ciphertextHex string) ([]byte, error)
	// IsResponseFieldEncrypted checks if the given field path requires encryption
	// at the specified endpoint type (chat, embeddings, images, etc.).
	// Endpoint types are canonical OpenAI route kinds; actual provider paths
	// (e.g., /v1/chat/completions vs /api/v1/chat/completions) are documented
	// at call sites.
	IsResponseFieldEncrypted(fieldPath string, endpoint EndpointType) bool
	Zero()
}

// EncryptResult carries the outcome of a single EncryptRequest call.
// Exactly one of Session, Chutes, or EHBP is non-nil for E2EE requests.
// For EHBP, BodyReader is set instead of Body (streaming encryption).
type EncryptResult struct {
	Body       []byte       // field-level E2EE (Venice, NearCloud)
	BodyReader io.Reader    // EHBP streaming encrypted body
	Session    Decryptor    // Venice, NearCloud field-level E2EE
	Chutes     *ChutesE2EE  // Chutes full-body relay state
	EHBP       *EHBPSession // Tinfoil EHBP full-body state
}

// ChutesE2EE carries the per-request state for the Chutes E2EE protocol:
// routing metadata (headers) and the crypto session (for relay decryption).
// It is returned by EncryptRequest and passed through the proxy to both
// PrepareRequest (for headers) and the relay functions (for decryption).
type ChutesE2EE struct {
	ChuteID    string         // X-Chute-Id header value (the model name)
	InstanceID string         // X-Instance-Id header value
	E2ENonce   string         // X-E2E-Nonce header value (single-use token)
	Session    *ChutesSession // ML-KEM session for relay decryption
}
