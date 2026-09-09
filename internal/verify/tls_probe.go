package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider/nearparse"
)

func nearTLSOnly(opts *Options) bool {
	return (opts.ProviderName == "nearcloud" || opts.ProviderName == "neardirect") && !opts.Provider.E2EE
}

func tlsInferenceFromCapture(value *capture.TLSInferenceOutcome) *attestation.TLSInferenceResult {
	if value == nil {
		return nil
	}
	return &attestation.TLSInferenceResult{Attempted: value.Attempted, Failed: value.Failed, Detail: value.Detail}
}
func tlsInferenceToCapture(value *attestation.TLSInferenceResult) *capture.TLSInferenceOutcome {
	if value == nil {
		return nil
	}
	return &capture.TLSInferenceOutcome{Attempted: value.Attempted, Failed: value.Failed, Detail: value.Detail}
}

func completeTLSOnlyInference(result *verificationOutcome, err error) {
	if result.tlsInference == nil {
		result.tlsInference = &attestation.TLSInferenceResult{Attempted: true}
	}
	result.tlsInference.Attempted = true
	if err != nil {
		result.tlsInference.Failed = true
		result.tlsInference.Detail = fmt.Sprintf("TLS-only streaming chat probe failed: %v", err)
	}
	if result.report != nil {
		result.report.MarkTLSInference(result.tlsInference)
	}
}

// verifyTLSOnlyStream requires a completed chat stream, without claiming E2EE verification.
func verifyTLSOnlyStream(resp *http.Response) error {
	scanner, cleanup := e2ee.NewSSEScanner(resp.Body)
	defer cleanup()
	chunks := 0
	textSeen := false
	for scanner.Scan() {
		line := scanner.Text()
		if err := e2ee.CheckSSEEvent(line); err != nil {
			return err
		}
		data, ok := e2ee.SSEData(line)
		if !ok {
			continue
		}
		if data == "[DONE]" {
			if err := e2ee.FinishSSE(scanner); err != nil {
				return err
			}
			if chunks == 0 || !textSeen {
				return errors.New("TLS-only chat stream contained no text output")
			}
			return nil
		}
		hasText, err := parseTLSOnlyChunk([]byte(data))
		if err != nil {
			return err
		}
		textSeen = textSeen || hasText
		chunks++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return errors.New("TLS-only chat stream ended without completion marker")
}

// parseTLSOnlyChunk accepts provider extensions but requires each supported
// structural boundary. Null content is valid; null choices and deltas are not.
func parseTLSOnlyChunk(data []byte) (bool, error) {
	var chunk struct {
		Object  string            `json:"object"`
		Choices []json.RawMessage `json:"choices"`
		Error   json.RawMessage   `json:"error,omitempty"`
	}
	// This caller permits extensions, but excludes them before typed decoding.
	// Exact field names are required at every boundary that contributes to success.
	_, err := nearparse.Object(data, &chunk, "chunk", "error")
	if err != nil {
		return false, errors.New("TLS-only chat stream contains invalid chunk")
	}
	if len(chunk.Error) != 0 && string(bytes.TrimSpace(chunk.Error)) != "null" {
		return false, errors.New("upstream TLS-only chat stream error")
	}
	if chunk.Object != "chat.completion.chunk" {
		return false, errors.New("TLS-only probe did not receive a chat completion chunk")
	}
	textSeen := false
	for _, choice := range chunk.Choices {
		hasText, err := parseTLSOnlyChoice(choice)
		if err != nil {
			return false, err
		}
		textSeen = textSeen || hasText
	}
	return textSeen, nil
}

func parseTLSOnlyChoice(data []byte) (bool, error) {
	var choice struct {
		Delta json.RawMessage `json:"delta"`
	}
	if _, err := nearparse.Object(data, &choice, "choice"); err != nil {
		return false, errors.New("TLS-only chat stream contains invalid choice")
	}
	var delta struct {
		Content          *string `json:"content,omitempty"`
		ReasoningContent *string `json:"reasoning_content,omitempty"`
	}
	if _, err := nearparse.Object(choice.Delta, &delta, "delta", "content", "reasoning_content"); err != nil {
		return false, errors.New("TLS-only chat stream contains invalid delta")
	}
	return (delta.Content != nil && *delta.Content != "") || (delta.ReasoningContent != nil && *delta.ReasoningContent != ""), nil
}
