package proxy

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/reqid"
)

//go:embed testing.html
var testingPage string

// testRequest is the JSON body for POST /test/attest and POST /test/infer.
type testRequest struct {
	Model string `json:"model"`
}

// testInferResponse is the JSON response for POST /test/infer.
type testInferResponse struct {
	Model     string                          `json:"model"`
	Response  string                          `json:"response"`
	E2EE      bool                            `json:"e2ee"`
	Blocked   bool                            `json:"blocked"`
	LatencyMs int64                           `json:"latency_ms"`
	Report    *attestation.VerificationReport `json:"report,omitempty"`
	Error     string                          `json:"error,omitempty"`
}

// handleTestPage serves the interactive testing page at GET /test.
func (s *Server) handleTestPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := io.WriteString(w, testingPage); err != nil {
		slog.Error("write testing page", "err", err)
	}
}

// handleTestAttest triggers attestation for a model and returns the report.
func (s *Server) handleTestAttest(w http.ResponseWriter, r *http.Request) {
	ctx := reqid.WithID(r.Context(), reqid.New())

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	var req testRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}

	prov, upstreamModel, ok := s.resolveModel(req.Model)
	if !ok {
		http.Error(w, fmt.Sprintf("unknown model: %q", req.Model), http.StatusBadRequest)
		return
	}

	report, _ := s.fetchAndVerify(ctx, prov, upstreamModel)
	if report == nil {
		http.Error(w, "attestation fetch failed; see server logs", http.StatusBadGateway)
		return
	}

	s.cache.Put(prov.Name, upstreamModel, report)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(report); err != nil {
		slog.ErrorContext(ctx, "encode attest response", "err", err)
	}
}

// testInferPrompt is the hardcoded prompt for inference tests.
const testInferPrompt = "Say hello in one word."

// testInferMaxTokens is the max tokens for inference tests.
const testInferMaxTokens = 16

// handleTestInfer sends a test inference through the proxy's own handler.
func (s *Server) handleTestInfer(w http.ResponseWriter, r *http.Request) {
	ctx := reqid.WithID(r.Context(), reqid.New())

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	var req testRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if _, _, ok := s.resolveModel(req.Model); !ok {
		http.Error(w, fmt.Sprintf("unknown model: %q", req.Model), http.StatusBadRequest)
		return
	}

	chatReq := map[string]any{
		"model":      req.Model,
		"max_tokens": testInferMaxTokens,
		"messages": []map[string]string{
			{"role": "user", "content": testInferPrompt},
		},
	}
	chatBody, err := json.Marshal(chatReq)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	start := time.Now()
	resp := s.loopbackInfer(ctx, req.Model, chatBody)
	resp.LatencyMs = time.Since(start).Milliseconds()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.ErrorContext(ctx, "encode infer response", "err", err)
	}
}

// loopbackInfer sends a chat completion request through the proxy's own
// ServeHTTP, returning the parsed response or error details.
func (s *Server) loopbackInfer(ctx context.Context, model string, body []byte) testInferResponse {
	inner, err := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return testInferResponse{Model: model, Error: fmt.Sprintf("build request: %v", err)}
	}
	inner.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, inner)

	result := rec.Result()
	defer result.Body.Close()
	respBody, _ := io.ReadAll(result.Body)

	if result.StatusCode != http.StatusOK {
		// Try to parse as a verification report (502 blocked response).
		var report attestation.VerificationReport
		if err := json.Unmarshal(respBody, &report); err == nil && report.Provider != "" {
			return testInferResponse{
				Model:   model,
				Blocked: true,
				Report:  &report,
				Error:   fmt.Sprintf("attestation blocked (HTTP %d)", result.StatusCode),
			}
		}
		return testInferResponse{
			Model: model,
			Error: fmt.Sprintf("HTTP %d: %s", result.StatusCode, bytes.TrimSpace(respBody)),
		}
	}

	// Parse OpenAI chat completion response to extract the reply text.
	var chatResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return testInferResponse{
			Model: model,
			Error: fmt.Sprintf("failed to parse response: %v", err),
		}
	}

	var responseText string
	if len(chatResp.Choices) > 0 {
		responseText = chatResp.Choices[0].Message.Content
	}

	// Check cached report for E2EE status.
	provName, upstreamModel, _ := strings.Cut(model, ":")
	var e2ee bool
	if report, ok := s.cache.Get(provName, upstreamModel); ok {
		prov, provOK := s.providers[provName]
		e2ee = provOK && prov.E2EE && report.ReportDataBindingPassed()
	}

	return testInferResponse{
		Model:    model,
		Response: responseText,
		E2EE:     e2ee,
	}
}
