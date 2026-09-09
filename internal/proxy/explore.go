package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/reqid"
)

// exploreRequest is the JSON body for POST /explore/attest and POST /explore/infer.
type exploreRequest struct {
	Model string `json:"model"`
}

// exploreInferResponse is the JSON response for POST /explore/infer.
type exploreInferResponse struct {
	Model     string                          `json:"model"`
	Response  string                          `json:"response"`
	E2EE      bool                            `json:"e2ee"`
	Blocked   bool                            `json:"blocked"`
	LatencyMs int64                           `json:"latency_ms"`
	Report    *attestation.VerificationReport `json:"report,omitempty"`
	Error     string                          `json:"error,omitempty"`
}

// exploreProviderInfo is the per-provider metadata injected into the explore template.
type exploreProviderInfo struct {
	Name   string `json:"name"`
	Pinned bool   `json:"pinned"`
	E2EE   bool   `json:"e2ee"`
}

// exploreTemplateData is the template data for the explore page.
type exploreTemplateData struct {
	ProvidersJSON template.JS
}

// handleExplorePage serves the interactive explore page at GET /explore.
func (s *Server) handleExplorePage(w http.ResponseWriter, r *http.Request) {
	infos := make([]exploreProviderInfo, 0, len(s.providers))
	for _, p := range s.providers {
		infos = append(infos, exploreProviderInfo{
			Name:   p.Name,
			Pinned: p.UsesTLSBinding,
			E2EE:   p.E2EE,
		})
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })

	raw, err := json.Marshal(infos)
	if err != nil {
		slog.ErrorContext(r.Context(), "marshal provider info", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := exploreTemplateData{
		ProvidersJSON: template.JS(raw), //nolint:gosec // G203: raw is server-generated JSON from json.Marshal, not user input
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "explore", data); err != nil {
		slog.ErrorContext(r.Context(), "write explore page", "err", err)
	}
}

// handleExploreAttest triggers attestation for a model and returns the report.
func (s *Server) handleExploreAttest(w http.ResponseWriter, r *http.Request) {
	ctx := reqid.WithID(r.Context(), reqid.New())

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	var req exploreRequest
	if _, _, err := jsonstrict.UnmarshalWarn(body, &req, "explore attest request"); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}

	prov, upstreamModel, ok := s.resolveModel(req.Model)
	if !ok {
		http.Error(w, fmt.Sprintf("unknown model: %q", req.Model), http.StatusBadRequest)
		return
	}

	if prov.UsesTLSBinding {
		route, key, routeErr := resolveRequestRoute(ctx, prov, upstreamModel)
		if routeErr != nil {
			http.Error(w, "resolve route failed", http.StatusBadGateway)
			return
		}
		value, blocked, loadErr := s.loadAuthorization(ctx, prov, route, key)
		if loadErr != nil {
			http.Error(w, "authorization failed", http.StatusBadGateway)
			return
		}
		report := blocked
		if value != nil {
			report = value.report
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(report); err != nil {
			slog.ErrorContext(ctx, "encode attest response", "err", err)
		}
		return
	}

	report, _ := s.fetchAndVerify(ctx, prov, upstreamModel)
	if report == nil {
		http.Error(w, "attestation fetch failed; see server logs", http.StatusBadGateway)
		return
	}

	s.cache.Put(prov.Name, cacheModelFor(ctx, upstreamModel), report)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(report); err != nil {
		slog.ErrorContext(ctx, "encode attest response", "err", err)
	}
}

const (
	// exploreInferPrompt is the hardcoded prompt for inference tests.
	exploreInferPrompt = "Say hello in one word."
	// exploreInferMaxTokens is the max tokens for inference tests.
	exploreInferMaxTokens = 16
)

// handleExploreInfer sends a test inference through the proxy's own handler.
func (s *Server) handleExploreInfer(w http.ResponseWriter, r *http.Request) {
	ctx := reqid.WithID(r.Context(), reqid.New())

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	var req exploreRequest
	if _, _, err := jsonstrict.UnmarshalWarn(body, &req, "explore infer request"); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if _, _, ok := s.resolveModel(req.Model); !ok {
		http.Error(w, fmt.Sprintf("unknown model: %q", req.Model), http.StatusBadRequest)
		return
	}

	chatReq := map[string]any{
		"model":      req.Model,
		"max_tokens": exploreInferMaxTokens,
		"messages": []map[string]string{
			{"role": "user", "content": exploreInferPrompt},
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
// endpoint handler, returning the parsed response or error details.
func (s *Server) loopbackInfer(ctx context.Context, model string, body []byte) exploreInferResponse {
	inner, err := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return exploreInferResponse{Model: model, Error: fmt.Sprintf("build request: %v", err)}
	}
	inner.Header.Set("Content-Type", "application/json")

	rec := newInferenceRecorder()
	var usedReport *attestation.VerificationReport
	var usedE2EE bool
	if prov, _, ok := s.resolveModel(model); ok && prov.UsesTLSBinding {
		s.endpointHandler(&chatEndpoint, func(report *attestation.VerificationReport, encrypted bool) {
			usedReport, usedE2EE = report, encrypted
		})(rec, inner)
	} else {
		s.ServeHTTP(rec, inner)
	}

	result := rec.Result()
	defer result.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(result.Body, 1<<20)) // 1 MB cap

	if result.StatusCode != http.StatusOK {
		// Try to parse as a verification report (502 blocked response).
		var report attestation.VerificationReport
		if err := json.Unmarshal(respBody, &report); err == nil && report.Provider != "" {
			return exploreInferResponse{
				Model:   model,
				Blocked: true,
				Report:  &report,
				Error:   fmt.Sprintf("attestation blocked (HTTP %d)", result.StatusCode),
			}
		}
		errBody := bytes.TrimSpace(respBody)
		if len(errBody) > 512 {
			errBody = append(errBody[:512], []byte("... (truncated)")...)
		}
		return exploreInferResponse{
			Model: model,
			Error: fmt.Sprintf("HTTP %d: %s", result.StatusCode, errBody),
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
		return exploreInferResponse{
			Model: model,
			Error: fmt.Sprintf("failed to parse response: %v", err),
		}
	}

	var responseText string
	if len(chatResp.Choices) > 0 {
		responseText = chatResp.Choices[0].Message.Content
	}

	// Non-TLS-binding providers retain the model-scoped report cache.
	var encrypted bool
	if prov, upModel, ok := s.resolveModel(model); ok && !prov.UsesTLSBinding {
		cacheKey := cacheModelFor(ctx, upModel)
		if report, cacheOK := s.cache.Get(prov.Name, cacheKey); cacheOK {
			encrypted = prov.E2EE && report.ReportDataBindingPassed()
		}
	}

	if usedReport != nil {
		encrypted = usedE2EE && usedReport.ReportDataBindingPassed()
	}
	return exploreInferResponse{
		Report:   usedReport,
		Model:    model,
		Response: responseText,
		E2EE:     encrypted,
	}
}

// inferenceRecorder collects the explore response in memory. Its writes never
// wait for network capacity, but must still respect the attempt deadline.
type inferenceRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func newInferenceRecorder() *inferenceRecorder {
	return &inferenceRecorder{ResponseRecorder: httptest.NewRecorder()}
}

func (r *inferenceRecorder) SetWriteDeadline(deadline time.Time) error {
	r.deadline = deadline
	return nil
}

func (r *inferenceRecorder) Write(body []byte) (int, error) {
	if !r.deadline.IsZero() && !time.Now().Before(r.deadline) {
		return 0, context.DeadlineExceeded
	}
	return r.ResponseRecorder.Write(body)
}
