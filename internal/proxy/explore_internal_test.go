package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
)

func TestHandleExplorePage_Status(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/explore", http.NoBody)
	rec := httptest.NewRecorder()
	s.handleExplorePage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
}

func TestHandleExplorePage_ValidHTML(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/explore", http.NoBody)
	rec := httptest.NewRecorder()
	s.handleExplorePage(rec, req)

	body := rec.Body.String()
	if _, err := html.Parse(strings.NewReader(body)); err != nil {
		t.Fatalf("HTML parse error: %v", err)
	}
	if !strings.Contains(body, "teep") {
		t.Error("explore page missing 'teep' text")
	}
	if !strings.Contains(body, "/v1/models") {
		t.Error("explore page missing /v1/models fetch")
	}
}

func TestHandleExploreAttest_InvalidJSON(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/explore/attest", strings.NewReader("{bad"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleExploreAttest(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestHandleExploreAttest_EmptyModel(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/explore/attest", strings.NewReader(`{"model":""}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleExploreAttest(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestHandleExploreAttest_UnknownProvider(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/explore/attest", strings.NewReader(`{"model":"nope:model"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleExploreAttest(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "unknown model") {
		t.Errorf("body = %q, want 'unknown model' error", rec.Body.String())
	}
}

func TestHandleExploreInfer_InvalidJSON(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/explore/infer", strings.NewReader("{bad"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleExploreInfer(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestHandleExploreInfer_UnknownProvider(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/explore/infer", strings.NewReader(`{"model":"nope:model"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleExploreInfer(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// newExploreTestServer returns a Server with a mux, a mock provider, and a
// chat completions handler that returns a canned response. This enables
// testing loopbackInfer and the explore infer/attest success paths.
func newExploreTestServer(t *testing.T, chatHandler http.HandlerFunc) *Server {
	t.Helper()
	s := &Server{
		cfg:      &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:    attestation.NewCache(10 * time.Minute),
		negCache: attestation.NewNegativeCache(0),
		mux:      http.NewServeMux(),
		stats:    stats{startTime: time.Now(), models: make(map[string]*modelStats)},
		providers: map[string]*provider.Provider{
			"testprov": {
				Name:              "testprov",
				BaseURL:           "https://test.example.com",
				E2EE:              true,
				SupplyChainPolicy: attestation.NoSupplyChainPolicy(),
			},
		},
	}
	if chatHandler != nil {
		s.mux.HandleFunc("POST /v1/chat/completions", chatHandler)
	}
	return s
}

func TestLoopbackInfer_Success(t *testing.T) {
	s := newExploreTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": "Hello!"}},
			},
		})
	})

	// Pre-populate cache so E2EE check passes.
	s.cache.Put("testprov", "test-model", &attestation.VerificationReport{
		Provider: "testprov",
		Model:    "test-model",
		Factors: []attestation.FactorResult{
			{Name: attestation.FactorTEEReportData, Status: attestation.Pass},
		},
	})

	body, _ := json.Marshal(map[string]any{
		"model":      "testprov:test-model",
		"max_tokens": 16,
		"messages":   []map[string]string{{"role": "user", "content": "hi"}},
	})

	resp := s.loopbackInfer(context.Background(), "testprov:test-model", body)
	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	if resp.Response != "Hello!" {
		t.Errorf("response = %q, want %q", resp.Response, "Hello!")
	}
	if !resp.E2EE {
		t.Error("e2ee = false, want true (cached report with REPORTDATA binding pass)")
	}
	if resp.Blocked {
		t.Error("blocked = true, want false")
	}
}

func TestLoopbackInfer_HTTPError(t *testing.T) {
	s := newExploreTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	})

	body, _ := json.Marshal(map[string]any{
		"model":    "testprov:test-model",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})

	resp := s.loopbackInfer(context.Background(), "testprov:test-model", body)
	if resp.Error == "" {
		t.Fatal("expected error for HTTP 400")
	}
	if !strings.Contains(resp.Error, "HTTP 400") {
		t.Errorf("error = %q, want to contain 'HTTP 400'", resp.Error)
	}
}

func TestLoopbackInfer_BlockedResponse(t *testing.T) {
	s := newExploreTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(attestation.VerificationReport{
			Provider: "testprov",
			Model:    "test-model",
			Passed:   2,
			Failed:   3,
		})
	})

	body, _ := json.Marshal(map[string]any{
		"model":    "testprov:test-model",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})

	resp := s.loopbackInfer(context.Background(), "testprov:test-model", body)
	if !resp.Blocked {
		t.Error("blocked = false, want true")
	}
	if resp.Report == nil {
		t.Fatal("report = nil, want non-nil")
	}
	if resp.Report.Provider != "testprov" {
		t.Errorf("report.Provider = %q, want testprov", resp.Report.Provider)
	}
}

func TestLoopbackInfer_EmptyChoices(t *testing.T) {
	s := newExploreTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{}})
	})

	body, _ := json.Marshal(map[string]any{
		"model":    "testprov:test-model",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})

	resp := s.loopbackInfer(context.Background(), "testprov:test-model", body)
	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	if resp.Response != "" {
		t.Errorf("response = %q, want empty for no choices", resp.Response)
	}
}

func TestLoopbackInfer_NoE2EEWithoutCache(t *testing.T) {
	s := newExploreTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": "Hi"}},
			},
		})
	})

	body, _ := json.Marshal(map[string]any{
		"model":    "testprov:test-model",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})

	resp := s.loopbackInfer(context.Background(), "testprov:test-model", body)
	if resp.E2EE {
		t.Error("e2ee = true, want false when no cached report")
	}
}

func TestHandleExploreInfer_Success(t *testing.T) {
	s := newExploreTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": "Hello!"}},
			},
		})
	})

	req := httptest.NewRequest(http.MethodPost, "/explore/infer", strings.NewReader(`{"model":"testprov:test-model"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleExploreInfer(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var resp exploreInferResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Response != "Hello!" {
		t.Errorf("response = %q, want %q", resp.Response, "Hello!")
	}
	if resp.LatencyMs < 0 {
		t.Errorf("latency_ms = %d, want >= 0", resp.LatencyMs)
	}
}

func TestHandleExploreAttest_Success(t *testing.T) {
	s := newExploreTestServer(t, nil)
	s.providers["testprov"].Attester = &mockAttester{}

	req := httptest.NewRequest(http.MethodPost, "/explore/attest", strings.NewReader(`{"model":"testprov:test-model"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleExploreAttest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	var report attestation.VerificationReport
	if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if report.Provider != "testprov" {
		t.Errorf("Provider = %q, want testprov", report.Provider)
	}

	// Verify the report was cached.
	if _, ok := s.cache.Get("testprov", "test-model"); !ok {
		t.Error("attestation report not found in cache after successful attest")
	}
}

func TestHandleExploreAttest_NoAttester(t *testing.T) {
	s := newExploreTestServer(t, nil)
	// testprov has no Attester set, so fetchAndVerify returns nil.

	req := httptest.NewRequest(http.MethodPost, "/explore/attest", strings.NewReader(`{"model":"testprov:test-model"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleExploreAttest(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 when no attester", rec.Code)
	}
}

func TestHandleExploreAttest_CacheKeySuffix(t *testing.T) {
	s := newExploreTestServer(t, nil)
	s.providers["testprov"].Attester = &mockAttester{}
	s.providers["testprov"].CacheKeySuffix = func(_ context.Context, _ string) string {
		return "backend.example.com"
	}

	req := httptest.NewRequest(http.MethodPost, "/explore/attest", strings.NewReader(`{"model":"testprov:test-model"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleExploreAttest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	// Report must be cached under "test-model@backend.example.com", not "test-model".
	if _, ok := s.cache.Get("testprov", "test-model@backend.example.com"); !ok {
		t.Error("report not cached under suffixed key")
	}
	if _, ok := s.cache.Get("testprov", "test-model"); ok {
		t.Error("report cached under bare model name; CacheKeySuffix not applied")
	}
}

func TestLoopbackInfer_E2EEWithCacheKeySuffix(t *testing.T) {
	s := newExploreTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": "Hi"}},
			},
		})
	})
	s.providers["testprov"].CacheKeySuffix = func(_ context.Context, _ string) string {
		return "backend.example.com"
	}

	// Cache under the suffixed key, as the main proxy path would.
	s.cache.Put("testprov", "test-model@backend.example.com", &attestation.VerificationReport{
		Provider: "testprov",
		Model:    "test-model",
		Factors: []attestation.FactorResult{
			{Name: attestation.FactorTEEReportData, Status: attestation.Pass},
		},
	})

	body, _ := json.Marshal(map[string]any{
		"model":      "testprov:test-model",
		"max_tokens": 16,
		"messages":   []map[string]string{{"role": "user", "content": "hi"}},
	})

	resp := s.loopbackInfer(context.Background(), "testprov:test-model", body)
	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	if !resp.E2EE {
		t.Error("e2ee = false, want true (cached report under suffixed key)")
	}
}

func TestLoopbackInfer_LargeErrorBodyTruncated(t *testing.T) {
	largeBody := strings.Repeat("x", 2000)
	s := newExploreTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, largeBody, http.StatusInternalServerError)
	})

	body, _ := json.Marshal(map[string]any{
		"model":    "testprov:test-model",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})

	resp := s.loopbackInfer(context.Background(), "testprov:test-model", body)
	if resp.Error == "" {
		t.Fatal("expected error")
	}
	if len(resp.Error) > 600 {
		t.Errorf("error body not truncated: len=%d", len(resp.Error))
	}
	if !strings.Contains(resp.Error, "truncated") {
		t.Error("truncated error should contain 'truncated' indicator")
	}
}

func TestHandleExplorePage_WithProviders(t *testing.T) {
	s := newExploreTestServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/explore", http.NoBody)
	rec := httptest.NewRecorder()
	s.handleExplorePage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "testprov") {
		t.Error("explore page missing provider name 'testprov'")
	}
	if _, err := html.Parse(strings.NewReader(body)); err != nil {
		t.Fatalf("HTML parse error: %v", err)
	}
}

// TestHandleExplorePage_DegradedSurfacedFromCache verifies handleExplorePage
// walks the shared attestation cache (via summarizeProviderAttestations, the
// same helper buildDashboardData uses) so a waived-and-failing factor is
// visible in the embedded provider JSON as soon as any model is cached —
// proactively, without requiring an on-demand Attest click first.
func TestHandleExplorePage_DegradedSurfacedFromCache(t *testing.T) {
	s := newExploreTestServer(t, nil)
	s.cache.Put("testprov", "m1", &attestation.VerificationReport{
		Provider:      "testprov",
		Model:         "m1",
		AllowedFailed: 1,
		Factors: []attestation.FactorResult{
			{Name: attestation.FactorTEEReportData, Status: attestation.Pass, Enforced: true},
			{Name: attestation.FactorTEEHardwareConfig, Status: attestation.Fail, Enforced: false},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/explore", http.NoBody)
	rec := httptest.NewRecorder()
	s.handleExplorePage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	start := strings.Index(body, "var PROVIDERS = ")
	if start == -1 {
		t.Fatal("PROVIDERS assignment not found in explore page")
	}
	start += len("var PROVIDERS = ")
	end := strings.Index(body[start:], ";\n")
	if end == -1 {
		t.Fatal("could not find end of PROVIDERS JSON")
	}
	var infos []exploreProviderInfo
	if err := json.Unmarshal([]byte(body[start:start+end]), &infos); err != nil {
		t.Fatalf("unmarshal PROVIDERS JSON: %v\nraw: %s", err, body[start:start+end])
	}
	if len(infos) != 1 {
		t.Fatalf("infos len = %d, want 1", len(infos))
	}
	if !infos[0].Degraded {
		t.Error("infos[0].Degraded = false, want true")
	}
	if len(infos[0].WaivedFactors) != 1 || infos[0].WaivedFactors[0] != attestation.FactorTEEHardwareConfig {
		t.Errorf("infos[0].WaivedFactors = %v, want [%s]", infos[0].WaivedFactors, attestation.FactorTEEHardwareConfig)
	}
	if infos[0].AllowedFailed != 1 {
		t.Errorf("infos[0].AllowedFailed = %d, want 1", infos[0].AllowedFailed)
	}
	if infos[0].MissingE2EE {
		t.Error("infos[0].MissingE2EE = true, want false")
	}
}
