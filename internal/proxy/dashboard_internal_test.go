package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		cfg:      &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:    attestation.NewCache(0),
		negCache: attestation.NewNegativeCache(0),
		stats:    stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}
}

func TestHandleHealth_NoRequests(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/health", http.NoBody)
	rec := httptest.NewRecorder()
	s.handleHealth(rec, req)

	t.Logf("status=%d body=%s", rec.Code, rec.Body.String())

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var resp struct {
		Status        string  `json:"status"`
		UptimeSeconds float64 `json:"uptime_seconds"`
		LastRequestAt *string `json:"last_request_at"`
		LastSuccessAt *string `json:"last_success_at"`
		RequestsTotal int64   `json:"requests_total"`
		ErrorsTotal   int64   `json:"errors_total"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	t.Logf("status=%s uptime=%.3f last_request_at=%v last_success_at=%v requests=%d errors=%d",
		resp.Status, resp.UptimeSeconds, resp.LastRequestAt, resp.LastSuccessAt, resp.RequestsTotal, resp.ErrorsTotal)

	if resp.Status != "ok" {
		t.Errorf("status = %q, want ok", resp.Status)
	}
	if resp.UptimeSeconds <= 0 {
		t.Errorf("uptime_seconds = %f, want > 0", resp.UptimeSeconds)
	}
	if resp.LastRequestAt != nil {
		t.Errorf("last_request_at = %v, want null when no requests", resp.LastRequestAt)
	}
	if resp.LastSuccessAt != nil {
		t.Errorf("last_success_at = %v, want null when no requests", resp.LastSuccessAt)
	}
	if resp.RequestsTotal != 0 {
		t.Errorf("requests_total = %d, want 0", resp.RequestsTotal)
	}
}

func TestHandleHealth_WithRequests(t *testing.T) {
	s := newTestServer(t)

	now := time.Now()
	s.stats.requests.Store(5)
	s.stats.errors.Store(1)
	s.stats.lastRequestAt.Store(now.Add(-10 * time.Second).UnixNano())
	s.stats.lastSuccessAt.Store(now.Add(-15 * time.Second).UnixNano())

	req := httptest.NewRequest(http.MethodGet, "/health", http.NoBody)
	rec := httptest.NewRecorder()
	s.handleHealth(rec, req)

	t.Logf("status=%d body=%s", rec.Code, rec.Body.String())

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var resp struct {
		Status        string  `json:"status"`
		LastRequestAt *string `json:"last_request_at"`
		LastSuccessAt *string `json:"last_success_at"`
		RequestsTotal int64   `json:"requests_total"`
		ErrorsTotal   int64   `json:"errors_total"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	t.Logf("status=%s last_request_at=%v last_success_at=%v requests=%d errors=%d",
		resp.Status, resp.LastRequestAt, resp.LastSuccessAt, resp.RequestsTotal, resp.ErrorsTotal)

	if resp.LastRequestAt == nil {
		t.Error("last_request_at is null, want RFC3339 timestamp")
	} else {
		if _, err := time.Parse(time.RFC3339, *resp.LastRequestAt); err != nil {
			t.Errorf("last_request_at %q is not valid RFC3339: %v", *resp.LastRequestAt, err)
		}
	}
	if resp.LastSuccessAt == nil {
		t.Error("last_success_at is null, want RFC3339 timestamp")
	}
	if resp.RequestsTotal != 5 {
		t.Errorf("requests_total = %d, want 5", resp.RequestsTotal)
	}
	if resp.ErrorsTotal != 1 {
		t.Errorf("errors_total = %d, want 1", resp.ErrorsTotal)
	}
}

func TestHitRateString(t *testing.T) {
	tests := []struct {
		hits, misses int64
		want         string
	}{
		{0, 0, "—"},
		{1, 0, "100%"},
		{0, 1, "0%"},
		{1, 1, "50%"},
		{3, 1, "75%"},
		{1, 3, "25%"},
		{99, 1, "99%"},
		{1000, 0, "100%"},
	}
	for _, tt := range tests {
		got := hitRateString(tt.hits, tt.misses)
		t.Logf("hitRateString(%d, %d) = %q", tt.hits, tt.misses, got)
		if got != tt.want {
			t.Errorf("hitRateString(%d, %d) = %q, want %q", tt.hits, tt.misses, got, tt.want)
		}
	}
}

func TestBuildDashboardData_NonZeroModelStats(t *testing.T) {
	s := &Server{
		cfg:      &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:    attestation.NewCache(0),
		negCache: attestation.NewNegativeCache(0),
		stats:    stats{models: make(map[string]*modelStats)},
		providers: map[string]*provider.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: "https://api.venice.ai",
				E2EE:    true,
			},
		},
	}

	// Add a model with non-zero stats.
	ms := &modelStats{}
	ms.requests.Store(5)
	ms.errors.Store(1)
	ms.lastVerifyMs.Store(250)                                       // 250ms verify time
	ms.lastTokDurMs.Store(2000)                                      // 2s token duration
	ms.lastTokCount.Store(100)                                       // 100 tokens in 2 seconds = 50 tok/s
	ms.lastRequestAt.Store(time.Now().Add(-30 * time.Second).Unix()) // "30s ago"
	s.stats.modelsMu.Lock()
	s.stats.models["test-model"] = ms
	s.stats.modelsMu.Unlock()

	data := s.buildDashboardData()
	t.Logf("buildDashboardData: listen_addr=%s uptime=%s e2ee=%s",
		data.ListenAddr, data.Uptime, data.Provider.E2EE)
	t.Logf("provider: name=%s e2ee=%s", data.Provider.Name, data.Provider.E2EE)

	if data.Provider.E2EE != "enabled" {
		t.Errorf("Provider.E2EE = %q, want 'enabled'", data.Provider.E2EE)
	}
	if data.Provider.Name != "venice" {
		t.Errorf("Provider.Name = %q, want 'venice'", data.Provider.Name)
	}

	model, ok := data.Models["test-model"]
	if !ok {
		t.Fatal("model 'test-model' not found in dashboard data")
	}
	t.Logf("model: requests=%d errors=%d verifyMs=%s tokPerSec=%s lastRequest=%s",
		model.Requests, model.Errors, model.VerifyMs, model.TokPerSec, model.LastRequest)
	if model.Requests != 5 {
		t.Errorf("model.Requests = %d, want 5", model.Requests)
	}
	if model.VerifyMs == "—" {
		t.Error("model.VerifyMs should not be '—' when lastVerifyMs > 0")
	}
	if model.TokPerSec == "—" {
		t.Error("model.TokPerSec should not be '—' when lastTokDurMs > 0")
	}
	if model.LastRequest == "—" {
		t.Error("model.LastRequest should not be '—' when lastRequestAt > 0")
	}
}

func TestBuildHTTPStats(t *testing.T) {
	s := &Server{
		cfg:      &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:    attestation.NewCache(0),
		negCache: attestation.NewNegativeCache(0),
		stats:    stats{models: make(map[string]*modelStats)},
	}

	// Zero state.
	h := s.buildHTTPStats()
	t.Logf("zero state: requests=%d errors=%d", h.Requests, h.Errors)
	if h.Requests != 0 {
		t.Errorf("zero state requests = %d, want 0", h.Requests)
	}
	if h.Errors != 0 {
		t.Errorf("zero state errors = %d, want 0", h.Errors)
	}

	// Populate counters.
	s.stats.httpRequests.Store(10)
	s.stats.httpErrors.Store(2)

	h = s.buildHTTPStats()
	t.Logf("populated: requests=%d errors=%d", h.Requests, h.Errors)
	if h.Requests != 10 {
		t.Errorf("requests = %d, want 10", h.Requests)
	}
	if h.Errors != 2 {
		t.Errorf("errors = %d, want 2", h.Errors)
	}
}
