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

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		cfg:             &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:           attestation.NewCache(0),
		negCache:        attestation.NewNegativeCache(0),
		signingKeyCache: attestation.NewSigningKeyCache(0),
		stats:           stats{startTime: time.Now().Add(-time.Second), models: make(map[string]*modelStats)},
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
		cfg:             &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:           attestation.NewCache(0),
		negCache:        attestation.NewNegativeCache(0),
		signingKeyCache: attestation.NewSigningKeyCache(0),
		stats:           stats{models: make(map[string]*modelStats)},
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
	s.stats.models["venice/test-model"] = ms
	s.stats.modelsMu.Unlock()

	data := s.buildDashboardData()
	t.Logf("buildDashboardData: listen_addr=%s uptime=%s", data.ListenAddr, data.Uptime)

	vp, ok := data.Providers["venice"]
	if !ok {
		t.Fatal("venice provider missing from Providers map")
	}
	t.Logf("provider: upstream=%s e2ee=%s", vp.Upstream, vp.E2EE)

	if vp.E2EE != "enabled" {
		t.Errorf("Providers[venice].E2EE = %q, want 'enabled'", vp.E2EE)
	}
	if vp.Upstream != "https://api.venice.ai" {
		t.Errorf("Providers[venice].Upstream = %q, want 'https://api.venice.ai'", vp.Upstream)
	}

	model, ok := data.Models["venice/test-model"]
	if !ok {
		t.Fatal("model 'venice/test-model' not found in dashboard data")
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

func TestBuildDashboardData_MultiProvider(t *testing.T) {
	s := &Server{
		cfg:             &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:           attestation.NewCache(0),
		negCache:        attestation.NewNegativeCache(0),
		signingKeyCache: attestation.NewSigningKeyCache(0),
		stats:           stats{models: make(map[string]*modelStats)},
		providers: map[string]*provider.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: "https://api.venice.ai",
				E2EE:    true,
			},
			"chutes": {
				Name:    "chutes",
				BaseURL: "https://api.chutes.ai",
				E2EE:    false,
			},
		},
	}

	data := s.buildDashboardData()
	t.Logf("buildDashboardData: providers=%v", data.Providers)

	if len(data.Providers) != 2 {
		t.Fatalf("Providers len = %d, want 2", len(data.Providers))
	}

	vp, ok := data.Providers["venice"]
	if !ok {
		t.Fatal("venice missing from Providers")
	}
	t.Logf("venice: upstream=%s e2ee=%s", vp.Upstream, vp.E2EE)
	if vp.E2EE != "enabled" {
		t.Errorf("venice E2EE = %q, want 'enabled'", vp.E2EE)
	}
	if vp.Upstream != "https://api.venice.ai" {
		t.Errorf("venice Upstream = %q, want 'https://api.venice.ai'", vp.Upstream)
	}

	cp, ok := data.Providers["chutes"]
	if !ok {
		t.Fatal("chutes missing from Providers")
	}
	t.Logf("chutes: upstream=%s e2ee=%s", cp.Upstream, cp.E2EE)
	if cp.E2EE != "disabled" {
		t.Errorf("chutes E2EE = %q, want 'disabled'", cp.E2EE)
	}
}

// newPopulatedServer returns a Server with providers, model stats, and a cached
// attestation report for HTML rendering tests.
func newPopulatedServer(t *testing.T) *Server {
	t.Helper()
	s := &Server{
		cfg:             &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:           attestation.NewCache(10 * time.Minute),
		negCache:        attestation.NewNegativeCache(10 * time.Minute),
		signingKeyCache: attestation.NewSigningKeyCache(0),
		stats:           stats{startTime: time.Now().Add(-time.Hour), models: make(map[string]*modelStats)},
		providers: map[string]*provider.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: "https://api.venice.ai",
				E2EE:    true,
			},
			"chutes": {
				Name:    "chutes",
				BaseURL: "https://api.chutes.ai",
				E2EE:    false,
			},
		},
	}
	s.stats.requests.Store(42)
	s.stats.errors.Store(3)
	s.stats.streaming.Store(30)
	s.stats.nonStream.Store(12)
	s.stats.e2ee.Store(25)
	s.stats.plaintext.Store(17)
	s.stats.cacheHits.Store(10)
	s.stats.cacheMisses.Store(5)

	ms := &modelStats{}
	ms.requests.Store(10)
	ms.errors.Store(1)
	ms.lastVerifyMs.Store(200)
	ms.lastTokDurMs.Store(1000)
	ms.lastTokCount.Store(50)
	ms.lastRequestAt.Store(time.Now().Add(-10 * time.Second).Unix())
	s.stats.modelsMu.Lock()
	s.stats.models["venice/test-model"] = ms
	s.stats.modelsMu.Unlock()

	// Cache an attestation report so the dashboard has enclave data.
	s.cache.Put("venice", "test-model", &attestation.VerificationReport{
		Provider: "venice",
		Model:    "test-model",
		Passed:   8,
		Failed:   2,
		Factors: []attestation.FactorResult{
			{Name: attestation.FactorNonceMatch, Status: attestation.Pass, Tier: attestation.TierCore, Enforced: true, Detail: "nonces match"},
			{Name: attestation.FactorTEEQuotePresent, Status: attestation.Pass, Tier: attestation.TierCore, Enforced: true, Detail: "TDX quote present"},
			{Name: attestation.FactorE2EECapable, Status: attestation.Pass, Tier: attestation.TierBinding, Enforced: true, Detail: "ECDH key present"},
			{Name: attestation.FactorE2EEUsable, Status: attestation.Pass, Tier: attestation.TierBinding, Enforced: true, Detail: "round-trip ok"},
			{Name: attestation.FactorTLSKeyBinding, Status: attestation.NotApplicable, Tier: attestation.TierSupplyChain, Enforced: false, Detail: "E2EE provider"},
			{Name: attestation.FactorBuildTransparency, Status: attestation.Fail, Tier: attestation.TierSupplyChain, Enforced: false, Detail: "image not found"},
		},
	})
	return s
}

// findAttr returns the value of the named attribute on an HTML node, or "".
func findAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

// findByID walks the HTML tree and returns the first node with the given id attribute.
func findByID(n *html.Node, id string) *html.Node {
	if n.Type == html.ElementNode && findAttr(n, "id") == id {
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if found := findByID(c, id); found != nil {
			return found
		}
	}
	return nil
}

func TestHandleIndex_Status(t *testing.T) {
	s := newPopulatedServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	s.handleIndex(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
}

func TestHandleIndex_ValidHTML(t *testing.T) {
	s := newPopulatedServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	s.handleIndex(rec, req)

	body := rec.Body.String()
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("HTML parse error: %v", err)
	}

	// Verify key structural elements exist.
	for _, id := range []string{"addr", "uptime", "seal", "verdict", "enclaves", "metrics"} {
		if findByID(doc, id) == nil {
			t.Errorf("element with id=%q not found in dashboard HTML", id)
		}
	}
}

func TestHandleIndex_ContainsInitialJSON(t *testing.T) {
	s := newPopulatedServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	s.handleIndex(rec, req)

	body := rec.Body.String()

	// __INITIAL__ must be replaced — it should not appear in the output.
	if strings.Contains(body, "__INITIAL__") {
		t.Error("dashboard HTML still contains __INITIAL__ placeholder")
	}

	// The inlined JSON should contain provider and listen_addr data.
	if !strings.Contains(body, `"listen_addr"`) {
		t.Error("dashboard HTML missing inlined listen_addr JSON")
	}
	if !strings.Contains(body, `"venice"`) {
		t.Error("dashboard HTML missing inlined venice provider data")
	}
	if !strings.Contains(body, `"chutes"`) {
		t.Error("dashboard HTML missing inlined chutes provider data")
	}
}

func TestHandleIndex_InitialJSONValid(t *testing.T) {
	s := newPopulatedServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	s.handleIndex(rec, req)

	body := rec.Body.String()

	// Extract the JSON from "window.__last = {...};"
	const prefix = "window.__last = "
	idx := strings.Index(body, prefix)
	if idx < 0 {
		t.Fatal("cannot find window.__last assignment in dashboard HTML")
	}
	jsonStart := idx + len(prefix)
	// Find the closing semicolon.
	jsonEnd := strings.Index(body[jsonStart:], ";\n")
	if jsonEnd < 0 {
		t.Fatal("cannot find end of window.__last JSON")
	}
	jsonStr := body[jsonStart : jsonStart+jsonEnd]

	var data dashboardData
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		t.Fatalf("inlined JSON is not valid dashboardData: %v", err)
	}
	if data.ListenAddr != "127.0.0.1:8337" {
		t.Errorf("ListenAddr = %q, want 127.0.0.1:8337", data.ListenAddr)
	}
	if len(data.Providers) != 2 {
		t.Errorf("Providers len = %d, want 2", len(data.Providers))
	}
	if len(data.Attestations) != 1 {
		t.Errorf("Attestations len = %d, want 1", len(data.Attestations))
	}
	if data.Requests.Total != 42 {
		t.Errorf("Requests.Total = %d, want 42", data.Requests.Total)
	}
	if data.Cache.HitRate != "67%" {
		t.Errorf("Cache.HitRate = %q, want 67%%", data.Cache.HitRate)
	}
}

func TestHandleIndex_AttestationData(t *testing.T) {
	s := newPopulatedServer(t)
	data := s.buildDashboardData()

	if len(data.Attestations) != 1 {
		t.Fatalf("Attestations len = %d, want 1", len(data.Attestations))
	}
	a := data.Attestations[0]
	if a.Provider != "venice" {
		t.Errorf("Provider = %q, want venice", a.Provider)
	}
	if a.Model != "test-model" {
		t.Errorf("Model = %q, want test-model", a.Model)
	}
	if a.Passed != 8 {
		t.Errorf("Passed = %d, want 8", a.Passed)
	}
	if a.E2EE != "usable" {
		t.Errorf("E2EE = %q, want usable", a.E2EE)
	}

	// Verify factor flattening.
	if len(a.Factors) != 6 {
		t.Fatalf("Factors len = %d, want 6", len(a.Factors))
	}
	if a.Factors[0].Name != attestation.FactorNonceMatch {
		t.Errorf("Factors[0].Name = %q, want %q", a.Factors[0].Name, attestation.FactorNonceMatch)
	}
	if a.Factors[0].Status != "pass" {
		t.Errorf("Factors[0].Status = %q, want pass", a.Factors[0].Status)
	}

	// Verify tier rollup.
	if len(a.Tiers) != 3 {
		t.Fatalf("Tiers len = %d, want 3", len(a.Tiers))
	}
	core := a.Tiers[0]
	if core.Passed != 2 || core.Total != 2 {
		t.Errorf("Core tier: Passed=%d Total=%d, want 2/2", core.Passed, core.Total)
	}
}

func TestHandleIndex_NoProviders(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	s.handleIndex(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	_, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("HTML parse error with no providers: %v", err)
	}
}

func TestHandleMetrics_Format(t *testing.T) {
	s := newPopulatedServer(t)
	req := httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody)
	rec := httptest.NewRecorder()
	s.handleMetrics(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain prefix", ct)
	}

	body := rec.Body.String()
	for _, metric := range []string{
		"teep_requests_total 42",
		"teep_errors_total 3",
		"teep_attestation_cache_hits_total 10",
		"teep_attestation_cache_misses_total 5",
		"teep_e2ee_sessions_total 25",
		"teep_plaintext_sessions_total 17",
	} {
		if !strings.Contains(body, metric) {
			t.Errorf("metrics output missing %q", metric)
		}
	}
}

func TestHandleEvents_MaxConnections(t *testing.T) {
	s := newPopulatedServer(t)

	// Saturate SSE connection limit.
	s.sseConns.Store(maxSSEConns)

	req := httptest.NewRequest(http.MethodGet, "/events", http.NoBody)
	rec := httptest.NewRecorder()
	s.handleEvents(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 when at max SSE connections", rec.Code)
	}
}

func TestDashFactorStatus(t *testing.T) {
	tests := []struct {
		status attestation.Status
		want   string
	}{
		{attestation.Pass, "pass"},
		{attestation.Fail, "fail"},
		{attestation.Skip, "skip"},
		{attestation.NotApplicable, "na"},
		{attestation.Status(99), "skip"}, // unknown defaults to skip
	}
	for _, tt := range tests {
		got := dashFactorStatus(tt.status)
		if got != tt.want {
			t.Errorf("dashFactorStatus(%d) = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestNanoAgo(t *testing.T) {
	if got := nanoAgo(0); got != "—" {
		t.Errorf("nanoAgo(0) = %q, want —", got)
	}
	recent := time.Now().Add(-5 * time.Second).UnixNano()
	got := nanoAgo(recent)
	if !strings.HasSuffix(got, "ago") {
		t.Errorf("nanoAgo(%d) = %q, want suffix 'ago'", recent, got)
	}
}

func TestTimestampPtr(t *testing.T) {
	if got := timestampPtr(0); got != nil {
		t.Errorf("timestampPtr(0) = %v, want nil", got)
	}
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC).UnixNano()
	got := timestampPtr(ts)
	if got == nil {
		t.Fatal("timestampPtr non-zero = nil, want RFC3339 string")
	}
	if _, err := time.Parse(time.RFC3339, *got); err != nil {
		t.Errorf("timestampPtr result %q is not valid RFC3339: %v", *got, err)
	}
}

func TestBuildDashboardData_NegBlocked(t *testing.T) {
	s := &Server{
		cfg:             &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:           attestation.NewCache(0),
		negCache:        attestation.NewNegativeCache(time.Minute),
		signingKeyCache: attestation.NewSigningKeyCache(0),
		stats:           stats{models: make(map[string]*modelStats)},
	}
	// Record in reverse alphabetical order to verify sort.
	s.negCache.Record("venice", "model-b")
	s.negCache.Record("chutes", "model-a")

	data := s.buildDashboardData()
	t.Logf("NegBlocked = %+v", data.NegBlocked)

	if len(data.NegBlocked) != 2 {
		t.Fatalf("NegBlocked len = %d, want 2", len(data.NegBlocked))
	}
	// Verify sorted by provider, then model.
	if data.NegBlocked[0].Provider != "chutes" || data.NegBlocked[0].Model != "model-a" {
		t.Errorf("NegBlocked[0] = %s/%s, want chutes/model-a", data.NegBlocked[0].Provider, data.NegBlocked[0].Model)
	}
	if data.NegBlocked[1].Provider != "venice" || data.NegBlocked[1].Model != "model-b" {
		t.Errorf("NegBlocked[1] = %s/%s, want venice/model-b", data.NegBlocked[1].Provider, data.NegBlocked[1].Model)
	}
	if data.NegBlocked[0].Remaining == "" {
		t.Error("NegBlocked[0].Remaining is empty")
	}
}

func TestBuildDashboardData_E2EEFailures(t *testing.T) {
	s := &Server{
		cfg:             &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:           attestation.NewCache(0),
		negCache:        attestation.NewNegativeCache(0),
		signingKeyCache: attestation.NewSigningKeyCache(0),
		stats:           stats{models: make(map[string]*modelStats)},
	}
	s.e2eeFailed.Store(providerModelKey{provider: "chutes", model: "llama-70b"}, true)

	data := s.buildDashboardData()
	t.Logf("E2EEFailures = %+v", data.E2EEFailures)

	if len(data.E2EEFailures) != 1 {
		t.Fatalf("E2EEFailures len = %d, want 1", len(data.E2EEFailures))
	}
	ef := data.E2EEFailures[0]
	if ef.Provider != "chutes" || ef.Model != "llama-70b" {
		t.Errorf("E2EEFailures[0] = %s/%s, want chutes/llama-70b", ef.Provider, ef.Model)
	}
}

func TestBuildDashboardData_ProviderErrors(t *testing.T) {
	s := &Server{
		cfg:             &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:           attestation.NewCache(0),
		negCache:        attestation.NewNegativeCache(0),
		signingKeyCache: attestation.NewSigningKeyCache(0),
		stats:           stats{models: make(map[string]*modelStats)},
		providers: map[string]*provider.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: "https://api.venice.ai",
				E2EE:    true,
			},
		},
	}

	// Two models under the same provider.
	ms1 := &modelStats{}
	ms1.requests.Store(10)
	ms1.errors.Store(2)
	ms2 := &modelStats{}
	ms2.requests.Store(5)
	ms2.errors.Store(1)
	s.stats.modelsMu.Lock()
	s.stats.models["venice/model-a"] = ms1
	s.stats.models["venice/model-b"] = ms2
	s.stats.modelsMu.Unlock()

	data := s.buildDashboardData()
	vp, ok := data.Providers["venice"]
	if !ok {
		t.Fatal("venice provider missing")
	}
	t.Logf("venice provider: requests=%d errors=%d", vp.Requests, vp.Errors)

	if vp.Requests != 15 {
		t.Errorf("venice Requests = %d, want 15", vp.Requests)
	}
	if vp.Errors != 3 {
		t.Errorf("venice Errors = %d, want 3", vp.Errors)
	}
}

func TestBuildCacheStats_SeededModels(t *testing.T) {
	s := newTestServer(t)
	// Seed the models cache.
	s.modelsMu.Lock()
	s.modelsCache = make([]json.RawMessage, 3)
	s.modelsCachedAt = time.Now().Add(-5 * time.Second)
	s.modelsMu.Unlock()

	cs := s.buildCacheStats(10, 5)
	t.Logf("buildCacheStats: models_count=%d models_cached_ago=%q signing_keys=%d",
		cs.ModelsCount, cs.ModelsCachedAgo, cs.SigningKeys)

	if cs.ModelsCount != 3 {
		t.Errorf("ModelsCount = %d, want 3", cs.ModelsCount)
	}
	if cs.ModelsCachedAgo == "" {
		t.Error("ModelsCachedAgo is empty, want non-empty when cache is seeded")
	}
	if !strings.HasSuffix(cs.ModelsCachedAgo, "ago") {
		t.Errorf("ModelsCachedAgo = %q, want suffix 'ago'", cs.ModelsCachedAgo)
	}
}

func TestBuildHTTPStats_SSEClients(t *testing.T) {
	s := newTestServer(t)
	s.sseConns.Store(3)
	s.stats.httpRequests.Store(42)
	s.stats.httpErrors.Store(2)

	h := s.buildHTTPStats()
	t.Logf("buildHTTPStats: requests=%d errors=%d sse_clients=%d", h.Requests, h.Errors, h.SSEClients)

	if h.SSEClients != 3 {
		t.Errorf("SSEClients = %d, want 3", h.SSEClients)
	}
	if h.Requests != 42 {
		t.Errorf("Requests = %d, want 42", h.Requests)
	}
}

func TestWriteModelsResponse_Nil(t *testing.T) {
	rec := httptest.NewRecorder()
	writeModelsResponse(context.Background(), rec, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp struct {
		Object string            `json:"object"`
		Data   []json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Object != "list" {
		t.Errorf("object = %q, want list", resp.Object)
	}
	// nil models must produce an empty array, not null (OpenAI API convention).
	if resp.Data == nil {
		t.Error("data is null, want empty array")
	}
	if len(resp.Data) != 0 {
		t.Errorf("data len = %d, want 0", len(resp.Data))
	}
}

func TestStoreModelsCache_SkipsEmpty(t *testing.T) {
	s := newTestServer(t)

	// Seed with real data first.
	s.storeModelsCache([]json.RawMessage{json.RawMessage(`{"id":"test"}`)})
	if cached := s.cachedModels(); cached == nil {
		t.Fatal("expected cache to be populated after storing non-empty list")
	}

	// Storing nil should not overwrite.
	s.storeModelsCache(nil)
	if cached := s.cachedModels(); cached == nil {
		t.Error("nil store overwrote existing cache")
	}

	// Storing empty slice should not overwrite.
	s.storeModelsCache([]json.RawMessage{})
	if cached := s.cachedModels(); cached == nil {
		t.Error("empty store overwrote existing cache")
	}
}
