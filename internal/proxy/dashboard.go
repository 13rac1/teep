package proxy

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/13rac1/teep/internal/attestation"
)

// dashboardData is the JSON-serializable snapshot of all dashboard stats.
// Used by both the initial page render and the SSE /events endpoint.
type dashboardData struct {
	ListenAddr   string                       `json:"listen_addr"`
	Uptime       string                       `json:"uptime"`
	Providers    map[string]dashboardProvider `json:"providers"`
	Attestations []dashAttestation            `json:"attestations"`
	Requests     dashboardRequests            `json:"requests"`
	Cache        dashboardCache               `json:"cache"`
	HTTP         dashboardHTTP                `json:"http"`
	Models       map[string]dashModel         `json:"models"`
	NegBlocked   []dashNegBlocked             `json:"neg_blocked,omitempty"`
	E2EEFailures []dashE2EEFailure            `json:"e2ee_failures,omitempty"`
}

type dashNegBlocked struct {
	Provider  string `json:"provider"`
	Model     string `json:"model"`
	Remaining string `json:"remaining"`
}

type dashE2EEFailure struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

type dashAttestation struct {
	Provider       string       `json:"provider"`
	Model          string       `json:"model"`
	Passed         int          `json:"passed"`
	EnforcedFailed int          `json:"enforced_failed"`
	AllowedFailed  int          `json:"allowed_failed"`
	Blocked        bool         `json:"blocked"`
	BlockedFactors []string     `json:"blocked_factors"` // non-empty when Blocked
	E2EE           string       `json:"e2ee"`
	Verified       string       `json:"verified"`
	Factors        []dashFactor `json:"factors"` // full per-factor breakdown for drill-down
	Tiers          []dashTier   `json:"tiers"`   // per-tier pass/total rollup, in report order
}

// dashFactor is one verification factor flattened for the dashboard. Status is
// a lowercase string ("pass"/"fail"/"skip"/"na") so the client can style it
// without re-deriving the Status enum.
type dashFactor struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Tier     string `json:"tier"`
	Enforced bool   `json:"enforced"`
	Detail   string `json:"detail,omitempty"`
}

// dashTier rolls up the factors in one tier so the client can draw coverage
// bars without grouping the flat factor list itself.
type dashTier struct {
	Name   string `json:"name"`
	Passed int    `json:"passed"`
	Failed int    `json:"failed"` // enforced failures (red)
	Warned int    `json:"warned"` // allowed failures and skips (yellow)
	Total  int    `json:"total"`  // excludes N/A factors (not part of the score)
}

// dashFactorStatus maps an attestation.Status to the short lowercase token the
// dashboard uses for styling.
func dashFactorStatus(s attestation.Status) string {
	switch s {
	case attestation.Pass:
		return "pass"
	case attestation.Fail:
		return "fail"
	case attestation.Skip:
		return "skip"
	case attestation.NotApplicable:
		return "na"
	default:
		return "skip"
	}
}

type dashboardProvider struct {
	Upstream string `json:"upstream"`
	E2EE     string `json:"e2ee"`
	Requests int64  `json:"requests"`
	Errors   int64  `json:"errors"`
}

type dashboardRequests struct {
	Total     int64 `json:"total"`
	Streaming int64 `json:"streaming"`
	NonStream int64 `json:"non_stream"`
	E2EE      int64 `json:"e2ee"`
	Plaintext int64 `json:"plaintext"`
	Errors    int64 `json:"errors"`

	ActiveStreaming int64 `json:"active_streaming"`
	ActiveNonStream int64 `json:"active_non_stream"`
	TotalChunks     int64 `json:"total_chunks"`
	TotalBytes      int64 `json:"total_bytes"`

	LastRequestAt string `json:"last_request_at"`
	LastSuccessAt string `json:"last_success_at"`
}

type dashboardCache struct {
	Entries         int    `json:"entries"`
	Negative        int    `json:"negative"`
	HitRate         string `json:"hit_rate"`
	Hits            int64  `json:"hits"`
	Misses          int64  `json:"misses"`
	SigningKeys     int    `json:"signing_keys"`
	ModelsCount     int    `json:"models_count"`
	ModelsCachedAgo string `json:"models_cached_ago"`
}

type dashboardHTTP struct {
	Requests   int64 `json:"requests"`
	Errors     int64 `json:"errors"`
	SSEClients int64 `json:"sse_clients"`
}

type dashModel struct {
	Requests    int64  `json:"requests"`
	Errors      int64  `json:"errors"`
	VerifyMs    string `json:"verify_ms"`
	TokPerSec   string `json:"tok_per_sec"`
	LastRequest string `json:"last_request"`
}

func hitRateString(hits, misses int64) string {
	if total := hits + misses; total > 0 {
		return fmt.Sprintf("%.0f%%", float64(hits)/float64(total)*100)
	}
	return "—"
}

// nanoAgo converts a unix-nanosecond timestamp to a human-readable "Xs ago"
// string, or "—" if the timestamp is zero (never recorded).
func nanoAgo(ns int64) string {
	if ns == 0 {
		return "—"
	}
	return time.Since(time.Unix(0, ns)).Truncate(time.Second).String() + " ago"
}

// timestampPtr converts a unix-nanosecond timestamp to an RFC3339 string pointer,
// or nil if the timestamp is zero (never recorded).
func timestampPtr(ns int64) *string {
	if ns == 0 {
		return nil
	}
	t := time.Unix(0, ns).UTC().Format(time.RFC3339)
	return &t
}

func (s *Server) buildHTTPStats() dashboardHTTP {
	return dashboardHTTP{
		Requests:   s.stats.httpRequests.Load(),
		Errors:     s.stats.httpErrors.Load(),
		SSEClients: s.sseConns.Load(),
	}
}

func (s *Server) buildCacheStats(hits, misses int64) dashboardCache {
	var modelsCachedAgo string
	var modelsCount int
	s.modelsMu.RLock()
	if !s.modelsCachedAt.IsZero() {
		modelsCachedAgo = time.Since(s.modelsCachedAt).Truncate(time.Second).String() + " ago"
		modelsCount = len(s.modelsCache)
	}
	s.modelsMu.RUnlock()

	authorizations, signingKeys := s.authorizations.counts()
	return dashboardCache{
		Entries:         s.cache.Len() + authorizations,
		Negative:        s.negCache.Len(),
		HitRate:         hitRateString(hits, misses),
		Hits:            hits,
		Misses:          misses,
		SigningKeys:     s.signingKeyCache.Len() + signingKeys,
		ModelsCount:     modelsCount,
		ModelsCachedAgo: modelsCachedAgo,
	}
}

func (s *Server) buildDashboardData() dashboardData {
	providers := make(map[string]dashboardProvider, len(s.providers))
	for name, p := range s.providers {
		e2eeStatus := "disabled"
		if p.E2EE {
			e2eeStatus = "enabled"
		}
		providers[name] = dashboardProvider{
			Upstream: p.BaseURL,
			E2EE:     e2eeStatus,
		}
	}

	hits := s.stats.cacheHits.Load()
	misses := s.stats.cacheMisses.Load()

	// Per-provider request/error rollup, computed alongside per-model stats.
	type provRollup struct{ requests, errors int64 }
	provStats := make(map[string]*provRollup)

	models := make(map[string]dashModel)
	s.stats.modelsMu.RLock()
	for k, m := range s.stats.models {
		reqs := m.requests.Load()
		errs := m.errors.Load()
		var verifyStr string
		if ms := m.lastVerifyMs.Load(); ms > 0 {
			verifyStr = fmt.Sprintf("%dms", ms)
		} else {
			verifyStr = "—"
		}
		var tokStr string
		if dur := m.lastTokDurMs.Load(); dur > 0 {
			tps := float64(m.lastTokCount.Load()) / (float64(dur) / 1000)
			tokStr = fmt.Sprintf("%.1f", tps)
		} else {
			tokStr = "—"
		}
		var agoStr string
		if lastReq := m.lastRequestAt.Load(); lastReq > 0 {
			agoStr = time.Since(time.Unix(lastReq, 0)).Truncate(time.Second).String() + " ago"
		} else {
			agoStr = "—"
		}
		models[k] = dashModel{
			Requests:    reqs,
			Errors:      errs,
			VerifyMs:    verifyStr,
			TokPerSec:   tokStr,
			LastRequest: agoStr,
		}
		if prov, _, ok := strings.Cut(k, "/"); ok {
			r := provStats[prov]
			if r == nil {
				r = &provRollup{}
				provStats[prov] = r
			}
			r.requests += reqs
			r.errors += errs
		}
	}
	s.stats.modelsMu.RUnlock()

	// Merge per-provider request/error rollup into providers map.
	for name, r := range provStats {
		if p, ok := providers[name]; ok {
			p.Requests = r.requests
			p.Errors = r.errors
			providers[name] = p
		}
	}

	reports := s.cachedReportSnapshots()
	slices.SortFunc(reports, func(a, b cachedReportSnapshot) int { return b.info.FetchedAt.Compare(a.info.FetchedAt) })
	attestations := make([]dashAttestation, 0, len(reports))
	for _, snapshot := range reports {
		info, report := snapshot.info, snapshot.report
		e2ee := ""
		for _, f := range report.Factors {
			if f.Name == attestation.FactorE2EEUsable && f.Status == attestation.Pass {
				e2ee = "usable"
				break
			}
			if f.Name == attestation.FactorE2EECapable && f.Status == attestation.Pass {
				e2ee = "capable"
			}
		}
		blocked := report.Blocked()
		var blockedFactors []string
		if blocked {
			bf := report.BlockedFactors()
			blockedFactors = make([]string, len(bf))
			for i, f := range bf {
				blockedFactors[i] = f.Name
			}
		}

		// Flatten factors for the drill-down and roll them up per tier. Tier
		// order follows first appearance in the report, which is already the
		// canonical Tier 1..4 ordering produced by BuildReport.
		factors := make([]dashFactor, len(report.Factors))
		var tiers []dashTier
		tierIdx := make(map[string]int)
		for i, f := range report.Factors {
			factors[i] = dashFactor{
				Name:     f.Name,
				Status:   dashFactorStatus(f.Status),
				Tier:     f.Tier,
				Enforced: f.Enforced,
				Detail:   f.Detail,
			}
			idx, exists := tierIdx[f.Tier]
			if !exists {
				idx = len(tiers)
				tierIdx[f.Tier] = idx
				tiers = append(tiers, dashTier{Name: f.Tier})
			}
			if f.Status == attestation.NotApplicable {
				continue // N/A factors are not part of the score denominator
			}
			tiers[idx].Total++
			switch {
			case f.Status == attestation.Pass:
				tiers[idx].Passed++
			case f.Status == attestation.Fail && f.Enforced:
				tiers[idx].Failed++
			case f.Status == attestation.Fail:
				tiers[idx].Warned++
			case f.Status == attestation.Skip:
				// A skip applies and did not run, so it is a gap in coverage,
				// not neutral space. Counting it keeps the bar summing to
				// Total; leaving it out drew the remainder as background and
				// read as though the tier were fully covered.
				tiers[idx].Warned++
			}
		}

		attestations = append(attestations, dashAttestation{
			Provider:       info.Provider,
			Model:          info.Model,
			Passed:         report.Passed,
			EnforcedFailed: report.EnforcedFailed,
			AllowedFailed:  report.AllowedFailed,
			Blocked:        blocked,
			BlockedFactors: blockedFactors,
			E2EE:           e2ee,
			Verified:       time.Since(info.FetchedAt).Truncate(time.Second).String() + " ago",
			Factors:        factors,
			Tiers:          tiers,
		})
	}

	// Negative cache: which provider+model pairs are currently blocked.
	blockedEntries := s.negCache.Blocked()
	var negBlocked []dashNegBlocked
	if len(blockedEntries) > 0 {
		negBlocked = make([]dashNegBlocked, 0, len(blockedEntries))
		for _, b := range blockedEntries {
			negBlocked = append(negBlocked, dashNegBlocked{
				Provider:  b.Provider,
				Model:     b.Model,
				Remaining: time.Until(b.ExpiresAt).Truncate(time.Second).String(),
			})
		}
	}
	slices.SortFunc(negBlocked, func(a, b dashNegBlocked) int {
		if c := cmp.Compare(a.Provider, b.Provider); c != 0 {
			return c
		}
		return cmp.Compare(a.Model, b.Model)
	})

	// E2EE decryption failures: provider+model pairs with post-relay failures.
	var e2eeFailures []dashE2EEFailure
	s.e2eeFailed.Range(func(k, _ any) bool {
		pk := k.(providerModelKey) //nolint:forcetypeassert // key type is always providerModelKey
		e2eeFailures = append(e2eeFailures, dashE2EEFailure{
			Provider: pk.provider,
			Model:    pk.model,
		})
		return true
	})
	slices.SortFunc(e2eeFailures, func(a, b dashE2EEFailure) int {
		if c := cmp.Compare(a.Provider, b.Provider); c != 0 {
			return c
		}
		return cmp.Compare(a.Model, b.Model)
	})

	return dashboardData{
		ListenAddr:   s.cfg.ListenAddr,
		Uptime:       time.Since(s.stats.startTime).Truncate(time.Second).String(),
		Providers:    providers,
		Attestations: attestations,
		Requests: dashboardRequests{
			Total:           s.stats.requests.Load(),
			Streaming:       s.stats.streaming.Load(),
			NonStream:       s.stats.nonStream.Load(),
			E2EE:            s.stats.e2ee.Load(),
			Plaintext:       s.stats.plaintext.Load(),
			Errors:          s.stats.errors.Load(),
			ActiveStreaming: s.stats.activeStreaming.Load(),
			ActiveNonStream: s.stats.activeNonStream.Load(),
			TotalChunks:     s.stats.totalChunks.Load(),
			TotalBytes:      s.stats.totalBytes.Load(),
			LastRequestAt:   nanoAgo(s.stats.lastRequestAt.Load()),
			LastSuccessAt:   nanoAgo(s.stats.lastSuccessAt.Load()),
		},
		Cache:        s.buildCacheStats(hits, misses),
		HTTP:         s.buildHTTPStats(),
		Models:       models,
		NegBlocked:   negBlocked,
		E2EEFailures: e2eeFailures,
	}
}

// v1HelpText is the plain text listing of available /v1 API endpoints.
const v1HelpText = `Teep API — OpenAI-compatible endpoints:

  GET  /v1/models                List available models
  POST /v1/chat/completions      Chat completions
  POST /v1/embeddings            Embeddings
  POST /v1/audio/transcriptions  Audio transcription
  POST /v1/images/generations    Image generation
  POST /v1/rerank                Reranking
  POST /v1/score                 Scoring
  POST /v1/responses             Responses
  POST /v1/audio/speech          Text-to-speech
  GET  /v1/tee/report            Attestation report
`

// handleV1Help returns a plain text listing of available API endpoints.
func handleV1Help(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, v1HelpText)
}

// handleHealth returns a JSON health snapshot for process managers and monitoring.
// The endpoint always returns 200; the presence of last_request_at (non-null)
// tells an automated monitor that the proxy is actively processing requests.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	type healthResponse struct {
		Status        string  `json:"status"`
		UptimeSeconds float64 `json:"uptime_seconds"`
		LastRequestAt *string `json:"last_request_at"`
		LastSuccessAt *string `json:"last_success_at"`
		RequestsTotal int64   `json:"requests_total"`
		ErrorsTotal   int64   `json:"errors_total"`
	}

	resp := healthResponse{
		Status:        "ok",
		UptimeSeconds: time.Since(s.stats.startTime).Seconds(),
		LastRequestAt: timestampPtr(s.stats.lastRequestAt.Load()),
		LastSuccessAt: timestampPtr(s.stats.lastSuccessAt.Load()),
		RequestsTotal: s.stats.requests.Load(),
		ErrorsTotal:   s.stats.errors.Load(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.ErrorContext(r.Context(), "health encode", "err", err)
	}
}

// maxSSEConns is the maximum number of concurrent SSE /events connections.
const maxSSEConns = 10

// handleEvents streams dashboard stats as Server-Sent Events.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.sseConns.Add(1) > maxSSEConns {
		s.sseConns.Add(-1)
		http.Error(w, "too many SSE connections", http.StatusServiceUnavailable)
		return
	}
	defer s.sseConns.Add(-1)

	ctx := r.Context()
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	send := func(ctx context.Context) error {
		b, err := json.Marshal(s.buildDashboardData())
		if err != nil {
			slog.ErrorContext(ctx, "marshal dashboard data", "err", err)
			return nil // skip this tick
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return err // client gone
		}
		flusher.Flush()
		return nil
	}

	if err := send(ctx); err != nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := send(ctx); err != nil {
				return
			}
		}
	}
}

// handleMetrics serves Prometheus-format counters at /metrics.
// Access control relies on the proxy binding to loopback by default; see config.Load/warnNonLoopback.
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP teep_requests_total Total proxy requests received\n")
	fmt.Fprintf(w, "# TYPE teep_requests_total counter\n")
	fmt.Fprintf(w, "teep_requests_total %d\n", s.stats.requests.Load())
	fmt.Fprintf(w, "# HELP teep_errors_total Total proxy requests that resulted in an error\n")
	fmt.Fprintf(w, "# TYPE teep_errors_total counter\n")
	fmt.Fprintf(w, "teep_errors_total %d\n", s.stats.errors.Load())
	fmt.Fprintf(w, "# HELP teep_attestation_cache_hits_total Total attestation cache hits\n")
	fmt.Fprintf(w, "# TYPE teep_attestation_cache_hits_total counter\n")
	fmt.Fprintf(w, "teep_attestation_cache_hits_total %d\n", s.stats.cacheHits.Load())
	fmt.Fprintf(w, "# HELP teep_attestation_cache_misses_total Total attestation cache misses\n")
	fmt.Fprintf(w, "# TYPE teep_attestation_cache_misses_total counter\n")
	fmt.Fprintf(w, "teep_attestation_cache_misses_total %d\n", s.stats.cacheMisses.Load())
	fmt.Fprintf(w, "# HELP teep_e2ee_sessions_total Total E2EE-encrypted sessions\n")
	fmt.Fprintf(w, "# TYPE teep_e2ee_sessions_total counter\n")
	fmt.Fprintf(w, "teep_e2ee_sessions_total %d\n", s.stats.e2ee.Load())
	fmt.Fprintf(w, "# HELP teep_plaintext_sessions_total Total plaintext (non-E2EE) sessions\n")
	fmt.Fprintf(w, "# TYPE teep_plaintext_sessions_total counter\n")
	fmt.Fprintf(w, "teep_plaintext_sessions_total %d\n", s.stats.plaintext.Load())
	fmt.Fprintf(w, "# HELP teep_upstream_requests_total Total HTTP requests sent to upstream providers\n")
	fmt.Fprintf(w, "# TYPE teep_upstream_requests_total counter\n")
	fmt.Fprintf(w, "teep_upstream_requests_total %d\n", s.stats.httpRequests.Load())
	fmt.Fprintf(w, "# HELP teep_upstream_errors_total Total HTTP errors from upstream providers\n")
	fmt.Fprintf(w, "# TYPE teep_upstream_errors_total counter\n")
	fmt.Fprintf(w, "teep_upstream_errors_total %d\n", s.stats.httpErrors.Load())
	fmt.Fprintf(w, "# HELP teep_active_streaming_requests In-flight streaming requests\n")
	fmt.Fprintf(w, "# TYPE teep_active_streaming_requests gauge\n")
	fmt.Fprintf(w, "teep_active_streaming_requests %d\n", s.stats.activeStreaming.Load())
	fmt.Fprintf(w, "# HELP teep_active_non_stream_requests In-flight non-streaming requests\n")
	fmt.Fprintf(w, "# TYPE teep_active_non_stream_requests gauge\n")
	fmt.Fprintf(w, "teep_active_non_stream_requests %d\n", s.stats.activeNonStream.Load())
	fmt.Fprintf(w, "# HELP teep_stream_chunks_total Total SSE data chunks relayed across all streams\n")
	fmt.Fprintf(w, "# TYPE teep_stream_chunks_total counter\n")
	fmt.Fprintf(w, "teep_stream_chunks_total %d\n", s.stats.totalChunks.Load())
	fmt.Fprintf(w, "# HELP teep_stream_bytes_total Total SSE payload bytes relayed across all streams\n")
	fmt.Fprintf(w, "# TYPE teep_stream_bytes_total counter\n")
	fmt.Fprintf(w, "teep_stream_bytes_total %d\n", s.stats.totalBytes.Load())
	fmt.Fprintf(w, "# HELP teep_uptime_seconds Seconds since the proxy started\n")
	fmt.Fprintf(w, "# TYPE teep_uptime_seconds gauge\n")
	fmt.Fprintf(w, "teep_uptime_seconds %g\n", time.Since(s.stats.startTime).Seconds())
}

// dashboardTemplateData is the context passed to the "dashboard" template.
type dashboardTemplateData struct {
	InitialJSON template.JS
}

// handleIndex serves the live attestation dashboard at /.
// The page is fully self-contained — no external fonts, scripts, or network
// requests — so it works on an air-gapped loopback proxy. Initial data is
// inlined as JSON for an instant first paint; an EventSource to /events then
// streams updates once per second.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	initial, err := json.Marshal(s.buildDashboardData())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := dashboardTemplateData{InitialJSON: template.JS(initial)} //nolint:gosec // G203: initial is server-generated JSON from json.Marshal, not user input
	if err := templates.ExecuteTemplate(w, "dashboard", data); err != nil {
		slog.ErrorContext(r.Context(), "write dashboard", "err", err)
	}
}
