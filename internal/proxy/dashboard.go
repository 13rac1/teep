package proxy

import (
	"context"
	"encoding/json"
	"fmt"
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
	Failed int    `json:"failed"`
	Total  int    `json:"total"` // excludes N/A factors (not part of the score)
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
}

type dashboardRequests struct {
	Total         int64  `json:"total"`
	Streaming     int64  `json:"streaming"`
	NonStream     int64  `json:"non_stream"`
	E2EE          int64  `json:"e2ee"`
	Plaintext     int64  `json:"plaintext"`
	Errors        int64  `json:"errors"`
	LastRequestAt string `json:"last_request_at"`
	LastSuccessAt string `json:"last_success_at"`
}

type dashboardCache struct {
	Entries  int    `json:"entries"`
	Negative int    `json:"negative"`
	HitRate  string `json:"hit_rate"`
	Hits     int64  `json:"hits"`
	Misses   int64  `json:"misses"`
}

type dashboardHTTP struct {
	Requests int64 `json:"requests"`
	Errors   int64 `json:"errors"`
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
		Requests: s.stats.httpRequests.Load(),
		Errors:   s.stats.httpErrors.Load(),
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

	models := make(map[string]dashModel)
	s.stats.modelsMu.RLock()
	for k, m := range s.stats.models {
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
			Requests:    m.requests.Load(),
			Errors:      m.errors.Load(),
			VerifyMs:    verifyStr,
			TokPerSec:   tokStr,
			LastRequest: agoStr,
		}
	}
	s.stats.modelsMu.RUnlock()

	cacheInfos := s.cache.Models()
	slices.SortFunc(cacheInfos, func(a, b attestation.CacheInfo) int {
		return b.FetchedAt.Compare(a.FetchedAt) // descending: most recent first
	})

	var attestations []dashAttestation
	for _, info := range cacheInfos {
		report, ok := s.cache.Get(info.Provider, info.Model)
		if !ok {
			continue
		}
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
			switch f.Status {
			case attestation.Pass:
				tiers[idx].Passed++
			case attestation.Fail:
				tiers[idx].Failed++
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

	return dashboardData{
		ListenAddr:   s.cfg.ListenAddr,
		Uptime:       time.Since(s.stats.startTime).Truncate(time.Second).String(),
		Providers:    providers,
		Attestations: attestations,
		Requests: dashboardRequests{
			Total:         s.stats.requests.Load(),
			Streaming:     s.stats.streaming.Load(),
			NonStream:     s.stats.nonStream.Load(),
			E2EE:          s.stats.e2ee.Load(),
			Plaintext:     s.stats.plaintext.Load(),
			Errors:        s.stats.errors.Load(),
			LastRequestAt: nanoAgo(s.stats.lastRequestAt.Load()),
			LastSuccessAt: nanoAgo(s.stats.lastSuccessAt.Load()),
		},
		Cache: dashboardCache{
			Entries:  s.cache.Len(),
			Negative: s.negCache.Len(),
			HitRate:  hitRateString(hits, misses),
			Hits:     hits,
			Misses:   misses,
		},
		HTTP:   s.buildHTTPStats(),
		Models: models,
	}
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
	fmt.Fprintf(w, "# HELP teep_uptime_seconds Seconds since the proxy started\n")
	fmt.Fprintf(w, "# TYPE teep_uptime_seconds gauge\n")
	fmt.Fprintf(w, "teep_uptime_seconds %g\n", time.Since(s.stats.startTime).Seconds())
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
	page := strings.Replace(dashboardPage, "__INITIAL__", string(initial), 1)
	if _, err := io.WriteString(w, page); err != nil {
		slog.ErrorContext(r.Context(), "write dashboard", "err", err)
	}
}

// dashboardPage is the complete self-contained dashboard. The single token
// __INITIAL__ is replaced with the first data snapshot at request time. The
// page contains no backtick characters so it can live in a Go raw string.
const dashboardPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>teep — attestation proxy</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64' fill='none' stroke-linecap='round' stroke-linejoin='round'%3E%3Cg stroke='%234FE3C1' stroke-width='3.4'%3E%3Cpath d='M27 13 L18 13 Q14 13 14 17 L14 47 Q14 51 18 51 L27 51'/%3E%3Cpath d='M37 13 L46 13 Q50 13 50 17 L50 47 Q50 51 46 51 L37 51'/%3E%3C/g%3E%3Cpath d='M28 24 L37 32 L28 40' stroke='%23E8EEF4' stroke-width='3.8'/%3E%3C/svg%3E">
<style>
  :root {
    --bg: #080B0F; --surface: #0F141A; --surface-2: #141B23;
    --line: #202A35; --line-soft: #19212A;
    --ink: #E8EEF4; --dim: #8493A3; --faint: #4A5663;
    --seal: #4FE3C1; --crypt: #5BB8FF; --warn: #E8B24A; --alert: #FF6B7D;
    --mono: 'JetBrains Mono','SF Mono',ui-monospace,'Cascadia Code',Menlo,Consolas,monospace;
    --sans: system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  html { -webkit-text-size-adjust: 100%; }
  body {
    font-family: var(--sans); color: var(--ink); line-height: 1.5;
    background: var(--bg);
    background-image:
      radial-gradient(1200px 600px at 50% -8%, rgba(79,227,193,0.06), transparent 60%),
      radial-gradient(900px 500px at 100% 0%, rgba(91,184,255,0.04), transparent 55%);
    background-attachment: fixed;
    -webkit-font-smoothing: antialiased;
    font-variant-numeric: tabular-nums;
  }
  .wrap { max-width: 980px; margin: 0 auto; padding: 28px 22px 64px; }
  a { color: var(--crypt); }

  /* ---- top bar ---- */
  .topbar { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
  .brand { display: flex; align-items: center; gap: 10px; }
  .brand svg { width: 30px; height: 30px; display: block; }
  .brand .word {
    font-family: var(--mono); font-weight: 600; font-size: 1.45rem;
    letter-spacing: -0.04em; color: var(--ink);
  }
  .topmeta {
    margin-left: auto; display: flex; align-items: center; gap: 18px;
    font-family: var(--mono); font-size: 0.78rem; color: var(--dim); flex-wrap: wrap;
  }
  .topmeta b { color: var(--ink); font-weight: 500; }
  .live { display: inline-flex; align-items: center; gap: 7px; }
  .pulse {
    width: 7px; height: 7px; border-radius: 50%; background: var(--seal);
    box-shadow: 0 0 0 0 rgba(79,227,193,0.5); animation: pulse 2.4s infinite;
  }
  @keyframes pulse {
    0% { box-shadow: 0 0 0 0 rgba(79,227,193,0.45); }
    70% { box-shadow: 0 0 0 7px rgba(79,227,193,0); }
    100% { box-shadow: 0 0 0 0 rgba(79,227,193,0); }
  }
  .copyable { cursor: pointer; border: 0; background: none; color: inherit;
    font: inherit; padding: 0; border-bottom: 1px dashed var(--faint); }
  .copyable:hover { color: var(--ink); border-bottom-color: var(--dim); }

  /* ---- hero seal ---- */
  .hero {
    margin-top: 26px; display: grid; grid-template-columns: 168px 1fr; gap: 30px;
    align-items: center;
    background: linear-gradient(180deg, var(--surface), rgba(15,20,26,0.4));
    border: 1px solid var(--line); border-radius: 16px; padding: 26px 30px;
  }
  .seal { width: 168px; height: 168px; color: var(--faint); }
  .seal-svg { width: 100%; height: 100%; overflow: visible; }
  .seal-track { fill: none; stroke: var(--line); stroke-width: 5; }
  .seal-prog {
    fill: none; stroke: currentColor; stroke-width: 5; stroke-linecap: round;
    stroke-dasharray: 464.96; stroke-dashoffset: 464.96;
    transition: stroke-dashoffset 1.1s cubic-bezier(.45,0,.15,1);
    filter: drop-shadow(0 0 6px currentColor);
  }
  .seal-guard { fill: none; stroke: currentColor; stroke-width: 2.6; stroke-linecap: round; stroke-linejoin: round; }
  .seal-prompt { fill: none; stroke: var(--ink); stroke-width: 2.8; stroke-linecap: round; stroke-linejoin: round; }
  .is-sealed { color: var(--seal); }
  .is-warn { color: var(--warn); }
  .is-alert { color: var(--alert); }
  .is-idle { color: var(--faint); }

  .eyebrow {
    font-family: var(--mono); font-size: 0.68rem; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.18em; color: var(--dim);
  }
  .verdict {
    font-family: var(--mono); font-weight: 600; font-size: 1.5rem; line-height: 1.18;
    letter-spacing: -0.02em; color: var(--ink); margin: 8px 0 6px;
  }
  .verdict-sub { color: var(--dim); font-size: 0.92rem; }
  .hero-stats { display: flex; gap: 28px; margin-top: 18px; flex-wrap: wrap; }
  .hstat .n { font-family: var(--mono); font-size: 1.45rem; font-weight: 600; color: var(--ink); }
  .hstat .n.accent { color: var(--seal); }
  .hstat .l {
    font-family: var(--mono); font-size: 0.64rem; text-transform: uppercase;
    letter-spacing: 0.14em; color: var(--faint); margin-top: 2px;
  }

  /* ---- blocks ---- */
  .block { margin-top: 36px; }
  .block-head { display: flex; align-items: center; gap: 12px; margin-bottom: 14px; }
  .block-head .eyebrow { margin: 0; }
  .filter {
    margin-left: auto; background: var(--surface); border: 1px solid var(--line);
    color: var(--ink); font-family: var(--mono); font-size: 0.8rem;
    padding: 6px 11px; border-radius: 8px; width: 180px; max-width: 45vw;
  }
  .filter::placeholder { color: var(--faint); }
  .filter:focus { outline: none; border-color: var(--seal); }

  /* ---- enclave cards ---- */
  .enclaves { display: flex; flex-direction: column; gap: 10px; }
  .card { background: var(--surface); border: 1px solid var(--line); border-radius: 12px; overflow: hidden; }
  .card.blocked { border-color: rgba(255,107,125,0.4); }
  .card-head {
    width: 100%; display: flex; align-items: center; gap: 11px; text-align: left;
    background: none; border: 0; color: inherit; font: inherit; cursor: pointer;
    padding: 14px 16px;
  }
  .card-head:hover { background: var(--surface-2); }
  .dot { font-size: 0.9rem; line-height: 1; flex-shrink: 0; }
  .card-name { font-family: var(--mono); font-size: 0.92rem; color: var(--ink); }
  .card-name .prov { color: var(--dim); }
  .card-tags { display: flex; gap: 6px; }
  .pill {
    font-family: var(--mono); font-size: 0.6rem; font-weight: 600; letter-spacing: 0.08em;
    text-transform: uppercase; padding: 3px 7px; border-radius: 999px;
    border: 1px solid currentColor;
  }
  .pill.e2ee { color: var(--crypt); }
  .pill.enclave { color: var(--seal); }
  .pill.block { color: var(--alert); }
  .card-time { margin-left: auto; font-family: var(--mono); font-size: 0.72rem; color: var(--faint); white-space: nowrap; }
  .chev { color: var(--faint); transition: transform 0.18s ease; flex-shrink: 0; }
  .card-head[aria-expanded="true"] .chev { transform: rotate(90deg); }
  .card-body { padding: 0 16px 15px; }
  .card-sub { display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
    font-size: 0.82rem; color: var(--dim); margin-bottom: 12px; }
  .card-sub .copyid {
    font-family: var(--mono); font-size: 0.7rem; color: var(--faint);
    background: var(--surface-2); border: 1px solid var(--line); border-radius: 6px;
    padding: 2px 7px; cursor: pointer;
  }
  .card-sub .copyid:hover { color: var(--seal); border-color: var(--seal); }

  .tiers { display: flex; gap: 14px; flex-wrap: wrap; }
  .tier { flex: 1; min-width: 130px; }
  .tier-top { display: flex; justify-content: space-between; font-family: var(--mono);
    font-size: 0.66rem; color: var(--dim); margin-bottom: 5px; letter-spacing: 0.04em; }
  .tier-top b { color: var(--ink); font-weight: 600; }
  .bar { height: 5px; border-radius: 3px; background: var(--line-soft); overflow: hidden; display: flex; }
  .bar i { display: block; height: 100%; }
  .bar .ok { background: var(--seal); }
  .bar .bad { background: var(--alert); }

  /* factor drill-down */
  .detail { margin-top: 14px; border-top: 1px solid var(--line); padding-top: 12px; }
  .detail[hidden] { display: none; }
  .tier-group + .tier-group { margin-top: 12px; }
  .tier-label { font-family: var(--mono); font-size: 0.64rem; text-transform: uppercase;
    letter-spacing: 0.12em; color: var(--faint); margin-bottom: 6px; }
  .factor { display: grid; grid-template-columns: 16px 1fr auto; gap: 9px; align-items: baseline;
    padding: 3px 0; font-size: 0.8rem; }
  .factor .fn { font-family: var(--mono); color: var(--ink); }
  .factor .fd { color: var(--faint); font-size: 0.74rem; grid-column: 2 / 4; }
  .factor .fi { font-weight: 700; text-align: center; }
  .factor .req { font-family: var(--mono); font-size: 0.58rem; letter-spacing: 0.06em;
    color: var(--warn); border: 1px solid var(--warn); border-radius: 4px; padding: 0 4px; align-self: center; }
  .fi.pass { color: var(--seal); }
  .fi.fail { color: var(--alert); }
  .fi.skip, .fi.na { color: var(--faint); }
  .factor.f-fail .fn { color: var(--alert); }

  /* ---- traffic ---- */
  .panel { background: var(--surface); border: 1px solid var(--line); border-radius: 12px; padding: 18px 20px; }
  .traffic { display: grid; grid-template-columns: 1fr 1.2fr; gap: 26px; align-items: center; }
  .metrics { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 14px 18px; }
  .metric .n { font-family: var(--mono); font-size: 1.3rem; font-weight: 600; color: var(--ink); }
  .metric .n.warnz { color: var(--alert); }
  .metric .l { font-family: var(--mono); font-size: 0.6rem; text-transform: uppercase;
    letter-spacing: 0.12em; color: var(--faint); margin-top: 1px; }
  .spark { display: flex; flex-direction: column; }
  .spark svg { width: 100%; height: 56px; display: block; }
  .spark-cap { font-family: var(--mono); font-size: 0.62rem; color: var(--faint);
    letter-spacing: 0.08em; margin-top: 6px; text-transform: uppercase; }
  .kv { display: flex; gap: 28px; flex-wrap: wrap; margin-top: 14px;
    font-family: var(--mono); font-size: 0.76rem; color: var(--dim); }
  .kv b { color: var(--ink); font-weight: 500; }

  /* ---- system strip ---- */
  .strip { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  .strip .panel h4 { font-family: var(--mono); font-size: 0.66rem; text-transform: uppercase;
    letter-spacing: 0.14em; color: var(--dim); font-weight: 600; margin-bottom: 12px; }
  .row { display: flex; justify-content: space-between; padding: 4px 0; font-size: 0.84rem; }
  .row span:first-child { color: var(--dim); }
  .row span:last-child { font-family: var(--mono); color: var(--ink); }
  .row .bad { color: var(--alert); }

  /* ---- tables (endpoints / providers) ---- */
  table { border-collapse: collapse; width: 100%; }
  .tbl td, .tbl th { text-align: left; padding: 7px 14px 7px 0; font-size: 0.84rem; }
  .tbl th { font-family: var(--mono); font-size: 0.62rem; text-transform: uppercase;
    letter-spacing: 0.1em; color: var(--faint); font-weight: 600; border-bottom: 1px solid var(--line); }
  .tbl td { border-bottom: 1px solid var(--line-soft); }
  .tbl tr:last-child td { border-bottom: 0; }
  .tbl .mono { font-family: var(--mono); }
  .ok { color: var(--seal); } .off { color: var(--faint); }
  code { font-family: var(--mono); font-size: 0.82em; color: var(--crypt);
    background: var(--surface-2); padding: 2px 6px; border-radius: 5px; }

  .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--line-soft);
    color: var(--faint); font-size: 0.78rem; }
  .footer code { background: none; padding: 0; }

  /* toast */
  .toast { position: fixed; left: 50%; bottom: 26px; transform: translateX(-50%) translateY(20px);
    background: var(--surface-2); border: 1px solid var(--seal); color: var(--ink);
    font-family: var(--mono); font-size: 0.78rem; padding: 9px 16px; border-radius: 9px;
    opacity: 0; pointer-events: none; transition: opacity .2s, transform .2s; z-index: 50; }
  .toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }

  :focus-visible { outline: 2px solid var(--seal); outline-offset: 2px; border-radius: 4px; }

  @media (max-width: 720px) {
    .hero { grid-template-columns: 1fr; justify-items: center; text-align: center; }
    .hero-stats { justify-content: center; }
    .traffic { grid-template-columns: 1fr; }
    .strip { grid-template-columns: 1fr; }
    .topmeta { margin-left: 0; width: 100%; }
  }
  @media (prefers-reduced-motion: reduce) {
    .seal-prog { transition: none; }
    .pulse { animation: none; }
    .chev { transition: none; }
    .toast { transition: none; }
  }
</style>
</head>
<body>
<div class="wrap">

  <header class="topbar">
    <div class="brand">
      <svg viewBox="0 0 64 64" fill="none" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <g stroke="#4FE3C1" stroke-width="3">
          <path d="M27 13 L18 13 Q14 13 14 17 L14 47 Q14 51 18 51 L27 51"/>
          <path d="M37 13 L46 13 Q50 13 50 17 L50 47 Q50 51 46 51 L37 51"/>
        </g>
        <path d="M28 24 L37 32 L28 40" stroke="#E8EEF4" stroke-width="3.4"/>
      </svg>
      <span class="word">teep</span>
    </div>
    <div class="topmeta">
      <span><button class="copyable" id="addr" title="Copy base URL"></button></span>
      <span>up <b id="uptime"></b></span>
      <span class="live"><span class="pulse"></span> live</span>
    </div>
  </header>

  <section class="hero" aria-label="Attestation posture">
    <div class="seal is-idle" id="seal">
      <svg class="seal-svg" viewBox="0 0 168 168" aria-hidden="true">
        <circle class="seal-track" cx="84" cy="84" r="74"/>
        <circle class="seal-prog" id="seal-prog" cx="84" cy="84" r="74" transform="rotate(-90 84 84)"/>
        <g transform="translate(41 41) scale(1.34)">
          <path class="seal-guard" d="M27 13 L18 13 Q14 13 14 17 L14 47 Q14 51 18 51 L27 51"/>
          <path class="seal-guard" d="M37 13 L46 13 Q50 13 50 17 L50 47 Q50 51 46 51 L37 51"/>
          <path class="seal-prompt" d="M28 24 L37 32 L28 40"/>
        </g>
      </svg>
    </div>
    <div class="hero-body">
      <p class="eyebrow" id="hero-eyebrow">Attestation</p>
      <h2 class="verdict" id="verdict">Starting up…</h2>
      <p class="verdict-sub" id="verdict-sub"></p>
      <div class="hero-stats" id="hero-stats"></div>
    </div>
  </section>

  <section class="block">
    <div class="block-head">
      <h3 class="eyebrow">Enclaves</h3>
      <input class="filter" id="filter" type="text" placeholder="filter models…" aria-label="Filter enclaves">
    </div>
    <div class="enclaves" id="enclaves"></div>
  </section>

  <section class="block">
    <h3 class="eyebrow" style="margin-bottom:14px">Traffic</h3>
    <div class="panel">
      <div class="traffic">
        <div class="metrics" id="metrics"></div>
        <div class="spark">
          <svg viewBox="0 0 300 56" preserveAspectRatio="none" aria-hidden="true">
            <polyline id="spark-line" fill="none" stroke="#4FE3C1" stroke-width="1.5" points=""/>
            <polygon id="spark-fill" fill="rgba(79,227,193,0.10)" points=""/>
          </svg>
          <div class="spark-cap" id="spark-cap">Requests / tick</div>
        </div>
      </div>
      <div class="kv">
        <span>Last request <b id="last-req">—</b></span>
        <span>Last success <b id="last-ok">—</b></span>
      </div>
    </div>
  </section>

  <section class="block">
    <div class="strip">
      <div class="panel">
        <h4>Attestation Cache</h4>
        <div class="row"><span>Entries</span><span id="c-entries">—</span></div>
        <div class="row"><span>Negative</span><span id="c-neg">—</span></div>
        <div class="row"><span>Hit rate</span><span id="c-hit">—</span></div>
      </div>
      <div class="panel">
        <h4>HTTP Transport</h4>
        <div class="row"><span>Requests</span><span id="h-req">—</span></div>
        <div class="row"><span>Errors</span><span id="h-err">—</span></div>
      </div>
    </div>
  </section>

  <section class="block">
    <h3 class="eyebrow" style="margin-bottom:14px">Providers</h3>
    <div class="panel">
      <table class="tbl">
        <thead><tr><th>Provider</th><th>Upstream</th><th>E2EE</th></tr></thead>
        <tbody id="prov-rows"></tbody>
      </table>
    </div>
  </section>

  <section class="block">
    <h3 class="eyebrow" style="margin-bottom:14px">Endpoints</h3>
    <div class="panel">
      <table class="tbl">
        <tbody>
          <tr><td class="mono"><code>POST /v1/chat/completions</code></td><td>Proxy with TEE attestation</td></tr>
          <tr><td class="mono"><code>GET /v1/models</code></td><td>List provider:model combinations</td></tr>
          <tr><td class="mono"><code>GET /v1/tee/report</code></td><td>Cached attestation report (JSON)</td></tr>
          <tr><td class="mono"><code>GET /metrics</code></td><td>Prometheus counters</td></tr>
        </tbody>
      </table>
    </div>
  </section>

  <p class="footer" id="footer"></p>
</div>

<div class="toast" id="toast" role="status" aria-live="polite"></div>

<script>
"use strict";
var SEAL_C = 464.96; // 2 * pi * 74
var TIER_SHORT = { "Tier 1: Core Attestation":"T1 · Hardware",
  "Tier 2: Binding & Crypto":"T2 · Crypto",
  "Tier 3: Supply Chain & Channel Integrity":"T3 · Supply chain",
  "Tier 4: Gateway Attestation":"T4 · Gateway" };

function esc(s) { var d = document.createElement("div"); d.textContent = s == null ? "" : s; return d.innerHTML; }
function el(id) { return document.getElementById(id); }
function key(p, m) { return p + "/" + m; }

var toastTimer;
function toast(msg) {
  var t = el("toast"); t.textContent = msg; t.classList.add("show");
  clearTimeout(toastTimer); toastTimer = setTimeout(function(){ t.classList.remove("show"); }, 1600);
}
function copy(text, label) {
  function done(){ toast((label || "Copied") + ": " + text); }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done, function(){ fallback(text); done(); });
  } else { fallback(text); done(); }
}
function fallback(text) {
  var ta = document.createElement("textarea"); ta.value = text;
  ta.style.position = "fixed"; ta.style.opacity = "0"; document.body.appendChild(ta);
  ta.select(); try { document.execCommand("copy"); } catch (e) {} document.body.removeChild(ta);
}

// expansion + filter state persist across SSE re-renders
var expanded = {};
var filterText = "";

function postureFor(atts, anyReq) {
  var verified = 0, blocked = 0, e2ee = 0, pass = 0, scored = 0;
  for (var i = 0; i < atts.length; i++) {
    var a = atts[i];
    var tiers = a.tiers || [];
    for (var t = 0; t < tiers.length; t++) { pass += tiers[t].passed; scored += tiers[t].total; }
    if (a.blocked) { blocked++; } else { verified++; if (a.e2ee === "usable") e2ee++; }
  }
  var frac = scored > 0 ? pass / scored : 0;
  var cls, head, sub;
  if (atts.length === 0) {
    cls = "is-idle"; frac = 0;
    head = anyReq ? "Awaiting verification" : "No models verified yet";
    sub = anyReq ? "A request is in flight — attestation runs on first use."
                 : "Send a request to any provider:model to begin.";
  } else if (blocked > 0 && verified === 0) {
    cls = "is-alert";
    head = "Verification failed";
    sub = blocked + " model" + (blocked>1?"s":"") + " blocked — prompts were never forwarded.";
  } else if (blocked > 0) {
    cls = "is-warn";
    head = verified + " sealed · " + blocked + " blocked";
    sub = "Some enclaves failed enforced checks and are refusing traffic.";
  } else if (e2ee === verified) {
    cls = "is-sealed";
    head = verified + " enclave" + (verified>1?"s":"") + " sealed";
    sub = "Running in verified hardware · end-to-end encrypted.";
  } else {
    cls = "is-sealed";
    head = verified + " enclave" + (verified>1?"s":"") + " verified";
    sub = e2ee > 0 ? e2ee + " end-to-end encrypted · the rest on standard connections."
                   : "Running in verified hardware.";
  }
  return { cls: cls, head: head, sub: sub, frac: frac, verified: verified, blocked: blocked, e2ee: e2ee, pass: pass, scored: scored };
}

function renderHero(p) {
  var seal = el("seal");
  seal.className = "seal " + p.cls;
  el("seal-prog").style.strokeDashoffset = SEAL_C * (1 - p.frac);
  el("verdict").textContent = p.head;
  el("verdict-sub").textContent = p.sub;
  var stats = [
    { n: p.verified, l: "Enclaves", accent: false },
    { n: p.e2ee, l: "Encrypted", accent: true },
    { n: p.scored ? (p.pass + "/" + p.scored) : "—", l: "Factors passed", accent: false }
  ];
  if (p.blocked > 0) stats.push({ n: p.blocked, l: "Blocked", accent: false });
  var h = "";
  for (var i = 0; i < stats.length; i++) {
    h += '<div class="hstat"><div class="n' + (stats[i].accent ? ' accent' : '') + '">' +
      esc(stats[i].n) + '</div><div class="l">' + esc(stats[i].l) + '</div></div>';
  }
  el("hero-stats").innerHTML = h;
}

var STATUS_GLYPH = { pass: "●", fail: "✕", skip: "◌", na: "–" };

function tierBars(tiers) {
  var h = '<div class="tiers">';
  for (var i = 0; i < tiers.length; i++) {
    var t = tiers[i];
    if (!t.total) continue;
    var okPct = (t.passed / t.total) * 100;
    var badPct = (t.failed / t.total) * 100;
    var label = TIER_SHORT[t.name] || esc(t.name);
    h += '<div class="tier"><div class="tier-top"><span>' + esc(label) +
      '</span><span><b>' + t.passed + '</b>/' + t.total + '</span></div>' +
      '<div class="bar"><i class="ok" style="width:' + okPct + '%"></i>' +
      '<i class="bad" style="width:' + badPct + '%"></i></div></div>';
  }
  return h + '</div>';
}

function factorList(factors, open) {
  // group by tier, preserving first-seen order
  var order = [], byTier = {};
  for (var i = 0; i < factors.length; i++) {
    var f = factors[i];
    if (!byTier[f.tier]) { byTier[f.tier] = []; order.push(f.tier); }
    byTier[f.tier].push(f);
  }
  var h = '<div class="detail"' + (open ? '' : ' hidden') + '>';
  for (var t = 0; t < order.length; t++) {
    var tn = order[t];
    h += '<div class="tier-group"><div class="tier-label">' + esc(TIER_SHORT[tn] || tn) + '</div>';
    var list = byTier[tn];
    for (var j = 0; j < list.length; j++) {
      var f = list[j];
      var glyph = STATUS_GLYPH[f.status] || "◌";
      h += '<div class="factor' + (f.status === "fail" ? " f-fail" : "") + '">' +
        '<span class="fi ' + f.status + '">' + glyph + '</span>' +
        '<span class="fn">' + esc(f.name) + '</span>' +
        (f.enforced && f.status === "fail" ? '<span class="req">enforced</span>' : '<span></span>') +
        (f.detail ? '<span class="fd">' + esc(f.detail) + '</span>' : '') +
        '</div>';
    }
    h += '</div>';
  }
  return h + '</div>';
}

function renderEnclaves(d) {
  var atts = d.attestations || [];
  var models = d.models || {};
  var host = el("enclaves");
  var seen = {};
  var cards = [];

  for (var i = 0; i < atts.length; i++) {
    var a = atts[i];
    var k = key(a.provider, a.model);
    seen[k] = true;
    var ms = models[k] || {};
    var dotColor, pills = "";
    if (a.blocked) {
      dotColor = "var(--alert)";
      pills = '<span class="pill block">blocked</span>';
    } else {
      dotColor = "var(--seal)";
      pills = '<span class="pill enclave">enclave</span>';
      if (a.e2ee === "usable") pills += '<span class="pill e2ee">e2ee</span>';
    }
    var sub;
    if (a.blocked) {
      sub = "Blocked — " + esc((a.blocked_factors || []).join(", ") || "enforced factor failed");
    } else if (a.e2ee === "usable") {
      sub = "Secure enclave · end-to-end encrypted";
    } else if (a.e2ee === "capable") {
      sub = "Secure enclave · encryption available";
    } else if (a.allowed_failed > 0) {
      sub = "Secure enclave · " + a.passed + " checks passed, " + a.allowed_failed + " non-critical pending";
    } else {
      sub = "Secure enclave · " + a.passed + " checks passed";
    }
    var meta = [];
    if (ms.requests) meta.push(ms.requests + " req");
    if (ms.tok_per_sec && ms.tok_per_sec !== "—") meta.push(ms.tok_per_sec + " tok/s");
    if (ms.verify_ms && ms.verify_ms !== "—") meta.push("verify " + ms.verify_ms);
    var subExtra = meta.length ? ' · ' + esc(meta.join(" · ")) : "";

    var open = !!expanded[k];
    var html = '<div class="card' + (a.blocked ? ' blocked' : '') + '" data-key="' + esc(k) + '">' +
      '<button class="card-head" aria-expanded="' + open + '" data-toggle="' + esc(k) + '">' +
        '<span class="dot" style="color:' + dotColor + '">●</span>' +
        '<span class="card-name"><span class="prov">' + esc(a.provider) + '/</span>' + esc(a.model) + '</span>' +
        '<span class="card-tags">' + pills + '</span>' +
        '<span class="card-time">verified ' + esc(a.verified) + '</span>' +
        '<span class="chev">▸</span>' +
      '</button>' +
      '<div class="card-body">' +
        '<div class="card-sub">' + sub + subExtra +
          '<button class="copyid" data-copy="' + esc(k) + '" title="Copy model id">copy id</button>' +
        '</div>' +
        tierBars(a.tiers || []) +
        factorList(a.factors || [], open) +
      '</div>' +
    '</div>';
    cards.push({ k: k, blocked: a.blocked, html: html });
  }

  // models with traffic but no cached attestation yet
  for (var mk in models) {
    if (seen[mk] || !models[mk].requests) continue;
    cards.push({ k: mk, blocked: false, html:
      '<div class="card" data-key="' + esc(mk) + '"><button class="card-head" aria-expanded="false" disabled style="cursor:default">' +
      '<span class="dot" style="color:var(--faint)">◌</span>' +
      '<span class="card-name">' + esc(mk) + '</span>' +
      '<span class="card-time">awaiting verification</span></button>' +
      '<div class="card-body"><div class="card-sub">' + models[mk].requests + ' request' +
      (models[mk].requests > 1 ? "s" : "") + ' · attestation pending</div></div></div>' });
  }

  var ft = filterText.toLowerCase();
  var shown = 0, out = "";
  for (var c = 0; c < cards.length; c++) {
    if (ft && cards[c].k.toLowerCase().indexOf(ft) === -1) continue;
    out += cards[c].html; shown++;
  }
  if (cards.length === 0) {
    out = '<div class="panel" style="color:var(--dim)">No enclaves yet. Point a client at the proxy and send a request.</div>';
  } else if (shown === 0) {
    out = '<div class="panel" style="color:var(--dim)">No enclaves match “' + esc(filterText) + '”.</div>';
  }
  host.innerHTML = out;

  // wire interactions (re-bound each render; handlers are idempotent)
  var heads = host.querySelectorAll(".card-head[data-toggle]");
  for (var hI = 0; hI < heads.length; hI++) {
    heads[hI].addEventListener("click", function () {
      var k = this.getAttribute("data-toggle");
      expanded[k] = !expanded[k];
      this.setAttribute("aria-expanded", expanded[k]);
      var det = this.parentNode.querySelector(".detail");
      if (det) det.hidden = !expanded[k];
    });
  }
  var copies = host.querySelectorAll(".copyid[data-copy]");
  for (var cI = 0; cI < copies.length; cI++) {
    copies[cI].addEventListener("click", function (e) {
      e.stopPropagation();
      copy(this.getAttribute("data-copy"), "Model id");
    });
  }
}

function renderTraffic(d) {
  var r = d.requests || {};
  var m = [
    { n: r.total || 0, l: "Requests" },
    { n: r.streaming || 0, l: "Streaming" },
    { n: r.non_stream || 0, l: "Non-stream" },
    { n: r.e2ee || 0, l: "E2EE" },
    { n: r.plaintext || 0, l: "Plaintext" },
    { n: r.errors || 0, l: "Errors", warn: (r.errors || 0) > 0 }
  ];
  var h = "";
  for (var i = 0; i < m.length; i++) {
    h += '<div class="metric"><div class="n' + (m[i].warn ? ' warnz' : '') + '">' +
      esc(m[i].n) + '</div><div class="l">' + esc(m[i].l) + '</div></div>';
  }
  el("metrics").innerHTML = h;
  el("last-req").textContent = r.last_request_at || "—";
  el("last-ok").textContent = r.last_success_at || "—";
}

// request-rate sparkline: client-side ring buffer of per-tick deltas
var hist = [];
var lastTotal = null;
function pushSpark(total) {
  if (lastTotal !== null) {
    var delta = total - lastTotal;
    if (delta < 0) delta = 0;
    hist.push(delta);
    if (hist.length > 60) hist.shift();
  }
  lastTotal = total;
  var W = 300, H = 56, n = hist.length;
  if (n < 2) { el("spark-line").setAttribute("points", ""); el("spark-fill").setAttribute("points", ""); return; }
  var max = 1;
  for (var i = 0; i < n; i++) if (hist[i] > max) max = hist[i];
  var pts = "", step = W / (n - 1);
  for (var j = 0; j < n; j++) {
    var x = (j * step).toFixed(1);
    var y = (H - 3 - (hist[j] / max) * (H - 8)).toFixed(1);
    pts += x + "," + y + " ";
  }
  el("spark-line").setAttribute("points", pts.trim());
  el("spark-fill").setAttribute("points", "0," + H + " " + pts.trim() + " " + W + "," + H);
  var peak = max > 1 ? "  ·  peak " + max + "/tick" : "";
  el("spark-cap").textContent = "Requests / tick" + peak;
}

function renderProviders(d) {
  var provs = d.providers || {};
  var names = Object.keys(provs).sort();
  var h = "";
  for (var i = 0; i < names.length; i++) {
    var p = provs[names[i]];
    var cls = p.e2ee === "enabled" ? "ok" : "off";
    h += '<tr><td class="mono">' + esc(names[i]) + '</td><td class="mono" style="color:var(--dim)">' +
      esc(p.upstream) + '</td><td class="' + cls + '">' + esc(p.e2ee) + '</td></tr>';
  }
  el("prov-rows").innerHTML = h;
}

function render(d) {
  var addr = el("addr");
  addr.textContent = d.listen_addr;
  addr.setAttribute("data-url", "http://" + d.listen_addr + "/v1");
  el("uptime").textContent = d.uptime;

  var anyReq = (d.requests && d.requests.total > 0);
  var p = postureFor(d.attestations || [], anyReq);
  renderHero(p);
  renderEnclaves(d);
  renderTraffic(d);
  pushSpark((d.requests && d.requests.total) || 0);

  var c = d.cache || {};
  el("c-entries").textContent = c.entries != null ? c.entries : "—";
  el("c-neg").textContent = c.negative != null ? c.negative : "—";
  el("c-hit").textContent = (c.hit_rate || "—") + " (" + (c.hits || 0) + " hit / " + (c.misses || 0) + " miss)";
  var http = d.http || {};
  el("h-req").textContent = http.requests != null ? http.requests : "—";
  var he = el("h-err"); he.textContent = http.errors != null ? http.errors : "—";
  he.className = (http.errors > 0) ? "bad" : "";

  renderProviders(d);
  el("footer").innerHTML = "Self-contained · live via SSE. Point any OpenAI-compatible client at " +
    "<code>http://" + esc(d.listen_addr) + "/v1</code> and use <code>provider:model</code> ids.";
}

// static wiring
el("addr").addEventListener("click", function () {
  copy(this.getAttribute("data-url") || ("http://" + this.textContent + "/v1"), "Base URL");
});
el("filter").addEventListener("input", function () {
  filterText = this.value;
  if (window.__last) renderEnclaves(window.__last);
});

// first paint from inlined snapshot, then stream
window.__last = __INITIAL__;
render(window.__last);

var es = new EventSource("/events");
es.onmessage = function (e) { window.__last = JSON.parse(e.data); render(window.__last); };
es.onerror = function () { setTimeout(function () { location.reload(); }, 5000); };
</script>
</body>
</html>
`
