package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
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
	Provider       string   `json:"provider"`
	Model          string   `json:"model"`
	Passed         int      `json:"passed"`
	EnforcedFailed int      `json:"enforced_failed"`
	AllowedFailed  int      `json:"allowed_failed"`
	Blocked        bool     `json:"blocked"`
	BlockedFactors []string `json:"blocked_factors"` // non-empty when Blocked
	E2EE           string   `json:"e2ee"`
	Verified       string   `json:"verified"`
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
// Access control relies on the proxy binding to loopback by default; see ListenAndServe.
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	writeCounter := func(name, help string, value int64) {
		fmt.Fprintf(w, "# HELP %s %s\n", name, help)
		fmt.Fprintf(w, "# TYPE %s counter\n", name)
		fmt.Fprintf(w, "%s %d\n", name, value)
	}
	writeGauge := func(name, help string, value float64) {
		fmt.Fprintf(w, "# HELP %s %s\n", name, help)
		fmt.Fprintf(w, "# TYPE %s gauge\n", name)
		fmt.Fprintf(w, "%s %g\n", name, value)
	}

	writeCounter("teep_requests_total", "Total proxy requests received", s.stats.requests.Load())
	writeCounter("teep_errors_total", "Total proxy requests that resulted in an error", s.stats.errors.Load())
	writeCounter("teep_attestation_cache_hits_total", "Total attestation cache hits", s.stats.cacheHits.Load())
	writeCounter("teep_attestation_cache_misses_total", "Total attestation cache misses", s.stats.cacheMisses.Load())
	writeCounter("teep_e2ee_sessions_total", "Total E2EE-encrypted sessions", s.stats.e2ee.Load())
	writeCounter("teep_plaintext_sessions_total", "Total plaintext (non-E2EE) sessions", s.stats.plaintext.Load())
	writeCounter("teep_upstream_requests_total", "Total HTTP requests sent to upstream providers", s.stats.httpRequests.Load())
	writeCounter("teep_upstream_errors_total", "Total HTTP errors from upstream providers", s.stats.httpErrors.Load())
	writeGauge("teep_uptime_seconds", "Seconds since the proxy started", time.Since(s.stats.startTime).Seconds())
}

// handleIndex serves a live stats dashboard at /.
// Initial data is embedded as JSON so the page renders immediately.
// An EventSource connection to /events takes over for live updates.
func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	initial, err := json.Marshal(s.buildDashboardData())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>teep</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, system-ui, 'Segoe UI', sans-serif;
    max-width: 760px; margin: 0 auto; padding: 40px 24px;
    background: #0d1117; color: #c9d1d9; line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }
  h1 {
    font-family: ui-monospace, 'SF Mono', 'Cascadia Code', Menlo, monospace;
    font-size: 1.5em; font-weight: 600; color: #e6edf3; letter-spacing: -0.02em;
  }
  .subtitle { color: #8b949e; font-size: 0.9em; margin-top: 0.25em; }
  h2 {
    font-size: 0.75em; font-weight: 600; color: #8b949e;
    text-transform: uppercase; letter-spacing: 0.08em;
    margin-top: 2em; margin-bottom: 0.5em;
  }
  section {
    background: #161b22; border: 1px solid #30363d;
    border-radius: 8px; padding: 16px 20px;
  }
  code {
    font-family: ui-monospace, 'SF Mono', 'Cascadia Code', Menlo, monospace;
    background: #21262d; padding: 2px 6px; border-radius: 4px;
    font-size: 0.85em; color: #58a6ff;
  }
  table { border-collapse: collapse; width: 100%%; }
  td, th {
    text-align: left; padding: 6px 16px 6px 0;
    font-variant-numeric: tabular-nums;
  }
  th { color: #8b949e; font-weight: 400; font-size: 0.9em; }
  td { color: #e6edf3; }
  .stat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0; }
  .model-table th {
    border-bottom: 1px solid #30363d; padding-bottom: 8px;
    font-size: 0.8em; text-transform: uppercase; letter-spacing: 0.05em;
  }
  .model-table td {
    border-bottom: 1px solid #21262d; padding: 8px 16px 8px 0;
    font-family: ui-monospace, 'SF Mono', 'Cascadia Code', Menlo, monospace;
    font-size: 0.85em;
  }
  .model-table td:first-child {
    font-family: -apple-system, system-ui, 'Segoe UI', sans-serif; font-size: 0.9em;
  }
  .model-table tr:last-child td { border-bottom: none; }
  .footer {
    color: #484f58; font-size: 0.8em;
    margin-top: 2em; padding-top: 1em; border-top: 1px solid #21262d;
  }
  .footer code { background: transparent; padding: 0; }
  .text-green { color: #3fb950; }
  .text-red { color: #f85149; }
  .status-banner {
    border-radius: 8px; padding: 14px 20px; margin-top: 1.5em;
    font-size: 1em; font-weight: 500; color: #e6edf3;
    border-left: 3px solid transparent;
  }
  .status-banner.green { background: #0d2b0d; border-left-color: #3fb950; }
  .status-banner.yellow { background: #2b2200; border-left-color: #d29922; }
  .status-banner.red { background: #2b0d0d; border-left-color: #f85149; }
  .status-banner.grey { background: #161b22; border-left-color: #484f58; color: #8b949e; }
  .status-row {
    padding: 10px 20px; background: #161b22; border: 1px solid #30363d;
    border-radius: 8px; margin-top: 8px;
  }
  .status-row-head { display: flex; justify-content: space-between; align-items: baseline; }
  .status-row-name { font-weight: 500; color: #e6edf3; }
  .status-row-time { font-size: 0.8em; color: #8b949e; flex-shrink: 0; margin-left: 12px; }
  .status-row-detail { font-size: 0.85em; color: #8b949e; margin-top: 3px; }
</style>
</head>
<body>
<h1>teep</h1>
<p class="subtitle">TEE attestation proxy on <code id="listen-addr"></code> &mdash; up <span id="uptime"></span></p>

<div id="status-banner"></div>
<div id="status-models"></div>

<h2>Attestation</h2>
<section>
<table class="model-table">
  <tr><th>Provider</th><th>Model</th><th>Score</th><th>E2EE</th><th>Verified</th></tr>
  <tbody id="attest-rows"></tbody>
</table>
</section>

<h2>Models</h2>
<section>
<table class="model-table">
  <tr><th>Model</th><th>Requests</th><th>Errors</th><th>Verify</th><th>Tok/s</th><th>Last request</th></tr>
  <tbody id="model-rows"></tbody>
</table>
</section>

<h2>Requests</h2>
<section>
<div class="stat-grid">
<table>
  <tr><th>Total</th><td id="req-total"></td></tr>
  <tr><th>Streaming</th><td id="req-streaming"></td></tr>
  <tr><th>Non-stream</th><td id="req-nonstream"></td></tr>
</table>
<table>
  <tr><th>E2EE</th><td id="req-e2ee"></td></tr>
  <tr><th>Plaintext</th><td id="req-plaintext"></td></tr>
  <tr><th>Errors</th><td id="req-errors"></td></tr>
</table>
</div>
<table style="margin-top:8px">
  <tr><th>Last request</th><td id="req-last-request"></td></tr>
  <tr><th>Last success</th><td id="req-last-success"></td></tr>
</table>
</section>

<h2>Attestation Cache</h2>
<section>
<table>
  <tr><th>Entries</th><td id="cache-entries"></td></tr>
  <tr><th>Negative</th><td id="cache-negative"></td></tr>
  <tr><th>Hit rate</th><td id="cache-hitrate"></td></tr>
</table>
</section>

<h2>HTTP Transport</h2>
<section>
<table>
  <tr><th>Requests</th><td id="http-requests"></td></tr>
  <tr><th>Errors</th><td id="http-errors"></td></tr>
</table>
</section>

<h2>Endpoints</h2>
<section>
<table>
  <tr><td><code>POST /v1/chat/completions</code></td><td>Proxy with TEE attestation</td></tr>
  <tr><td><code>GET /v1/models</code></td><td>List models</td></tr>
  <tr><td><code>GET /v1/tee/report</code></td><td>Cached attestation report</td></tr>
</table>
</section>

<h2>Providers</h2>
<section>
<table class="model-table">
  <tr><th>Name</th><th>Upstream</th><th>E2EE</th></tr>
  <tbody id="prov-rows"></tbody>
</table>
</section>

<p class="footer" id="footer"></p>

<script>
function esc(s) {
  var d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

function render(d) {
  document.getElementById("listen-addr").textContent = d.listen_addr;
  document.getElementById("uptime").textContent = d.uptime;

  // --- Status overview ---
  var atts = d.attestations || [];
  var nBlocked = 0, nE2EE = 0, nVerified = 0;
  for (var i = 0; i < atts.length; i++) {
    if (atts[i].blocked) { nBlocked++; }
    else { nVerified++; if (atts[i].e2ee === "usable") nE2EE++; }
  }
  var bannerText, bannerClass;
  if (atts.length === 0) {
    bannerText = "No models verified yet \u2014 send a request to begin";
    bannerClass = "grey";
  } else if (nBlocked > 0 && nVerified === 0) {
    bannerText = "Security verification failed for " + nBlocked + " model" + (nBlocked > 1 ? "s" : "");
    bannerClass = "red";
  } else if (nBlocked > 0) {
    bannerText = nVerified + " model" + (nVerified > 1 ? "s" : "") + " verified" +
      (nE2EE > 0 ? " \u00b7 end-to-end encrypted" : "") + " \u00b7 " +
      nBlocked + " blocked";
    bannerClass = "yellow";
  } else if (nE2EE === nVerified) {
    bannerText = nVerified + " model" + (nVerified > 1 ? "s" : "") +
      " running in secure enclave" + (nVerified > 1 ? "s" : "") +
      " \u00b7 End-to-end encrypted";
    bannerClass = "green";
  } else {
    bannerText = nVerified + " model" + (nVerified > 1 ? "s" : "") +
      " running in secure enclave" + (nVerified > 1 ? "s" : "") +
      (nE2EE > 0 ? " \u00b7 " + nE2EE + " encrypted" : "");
    bannerClass = "yellow";
  }
  var banner = document.getElementById("status-banner");
  banner.textContent = bannerText;
  banner.className = "status-banner " + bannerClass;

  var statusModels = document.getElementById("status-models");
  statusModels.innerHTML = "";
  for (var i = 0; i < atts.length; i++) {
    var a = atts[i];
    var ms = d.models[a.provider + "/" + a.model] || {};
    var reqCount = ms.requests || 0;
    var dot, dotColor, detail;
    if (a.blocked) {
      dot = "\u2717"; dotColor = "#f85149";
      detail = "Security blocked \u2014 " + esc((a.blocked_factors || []).join(", ") || "unknown");
    } else if (a.e2ee === "usable") {
      dot = "\u25cf"; dotColor = "#3fb950";
      detail = "Secure enclave \u00b7 End-to-end encrypted";
    } else if (a.e2ee === "capable") {
      dot = "\u26a0"; dotColor = "#d29922";
      detail = "Secure enclave \u00b7 Encryption available";
    } else if (a.allowed_failed > 0) {
      dot = "\u26a0"; dotColor = "#d29922";
      detail = "Secure enclave \u00b7 Some checks pending";
    } else {
      dot = "\u25cf"; dotColor = "#3fb950";
      detail = "Secure enclave \u00b7 Standard connection";
    }
    if (reqCount > 0) detail += " \u00b7 " + reqCount + " req";
    var div = document.createElement("div");
    div.className = "status-row";
    div.innerHTML = '<div class="status-row-head">' +
      '<span class="status-row-name"><span style="color:' + dotColor + '">' + dot + '</span> ' +
      esc(a.provider) + " / " + esc(a.model) + '</span>' +
      '<span class="status-row-time">verified ' + esc(a.verified) + '</span>' +
      '</div><div class="status-row-detail">' + detail + '</div>';
    statusModels.appendChild(div);
  }
  // Models with requests but no attestation yet
  for (var k in d.models) {
    var seen = false;
    for (var i = 0; i < atts.length; i++) {
      if (atts[i].provider + "/" + atts[i].model === k) { seen = true; break; }
    }
    if (!seen && d.models[k].requests > 0) {
      var div = document.createElement("div");
      div.className = "status-row";
      div.innerHTML = '<div class="status-row-head">' +
        '<span class="status-row-name"><span style="color:#484f58">\u25cc</span> ' + esc(k) + '</span>' +
        '</div><div class="status-row-detail">Awaiting verification \u00b7 ' + d.models[k].requests + ' req</div>';
      statusModels.appendChild(div);
    }
  }

  var provRows = document.getElementById("prov-rows");
  provRows.innerHTML = "";
  var provNames = Object.keys(d.providers).sort();
  for (var i = 0; i < provNames.length; i++) {
    var pname = provNames[i];
    var p = d.providers[pname];
    var e2eeClass = p.e2ee === "enabled" ? "text-green" : "text-red";
    var tr = document.createElement("tr");
    tr.innerHTML = "<td>" + esc(pname) + "</td><td>" + esc(p.upstream) + "</td><td class=\"" + e2eeClass + "\">" + esc(p.e2ee) + "</td>";
    provRows.appendChild(tr);
  }
  var attestRows = document.getElementById("attest-rows");
  attestRows.innerHTML = "";
  if (atts.length === 0) {
    var tr = document.createElement("tr");
    tr.innerHTML = "<td colspan=\"5\" style=\"color:#8b949e\">No attestations cached yet.</td>";
    attestRows.appendChild(tr);
  } else {
    for (var j = 0; j < atts.length; j++) {
      var a = atts[j];
      var scoreCell;
      if (a.blocked) {
        var detail = (a.blocked_factors && a.blocked_factors.length) ? " \u2014 " + esc(a.blocked_factors.join(", ")) : "";
        scoreCell = "<td class=\"text-red\">BLOCKED" + detail + "</td>";
      } else if (a.allowed_failed > 0) {
        scoreCell = "<td>" + a.passed + " passed <span style=\"color:#8b949e\">(" + a.allowed_failed + " allowed)</span></td>";
      } else {
        scoreCell = "<td class=\"text-green\">" + a.passed + " passed</td>";
      }
      var e2eeCell;
      if (a.e2ee === "usable") {
        e2eeCell = "<td class=\"text-green\">usable</td>";
      } else if (a.e2ee === "capable") {
        e2eeCell = "<td style=\"color:#d29922\">capable</td>";
      } else {
        e2eeCell = "<td style=\"color:#484f58\">\u2014</td>";
      }
      var tr = document.createElement("tr");
      tr.innerHTML = "<td>" + esc(a.provider) + "</td><td>" + esc(a.model) +
        "</td>" + scoreCell + e2eeCell + "<td>" + esc(a.verified) + "</td>";
      attestRows.appendChild(tr);
    }
  }
  document.getElementById("req-total").textContent = d.requests.total;
  document.getElementById("req-streaming").textContent = d.requests.streaming;
  document.getElementById("req-nonstream").textContent = d.requests.non_stream;
  document.getElementById("req-e2ee").textContent = d.requests.e2ee;
  document.getElementById("req-plaintext").textContent = d.requests.plaintext;
  var errors = document.getElementById("req-errors");
  errors.textContent = d.requests.errors;
  errors.className = d.requests.errors > 0 ? "text-red" : "";
  document.getElementById("req-last-request").textContent = d.requests.last_request_at;
  document.getElementById("req-last-success").textContent = d.requests.last_success_at;
  document.getElementById("cache-entries").textContent = d.cache.entries;
  document.getElementById("cache-negative").textContent = d.cache.negative;
  document.getElementById("cache-hitrate").textContent =
    d.cache.hit_rate + " (" + d.cache.hits + " hit, " + d.cache.misses + " miss)";
  document.getElementById("http-requests").textContent = d.http.requests;
  var httpErrors = document.getElementById("http-errors");
  httpErrors.textContent = d.http.errors;
  httpErrors.className = d.http.errors > 0 ? "text-red" : "";
  var tbody = document.getElementById("model-rows");
  tbody.innerHTML = "";
  for (var k in d.models) {
    var m = d.models[k];
    var tr = document.createElement("tr");
    var errClass = m.errors > 0 ? " class=\"text-red\"" : "";
    tr.innerHTML = "<td>" + esc(k) + "</td><td>" + m.requests + "</td><td" +
      errClass + ">" + m.errors + "</td><td>" + esc(m.verify_ms) + "</td><td>" +
      esc(m.tok_per_sec) + "</td><td>" + esc(m.last_request) + "</td>";
    tbody.appendChild(tr);
  }
  document.getElementById("footer").innerHTML =
    "Live via SSE &mdash; Point any OpenAI-compatible client at <code>http://" + esc(d.listen_addr) + "/v1</code> using <code>provider:model</code> format (e.g. <code>venice:qwen3-5b</code>).";
}

render(%s);

var es = new EventSource("/events");
es.onmessage = function(e) { render(JSON.parse(e.data)); };
es.onerror = function() { setTimeout(function() { location.reload(); }, 5000); };
</script>
</body>
</html>
`, initial)
}
