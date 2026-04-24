package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// dashboardData is the JSON-serializable snapshot of all dashboard stats.
// Used by both the initial page render and the SSE /events endpoint.
type dashboardData struct {
	ListenAddr string               `json:"listen_addr"`
	Uptime     string               `json:"uptime"`
	Provider   dashboardProvider    `json:"provider"`
	Requests   dashboardRequests    `json:"requests"`
	Cache      dashboardCache       `json:"cache"`
	HTTP       dashboardHTTP        `json:"http"`
	Models     map[string]dashModel `json:"models"`
}

type dashboardProvider struct {
	Name     string `json:"name"`
	Upstream string `json:"upstream"`
	E2EE     string `json:"e2ee"`
}

type dashboardRequests struct {
	Total     int64 `json:"total"`
	Streaming int64 `json:"streaming"`
	NonStream int64 `json:"non_stream"`
	E2EE      int64 `json:"e2ee"`
	Plaintext int64 `json:"plaintext"`
	Errors    int64 `json:"errors"`
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

func (s *Server) buildHTTPStats() dashboardHTTP {
	return dashboardHTTP{
		Requests: s.stats.httpRequests.Load(),
		Errors:   s.stats.httpErrors.Load(),
	}
}

func (s *Server) buildDashboardData() dashboardData {
	var provName, baseURL, e2eeStatus string
	for name, p := range s.providers {
		provName = name
		baseURL = p.BaseURL
		if p.E2EE {
			e2eeStatus = "enabled"
		} else {
			e2eeStatus = "disabled"
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

	return dashboardData{
		ListenAddr: s.cfg.ListenAddr,
		Uptime:     time.Since(s.stats.startTime).Truncate(time.Second).String(),
		Provider: dashboardProvider{
			Name:     provName,
			Upstream: baseURL,
			E2EE:     e2eeStatus,
		},
		Requests: dashboardRequests{
			Total:     s.stats.requests.Load(),
			Streaming: s.stats.streaming.Load(),
			NonStream: s.stats.nonStream.Load(),
			E2EE:      s.stats.e2ee.Load(),
			Plaintext: s.stats.plaintext.Load(),
			Errors:    s.stats.errors.Load(),
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

	nanoToPtr := func(ns int64) *string {
		if ns == 0 {
			return nil
		}
		t := time.Unix(0, ns).UTC().Format(time.RFC3339)
		return &t
	}

	resp := healthResponse{
		Status:        "ok",
		UptimeSeconds: time.Since(s.stats.startTime).Seconds(),
		LastRequestAt: nanoToPtr(s.stats.lastRequestAt.Load()),
		LastSuccessAt: nanoToPtr(s.stats.lastSuccessAt.Load()),
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
</style>
</head>
<body>
<h1>teep</h1>
<p class="subtitle">TEE attestation proxy on <code id="listen-addr"></code> &mdash; up <span id="uptime"></span></p>

<h2>Provider</h2>
<section>
<table>
  <tr><th>Name</th><td id="prov-name"></td></tr>
  <tr><th>Upstream</th><td id="prov-upstream"></td></tr>
  <tr><th>E2EE</th><td id="prov-e2ee"></td></tr>
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

<h2>Models</h2>
<section>
<table class="model-table">
  <tr><th>Model</th><th>Requests</th><th>Errors</th><th>Verify</th><th>Tok/s</th><th>Last request</th></tr>
  <tbody id="model-rows"></tbody>
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
  document.getElementById("prov-name").textContent = d.provider.name;
  document.getElementById("prov-upstream").textContent = d.provider.upstream;
  var e2ee = document.getElementById("prov-e2ee");
  e2ee.textContent = d.provider.e2ee;
  e2ee.className = d.provider.e2ee === "enabled" ? "text-green" : "text-red";
  document.getElementById("req-total").textContent = d.requests.total;
  document.getElementById("req-streaming").textContent = d.requests.streaming;
  document.getElementById("req-nonstream").textContent = d.requests.non_stream;
  document.getElementById("req-e2ee").textContent = d.requests.e2ee;
  document.getElementById("req-plaintext").textContent = d.requests.plaintext;
  var errors = document.getElementById("req-errors");
  errors.textContent = d.requests.errors;
  errors.className = d.requests.errors > 0 ? "text-red" : "";
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
    "Live via SSE. Point any OpenAI-compatible client at <code>http://" + esc(d.listen_addr) + "/v1</code>";
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
