package proxy

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// missingPortInAddress mirrors the stable error text net.SplitHostPort
// returns (via *net.AddrError.Err) when hostport has no ":port" suffix at
// all. There is no exported sentinel for this in net, so we match on the
// documented, stable message rather than substring-matching the address
// itself.
const missingPortInAddress = "missing port in address"

// contentSecurityPolicy is served on dashboard/HTML routes. script-src and
// style-src 'unsafe-inline' are both required because the templates embed
// inline <script> blocks, inline <style> blocks, and style="" attributes;
// tightening that belongs to a follow-up that moves those to static/hashed
// assets. M5's DOM-API rendering + hardened esc() reduce what an injected
// script could do in the meantime.
const contentSecurityPolicy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"

// hostGuard is a precomputed Host-header allowlist. It defends the
// loopback-bound proxy against DNS-rebinding: a browser page on a rebound
// domain that resolves to 127.0.0.1 becomes same-origin with the proxy from
// the browser's perspective, but the HTTP Host header it sends still names
// the attacker's domain — so rejecting unknown Host values closes the hole
// even though the TCP connection itself looks like ordinary loopback
// traffic.
type hostGuard struct {
	// port is the configured listen port. anyPort is set when the operator
	// configured an ephemeral port (":0", OS-assigned); this is never done
	// for real deployments (the documented default is 127.0.0.1:8337) and
	// is only used by test harnesses that bind an OS-assigned port decoupled
	// from the Config the Server was built with. In that case there is no
	// fixed port to compare against, so any port is accepted for an
	// otherwise-allowed host — the hostname/IP check (the actual
	// rebinding defense) still applies in full.
	port    string
	anyPort bool
	// allowedHosts holds canonicalized (net.ParseIP-normalized, or
	// lowercased for names) hosts that may be presented via the Host
	// header: 127.0.0.1, ::1, localhost, and the configured listen host
	// when the operator deliberately binds non-loopback.
	allowedHosts map[string]struct{}
}

// newHostGuard builds a hostGuard from the proxy's configured listen
// address (config.Config.ListenAddr / TEEP_LISTEN_ADDR). It fails closed:
// an unparsable listen address is a startup error, not a warning, since the
// guard cannot be built without knowing the configured authority.
func newHostGuard(listenAddr string) (*hostGuard, error) {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return nil, err
	}
	g := &hostGuard{
		port:         port,
		anyPort:      port == "0",
		allowedHosts: make(map[string]struct{}, 4),
	}
	g.allowedHosts[canonicalAuthorityHost("127.0.0.1")] = struct{}{}
	g.allowedHosts[canonicalAuthorityHost("::1")] = struct{}{}
	g.allowedHosts[canonicalAuthorityHost("localhost")] = struct{}{}
	if host != "" {
		g.allowedHosts[canonicalAuthorityHost(host)] = struct{}{}
	}
	return g, nil
}

// canonicalAuthorityHost normalizes a bare host (no port) for allowlist
// comparison. IP literals are canonicalized via net.ParseIP so that any
// equivalent textual form of the same address compares equal; non-IP
// hostnames are lowercased. This never does substring or prefix matching.
func canonicalAuthorityHost(host string) string {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return strings.ToLower(host)
}

// allow reports whether hostHeader — an incoming request's Host field — is
// in the allowlist. A Host header with no port is treated as using the
// configured listen port (OpenAI SDK clients and browsers reliably send an
// explicit port for a non-default-port proxy like this one, but we don't
// require it). Anything that fails to parse as "host[:port]" for a reason
// other than a missing port (garbage, empty, ambiguous unbracketed IPv6,
// etc.) is rejected outright.
func (g *hostGuard) allow(hostHeader string) bool {
	host, port, err := net.SplitHostPort(hostHeader)
	if err != nil {
		var addrErr *net.AddrError
		if !errors.As(err, &addrErr) || addrErr.Err != missingPortInAddress {
			return false
		}
		host, port = hostHeader, g.port
	}
	if !g.anyPort && port != g.port {
		return false
	}
	_, ok := g.allowedHosts[canonicalAuthorityHost(host)]
	return ok
}

// isHTMLRoute reports whether path serves an HTML document (the dashboard
// or the explore page), as opposed to a JSON/text/event-stream API route.
func isHTMLRoute(path string) bool {
	return path == "/" || path == "/explore"
}

// applySecurityHeaders sets baseline security headers for path's response
// class. Handlers may still override individual headers afterward (e.g.
// /events sets its own Cache-Control) since headers only take effect at the
// first Write/WriteHeader call.
func applySecurityHeaders(w http.ResponseWriter, path string) {
	h := w.Header()
	if isHTMLRoute(path) {
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		return
	}
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
}

// isCrossSiteExploreMutation reports whether r is a state-changing
// dashboard request (POST /explore/*) carrying a Sec-Fetch-Site header that
// declares it did not originate same-origin. The hostGuard Host check
// already defeats classic DNS rebinding; this is a cheap secondary barrier
// against future browser-level edge cases, alongside the existing
// JSON-content-type preflight barrier on these same endpoints.
func isCrossSiteExploreMutation(r *http.Request) bool {
	if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, "/explore/") {
		return false
	}
	site := r.Header.Get("Sec-Fetch-Site")
	return site != "" && site != "same-origin" && site != "none"
}

// rejectHost writes a 403 naming the rejected Host value (non-secret — a
// Host header is not sensitive) and emits a rate-limited WARN log, since a
// rejected Host is itself a signal worth surfacing (e.g. a DNS-rebinding
// attempt).
func (s *Server) rejectHost(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if allowHourlyLogAtLevel(r.Context(), &s.hostGuardLogs, slog.LevelWarn, host) {
		slog.WarnContext(r.Context(), "rejected request: Host header not in allowlist",
			"host", host, "method", r.Method, "path", r.URL.Path)
	}
	http.Error(w, fmt.Sprintf("host not allowed: %q", host), http.StatusForbidden)
}

// hostGuardMiddleware wraps the entire mux exactly once (see registerRoutes
// and New) so every route — including /v1/* — gets the Host allowlist and
// baseline security headers. There is no per-route opt-out and no config
// knob to disable the Host check: the only way to widen the allowlist is
// the configured listen address itself.
func (s *Server) hostGuardMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applySecurityHeaders(w, r.URL.Path)

		if !s.hostGuard.allow(r.Host) {
			s.rejectHost(w, r)
			return
		}
		if isCrossSiteExploreMutation(r) {
			http.Error(w, "cross-site request rejected", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
