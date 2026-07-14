package proxy_test

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// readBody reads and returns resp.Body as a string, closing it afterward.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// newHostGuardTestServer returns a proxy httptest.Server suitable for
// exercising hostGuardMiddleware and security headers without needing a
// full attestation round-trip: GET /health, /metrics, /v1/{$}, / and
// /explore never call out to a provider.
func newHostGuardTestServer(t *testing.T) *httptestServerWithPort {
	t.Helper()
	attestSrv := makeAttestationServer(t, false)
	t.Cleanup(attestSrv.Close)

	proxySrv := newProxyServer(t, buildConfig(attestSrv.URL, false))
	t.Cleanup(proxySrv.Close)

	return &httptestServerWithPort{URL: proxySrv.URL, Client: proxySrv.Client()}
}

// httptestServerWithPort is a tiny facade so this file doesn't need to
// import httptest directly for its one use (Client()).
type httptestServerWithPort struct {
	URL    string
	Client *http.Client
}

func doWithHost(t *testing.T, client *http.Client, url, host string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s (Host=%q): %v", url, host, err)
	}
	return resp
}

func TestHostGuardMiddleware_RejectsUnknownHost(t *testing.T) {
	srv := newHostGuardTestServer(t)

	resp := doWithHost(t, srv.Client, srv.URL+"/", "attacker.example:8337")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "attacker.example:8337") {
		t.Errorf("403 body = %q, want it to name the rejected Host", body)
	}
	// The body must not leak anything beyond the (non-secret) Host value.
	if strings.Contains(strings.ToLower(body), "provider") || strings.Contains(strings.ToLower(body), "api_key") {
		t.Errorf("403 body leaks internal details: %q", body)
	}
}

func TestHostGuardMiddleware_RejectsGarbageAndEmptyHost(t *testing.T) {
	srv := newHostGuardTestServer(t)

	// buildConfig uses ListenAddr "127.0.0.1:0" (ephemeral, OS-assigned port
	// — the guard's port-wildcard case, see hostguard_internal_test.go for
	// dedicated fixed-port mismatch coverage), so these must all fail on
	// the hostname check itself, independent of port.
	//
	// A genuinely empty Host header can't be produced through net/http's
	// client (an empty Request.Host falls back to the dialed URL's host,
	// which is exactly the allowed loopback address); that case — and the
	// "missing port" / IPv6-without-brackets edge cases — is covered
	// directly against hostGuard.allow in hostguard_internal_test.go.
	for _, host := range []string{"!!!not-a-host!!!", "evil:8337:8337"} {
		resp := doWithHost(t, srv.Client, srv.URL+"/health", host)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Host=%q: status = %d, want 403", host, resp.StatusCode)
		}
	}
}

func TestHostGuardMiddleware_AllowsLoopbackForms(t *testing.T) {
	srv := newHostGuardTestServer(t)

	// The httptest server always listens on 127.0.0.1 with an OS-assigned
	// port, so proxy.New was given ListenAddr "127.0.0.1:0" (see
	// buildConfig) — the ephemeral-port guard accepts any port for an
	// allowed host, letting this test assert purely on hostname forms.
	for _, host := range []string{"127.0.0.1", "localhost", "LOCALHOST", "[::1]"} {
		resp := doWithHost(t, srv.Client, srv.URL+"/health", host+portOf(t, srv.URL))
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Host=%q: status = %d, want 200, body=%q", host, resp.StatusCode, body)
		}
	}
}

// portOf extracts ":<port>" from a "http://host:port" URL.
func portOf(t *testing.T, rawURL string) string {
	t.Helper()
	i := strings.LastIndex(rawURL, ":")
	if i < 0 {
		t.Fatalf("no port in URL %q", rawURL)
	}
	return rawURL[i:]
}

func TestSecurityHeaders_HTMLRoutes(t *testing.T) {
	srv := newHostGuardTestServer(t)

	for _, path := range []string{"/", "/explore"} {
		resp, err := srv.Client.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body) // drain fully to avoid a server-side connection-reset log
		resp.Body.Close()

		wantCSP := "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
		if got := resp.Header.Get("Content-Security-Policy"); got != wantCSP {
			t.Errorf("%s: CSP = %q, want %q", path, got, wantCSP)
		}
		if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("%s: X-Frame-Options = %q, want DENY", path, got)
		}
		if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q, want nosniff", path, got)
		}
		if got := resp.Header.Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("%s: Referrer-Policy = %q, want no-referrer", path, got)
		}
	}
}

func TestSecurityHeaders_APIRoutes(t *testing.T) {
	srv := newHostGuardTestServer(t)

	for _, path := range []string{"/health", "/metrics", "/v1/", "/v1/models"} {
		resp, err := srv.Client.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()

		if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q, want nosniff", path, got)
		}
		if got := resp.Header.Get("Content-Security-Policy"); got != "" {
			t.Errorf("%s: unexpected CSP on an API route: %q", path, got)
		}
		if got := resp.Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control = %q, want no-store", path, got)
		}
	}
}

func TestExploreInfer_RejectsCrossSiteSecFetchSite(t *testing.T) {
	srv := newHostGuardTestServer(t)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/explore/infer", strings.NewReader(`{"model":"venice:tee-test-model"}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := srv.Client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for Sec-Fetch-Site: cross-site", resp.StatusCode)
	}
	if body := readBody(t, resp); !strings.Contains(body, "cross-site") {
		t.Errorf("body = %q, want it to explain the cross-site rejection", body)
	}
}

func TestExploreInfer_AllowsSameOriginSecFetchSite(t *testing.T) {
	srv := newHostGuardTestServer(t)

	for _, site := range []string{"same-origin", "none", ""} {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/explore/infer", strings.NewReader(`{"model":"nope:nope"}`))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		resp, err := srv.Client.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		body := readBody(t, resp)
		// The request is otherwise rejected (unknown model → 400), but it
		// must NOT be rejected by the cross-site check.
		if resp.StatusCode == http.StatusForbidden && strings.Contains(body, "cross-site") {
			t.Errorf("Sec-Fetch-Site=%q was wrongly rejected as cross-site: %q", site, body)
		}
	}
}

// TestOpenAISDKShapedRequest_LoopbackHostWorks is a regression test: an
// OpenAI-SDK-shaped client (default Host from the dialed loopback address,
// standard headers, no special casing) must be unaffected by the Host
// allowlist added for DNS-rebinding protection.
func TestOpenAISDKShapedRequest_LoopbackHostWorks(t *testing.T) {
	srv := newHostGuardTestServer(t)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/models", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer sk-does-not-matter")
	req.Header.Set("User-Agent", "OpenAI/Python 1.0")
	// Deliberately do NOT set req.Host: this reproduces what every
	// OpenAI-compatible SDK does (it lets net/http fill Host from the
	// dialed loopback address), the exact case the Host allowlist must not
	// break.
	resp, err := srv.Client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestHostGuardMiddleware_Concurrent drives many concurrent requests
// (a mix of allowed and rejected Host headers) through the full HTTP
// stack -race, since hostGuardMiddleware wraps the /v1/* hot path.
func TestHostGuardMiddleware_Concurrent(t *testing.T) {
	srv := newHostGuardTestServer(t)

	var wg sync.WaitGroup
	hosts := []string{"!!!bad-host!!!", "attacker.example:8337", "localhost" + portOf(t, srv.URL), "127.0.0.1" + portOf(t, srv.URL)}
	for i := range 40 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp := doWithHost(t, srv.Client, srv.URL+"/health", hosts[i%len(hosts)])
			resp.Body.Close()
		}(i)
	}
	wg.Wait()
}
