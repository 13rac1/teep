package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// Hold real proxy handshake errors until another request replaces one origin
// authorization. All attempts have acquired their original generations by then.
type heldProxyFailure struct {
	base    http.RoundTripper
	ready   chan<- struct{}
	release <-chan struct{}
}

func (h heldProxyFailure) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := h.base.RoundTrip(req)
	if err != nil {
		h.ready <- struct{}{}
		select {
		case <-h.release:
		case <-req.Context().Done():
		}
	}
	return resp, err
}

func TestAuthorizedHTTPSProxyFailureRetainsAuthorization(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, failure := range []string{"webpki", "ct"} {
			t.Run(failure, func(t *testing.T) { testAuthorizedProxyFailure(t, authority, failure) })
		}
	})
}

func testAuthorizedProxyFailure(t *testing.T, authority *testtls.Authority, failure string) {
	t.Helper()
	var originRequests, proxyRequests atomic.Int32
	origin := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		originRequests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyRequests.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	})
	var proxy *httptest.Server
	if failure == "ct" {
		proxy = authority.NewTLSServerForHost(t, proxyHandler, "proxy.example")
	} else {
		proxy = httptest.NewTLSServer(proxyHandler)
		t.Cleanup(proxy.Close)
	}
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	if failure == "ct" {
		proxyURL.Host = "proxy.example"
	}
	server, template, original := authorizedFailureFixture(t, origin, authorizedTestKey(t))
	inputs, values := proxyFailureAuthorizations(t, server, template, original)
	ready, release := make(chan struct{}, len(inputs)), make(chan struct{}, len(inputs))
	defer close(release)
	for _, input := range inputs {
		poolKey := pinnedUpstreamKey{provider: input.provider.Name, authority: input.route.Authority()}
		if server.pinnedUpstreams.entries[poolKey] != nil {
			continue
		}
		base := tlsct.NewPooledTransport()
		base.Proxy = http.ProxyURL(proxyURL)
		if failure == "ct" {
			base.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, proxy.Listener.Addr().String())
			}
		}
		client, err := tlsct.NewSPKIPinnedHTTPClientWithTransport(0, base, original.identity)
		if err != nil {
			t.Fatal(err)
		}
		client.Transport = heldProxyFailure{base: client.Transport, ready: ready, release: release}
		server.pinnedUpstreams.entries[poolKey] = &pinnedUpstreamEntry{identity: original.identity, client: client, transport: base}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, input := range inputs {
		wg.Go(func() {
			_, retry, err := server.authorizedAttempt(ctx, input)
			if err == nil || retry || !tlsct.IsTrustFailure(err) || tlsct.IsOriginTrustFailure(err) {
				t.Errorf("proxy failure classification: retry=%v err=%v", retry, err)
			}
		})
	}
	for range inputs {
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatal("proxy handshakes did not finish")
		}
	}
	// Replace the direct provider's first model; the other direct model and
	// shared cloud router must keep their original generations.
	replaced := len(inputs) - 2
	server.authorizations.invalidate(inputs[replaced].key)
	values[replaced] = loadTestAuthorization(t, server.authorizations, inputs[replaced].key, values[replaced])
	for range inputs {
		release <- struct{}{}
	}
	wg.Wait()
	if originRequests.Load() != 0 || proxyRequests.Load() != 0 {
		t.Fatal("request sent before proxy authentication")
	}
	for i, input := range inputs {
		value, ok := server.authorizations.acquire(input.key)
		if !ok || value.generation != values[i].generation {
			t.Fatal("proxy failure changed origin authorization")
		}
		loaded, blocked, err := server.loadAuthorization(ctx, input.provider, input.route, input.key)
		if err != nil || blocked != nil || loaded.generation != value.generation {
			t.Fatal("subsequent acquisition did not reuse authorization")
		}
	}
}

func proxyFailureAuthorizations(t *testing.T, server *Server, template *authorizedRequest, original *authorization) ([]*authorizedRequest, []*authorization) {
	t.Helper()
	inputs := make([]*authorizedRequest, 0, 4)
	values := make([]*authorization, 0, 4)
	for _, name := range []string{"tinfoil_v3_cloud", "tinfoil_v3_direct"} {
		for _, model := range []string{"one", "two"} {
			input, prov := *template, *template.provider
			prov.Name = name
			input.provider = &prov
			key, err := input.route.AuthorizationKey(name, model)
			if err != nil {
				t.Fatal(err)
			}
			input.key = key
			input.body = []byte(`{"model":"` + model + `","messages":[{"role":"user","content":"test"}]}`)
			report := original.report.Clone()
			report.Provider, report.Model = name, model
			candidate, err := newAuthorization(key, report, original.signingKey, true, false)
			if err != nil {
				t.Fatal(err)
			}
			values = append(values, loadTestAuthorization(t, server.authorizations, key, candidate))
			inputs = append(inputs, &input)
		}
	}
	return inputs, values
}
