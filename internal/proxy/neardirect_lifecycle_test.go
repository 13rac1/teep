package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// These unit scenarios isolate routing, real TLS authentication, and generation
// ownership under the explicit offline policy (generated public-name certificates
// have no public CT evidence). WebPKI and SPKI checks remain production checks.
// Synthetic parser evidence is not a signed quote; the live eviction
// and key-recovery tests separately require complete online admission.
type directLifecycleFixture struct {
	t                            *testing.T
	server                       *Server
	direct                       *neardirect.Attester
	route                        provider.ResolvedRoute
	selected                     atomic.Pointer[httptest.Server]
	metadata, fetches, inference atomic.Int32
}

func newDirectLifecycleFixture(t *testing.T, authority *testtls.Authority) *directLifecycleFixture {
	t.Helper()
	f := &directLifecycleFixture{t: t, server: newTLSBindingTestServerHandle()}
	f.server.cfg.Offline = true
	f.server.authorizations = newAuthorizationStore(2, 2, 5*time.Second)
	t.Cleanup(f.server.Close)
	metadata := authority.NewTLSServerForHost(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.metadata.Add(1)
		switch r.URL.Path {
		case "/endpoints":
			_, _ = io.WriteString(w, `{"endpoints":[{"domain":"model.completions.near.ai","models":["model"]}]}`)
		case "/backends/count":
			_, _ = io.WriteString(w, `{"domain":"model.completions.near.ai","requested_domain":"model.completions.near.ai","healthy":1,"total":1}`)
		default:
			t.Error("unexpected metadata request")
			w.WriteHeader(http.StatusBadRequest)
		}
	}), "completions.near.ai")
	resolver := neardirect.NewEndpointResolver()
	resolver.SetClient(lifecycleClient(func() string { return metadata.Listener.Addr().String() }))
	f.direct = neardirect.NewAttesterWithResolver("https://completions.near.ai", "test", resolver)
	f.direct.SetClientFactory(func() *http.Client {
		return lifecycleClient(func() string { return f.selected.Load().Listener.Addr().String() })
	})
	t.Cleanup(func() { f.direct.StopResolution(); f.direct.CloseIdleConnections() })
	var err error
	f.route, err = f.direct.ResolveRoute(t.Context(), "model")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func lifecycleClient(address func() string) *http.Client {
	base := tlsct.NewPooledTransport()
	dial := base.DialContext
	base.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) { return dial(ctx, network, address()) }
	return tlsct.NewHTTPClientWithTransport(5*time.Second, base, false)
}

func (f *directLifecycleFixture) backend(authority *testtls.Authority) *httptest.Server {
	var fingerprint string
	ready := make(chan struct{})
	server := authority.NewTLSServerForHost(f.t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-ready
		if r.TLS.ServerName != f.route.Authority() {
			f.t.Error("selected SNI changed")
		}
		if r.URL.Path == "/v1/attestation/report" {
			f.fetches.Add(1)
			_, _ = w.Write(lifecycleEvidence(f.t, "model", r.URL.Query().Get("nonce"), fingerprint))
			return
		}
		f.inference.Add(1)
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		_, _ = io.WriteString(w, `{}`)
	}), f.route.Authority())
	sum := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	fingerprint = hex.EncodeToString(sum[:])
	close(ready)
	return server
}

func lifecycleEvidence(t *testing.T, model, nonce, fp string) []byte {
	t.Helper()
	report := map[string]any{"model_name": model, "intel_quote": "unit fixture", "nvidia_payload": "unit fixture", "signing_algo": "ed25519", "signing_public_key": strings.Repeat("bb", 32), "signing_address": strings.Repeat("bb", 32), "tls_cert_fingerprint": fp, "request_nonce": nonce, "event_log": []any{}, "info": map[string]any{"app_name": "app", "compose_hash": "ab", "os_image_hash": "ab", "device_id": "ab", "tcb_info": map[string]any{"app_compose": "services: {}"}}}
	envelope := make(map[string]any, len(report)+1)
	maps.Copy(envelope, report)
	envelope["all_attestations"] = []any{report}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func (f *directLifecycleFixture) acquire(ctx context.Context, model string) (*authorization, error) {
	route, err := f.direct.ResolveRoute(ctx, model)
	if err != nil {
		return nil, err
	}
	if route != f.route {
		return nil, errors.New("lifetime route changed")
	}
	key, err := route.AuthorizationKey("neardirect", model)
	if err != nil {
		return nil, err
	}
	value, blocked, err := f.server.authorizations.load(ctx, key, nil, nil, func(owner context.Context) (authorizationVerification, error) {
		raw, err := f.direct.FetchAttestationForRoute(owner, route, model, attestation.NewNonce())
		if err != nil {
			return authorizationVerification{}, err
		}
		report := &attestation.VerificationReport{Provider: "neardirect", Model: model, TLSAuthority: raw.TransportTLSAuthority, TLSKeyFP: raw.TransportTLSFingerprint}
		candidate, err := newAuthorization(key, report, "", false, false)
		return authorizationVerification{candidate: candidate}, err
	})
	if blocked != nil {
		return nil, errors.New("unit authorization blocked")
	}
	return value, err
}

func (f *directLifecycleFixture) installPool(value *authorization, beforeDial func(context.Context) error) *http.Client {
	f.t.Helper()
	client, err := f.server.pinnedClientForIdentity("neardirect", value.identity)
	if err != nil {
		f.t.Fatal(err)
	}
	base := f.server.pinnedUpstreams.entries[pinnedUpstreamKey{provider: "neardirect", authority: f.route.Authority()}].transport
	dial := base.DialContext
	base.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if beforeDial != nil {
			if err := beforeDial(ctx); err != nil {
				return nil, err
			}
		}
		return dial(ctx, network, f.selected.Load().Listener.Addr().String())
	}
	return client
}

func (f *directLifecycleFixture) attempt(ctx context.Context, value *authorization) error {
	prov := &provider.Provider{Name: "neardirect", BaseURL: f.route.BaseURL(), StaticRoute: f.route, UsesTLSBinding: true}
	input := &authorizedRequest{provider: prov, route: f.route, key: value.key, body: []byte(`{}`), path: "/inference", endpoint: e2ee.EndpointChat, contentType: "application/json"}
	result, err := f.server.authorizedRoundtrip(ctx, input)
	if result.upstream != nil {
		_, _ = io.Copy(io.Discard, result.upstream.Resp.Body)
		cleanupAuthorized(result.upstream)
	}
	return err
}

func TestAuthorizedNearDirectRemappingPreservesReplacement(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		f := newDirectLifecycleFixture(t, authority)
		a, b := f.backend(authority), f.backend(authority)
		f.selected.Store(a)
		first, err := f.acquire(t.Context(), "model")
		if err != nil {
			t.Fatal(err)
		}
		entered, release := make(chan struct{}), make(chan struct{})
		var calls atomic.Int32
		old := f.installPool(first, func(ctx context.Context) error {
			if calls.Add(1) == 2 {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		})
		if err := f.attempt(t.Context(), first); err != nil {
			t.Fatal(err)
		}
		old.CloseIdleConnections()
		f.selected.Store(b)
		late := make(chan error, 1)
		go func() { late <- f.attempt(t.Context(), first) }()
		<-entered
		// A second fresh handshake fails first and removes only A's generation.
		if err := f.attempt(t.Context(), first); !errors.Is(err, tlsct.ErrSPKIMismatch) {
			t.Fatalf("remap error: %v", err)
		}
		if f.inference.Load() != 1 {
			t.Fatal("mismatched TLS handshake sent inference bytes")
		}
		replacement := lifecycleConcurrentAcquire(t, f)
		f.installPool(replacement, nil)
		close(release)
		if err := <-late; !errors.Is(err, tlsct.ErrSPKIMismatch) {
			t.Fatalf("late failure: %v", err)
		}
		current, ok := f.server.authorizations.acquire(first.key)
		if !ok || current.generation != replacement.generation {
			t.Fatal("late A failure removed B")
		}
		if err := f.attempt(t.Context(), replacement); err != nil {
			t.Fatal(err)
		}
		if f.metadata.Load() != 2 || f.fetches.Load() != 2 || f.inference.Load() != 2 {
			t.Fatalf("metadata=%d fetches=%d inference=%d", f.metadata.Load(), f.fetches.Load(), f.inference.Load())
		}
	})
}

func lifecycleConcurrentAcquire(t *testing.T, f *directLifecycleFixture) *authorization {
	t.Helper()
	values := make(chan *authorization, 16)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			value, err := f.acquire(t.Context(), "model")
			if err != nil {
				t.Error(err)
				return
			}
			values <- value
		})
	}
	wg.Wait()
	close(values)
	var result *authorization
	for value := range values {
		if result != nil && result.generation != value.generation {
			t.Fatal("joiners acquired different generations")
		}
		result = value
	}
	if result == nil {
		t.Fatal("no authorization published")
	}
	return result
}

func TestAuthorizationNearDirectEvictionRetainsSelection(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		f := newDirectLifecycleFixture(t, authority)
		f.server.authorizations.close()
		f.server.authorizations = newAuthorizationStore(1, 2, 5*time.Second)
		f.selected.Store(f.backend(authority))
		first, err := f.acquire(t.Context(), "model")
		if err != nil {
			t.Fatal(err)
		}
		otherKey, other := testAuthorizationCandidate(t, "other")
		loadTestAuthorization(t, f.server.authorizations, otherKey, other)
		if _, ok := f.server.authorizations.acquire(first.key); ok {
			t.Fatal("first authorization not evicted")
		}
		replacement := lifecycleConcurrentAcquire(t, f)
		if replacement.generation == first.generation || f.server.authorizations.deleteGeneration(first.key, first.generation) {
			t.Fatal("evicted generation affected replacement")
		}
		f.installPool(replacement, nil)
		if err := f.attempt(t.Context(), replacement); err != nil {
			t.Fatal(err)
		}
		if f.metadata.Load() != 2 || f.fetches.Load() != 2 {
			t.Fatalf("metadata=%d fetches=%d", f.metadata.Load(), f.fetches.Load())
		}
	})
}
