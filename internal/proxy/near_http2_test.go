package proxy_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/proxy"
	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestNearHTTP2ConcurrentProvidersAndModels(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		keys := make(map[string]*mockNearKeys)
		for _, name := range []string{"nearcloud", "neardirect"} {
			for _, model := range []string{"one", "two"} {
				keys[name+":"+model] = generateMockKeys(t)
			}
		}
		arrived := make(chan struct{})
		var requests atomic.Int32
		var mu sync.Mutex
		connections := make(map[string]bool)
		var sessionKeys []string
		upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			connections[r.RemoteAddr] = true
			key := r.Header.Get("X-Client-Pub-Key")
			for _, previous := range sessionKeys {
				if subtle.ConstantTimeCompare([]byte(previous), []byte(key)) == 1 {
					t.Error("NEAR inference reused an encryption session")
				}
			}
			sessionKeys = append(sessionKeys, key)
			mu.Unlock()
			n := requests.Add(1)
			if n == 12 {
				close(arrived)
			}
			if n > 4 {
				select {
				case <-arrived:
				case <-r.Context().Done():
					return
				}
			}
			serveNearMultiplexRequest(t, w, r, keys)
		}))
		srv := nearMultiplexProxy(t, upstream.URL, keys, upstream.Certificate().RawSubjectPublicKeyInfo)
		defer srv.Close()
		endpoint := authority.NewTLSServer(t, srv)
		client := tlsct.NewHTTPClient(10 * time.Second)
		defer client.CloseIdleConnections()
		for _, name := range []string{"nearcloud", "neardirect"} {
			for _, stream := range []bool{false, true} {
				nearMultiplexRequest(t, client, endpoint.URL, name+":one", "warm", stream)
			}
		}
		var wg sync.WaitGroup
		for _, name := range []string{"nearcloud", "neardirect"} {
			for _, model := range []string{"one", "two"} {
				for _, stream := range []bool{false, true} {
					wg.Go(func() { nearMultiplexRequest(t, client, endpoint.URL, name+":"+model, "concurrent", stream) })
				}
			}
		}
		wg.Wait()
		mu.Lock()
		count := len(connections)
		mu.Unlock()
		if requests.Load() != 12 || count != 2 {
			t.Fatalf("requests=%d connections=%d; want 12 requests on two provider pools", requests.Load(), count)
		}
	})
}

func serveNearMultiplexRequest(t *testing.T, w http.ResponseWriter, r *http.Request, keys map[string]*mockNearKeys) {
	t.Helper()
	body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		t.Error("invalid multiplex request body")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	var envelope struct {
		Model string `json:"model"`
	}
	// Only the routing field is read here; the mock decrypts the full body.
	if _, _, err := jsonstrict.Unmarshal(body, &envelope); err != nil {
		t.Error(err)
		http.Error(w, "invalid model", http.StatusBadRequest)
		return
	}
	name := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	key := keys[name+":"+envelope.Model]
	if key == nil {
		t.Error("provider or model was routed incorrectly")
		http.Error(w, "unknown route", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	mock := &mockNearPinnedHandler{keys: key, providerName: name}
	mock.serve(w, r, true)
}

func nearMultiplexProxy(t *testing.T, origin string, keys map[string]*mockNearKeys, spki []byte) *proxy.Server {
	t.Helper()
	srv, err := proxy.New(&config.Config{Providers: map[string]*config.Provider{
		"nearcloud":  {Name: "nearcloud", BaseURL: origin, APIKey: "nearcloud", E2EE: true},
		"neardirect": {Name: "neardirect", BaseURL: origin, APIKey: "neardirect", E2EE: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	route, err := provider.NewResolvedRoute(origin, "")
	if err != nil {
		t.Fatal(err)
	}
	fp := sha256.Sum256(spki)
	for _, name := range []string{"nearcloud", "neardirect"} {
		prov := srv.ProviderByName(name)
		prov.StaticRoute, prov.BaseURL, prov.Attester = route, route.BaseURL(), nil
		// NEAR direct must retain its production resolver for the configured origin.
		// NEAR cloud has a fixed public gateway, so this fixture supplies its route.
		if name == "nearcloud" {
			prov.ResolveRoute = nil
		}
		for _, model := range []string{"one", "two"} {
			// This test isolates transport multiplexing with authenticated keys;
			// fixture and live suites exercise the full evidence policy.
			report := &attestation.VerificationReport{Provider: name, Model: model, TLSAuthority: route.Authority(), TLSKeyFP: hex.EncodeToString(fp[:]), Factors: []attestation.FactorResult{{Name: attestation.FactorTEEReportData, Status: attestation.Pass}}}
			if err := srv.PutAuthorizationForTest(t.Context(), name, model, route, report, keys[name+":"+model].edPubHex); err != nil {
				t.Fatal(err)
			}
		}
	}
	return srv
}

func nearMultiplexRequest(t *testing.T, client *http.Client, origin, model, phase string, stream bool) {
	t.Helper()
	prompt := fmt.Sprintf("%s-%s-stream-%v", phase, model, stream)
	body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":%q}],"stream":%v}`, model, prompt, stream)
	resp, err := client.Post(origin+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Error("NEAR multiplexed request failed")
		return
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusOK || !strings.Contains(string(response), "echo: "+prompt) {
		t.Error("NEAR multiplexed response did not decrypt successfully")
	}
}
