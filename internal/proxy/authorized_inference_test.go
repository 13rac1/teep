package proxy

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/tinfoil"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestAuthorizedEHBPConcurrentHTTP2(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		private := authorizedTestKey(t)
		var requests atomic.Int32
		var connections sync.Map
		upstream, fp := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != 2 {
				t.Error("inference did not use HTTP/2")
			}
			connections.Store(r.RemoteAddr, true)
			encap, err := hex.DecodeString(r.Header.Get("Ehbp-Encapsulated-Key"))
			if err != nil {
				t.Error(err)
				return
			}
			plaintext := decryptAuthorizedTestRequest(t, private, encap, io.LimitReader(r.Body, 1<<20))
			if len(plaintext) == 0 {
				t.Error("empty encrypted request")
			}
			requests.Add(1)
			encrypted, nonce := encryptAuthorizedTestResponse(t, private, encap, [][]byte{[]byte("data: {\"id\":\"test\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello\"},\"finish_reason\":null}]}\n\ndata: [DONE]\n\n")})
			w.Header().Set("Ehbp-Response-Nonce", nonce)
			_, _ = w.Write(encrypted)
		}))
		defer upstream.Close()
		server := newTLSBindingTestServerHandle()
		server.authorizations = newAuthorizationStore(10, 2, time.Second)
		defer server.Close()
		route, err := provider.NewResolvedRoute(upstream.URL, tinfoil.RouterRepo)
		if err != nil {
			t.Fatal(err)
		}
		prov := &provider.Provider{Name: "tinfoil_v3_cloud", BaseURL: upstream.URL, StaticRoute: route, UsesTLSBinding: true, E2EE: true, Encryptor: tinfoil.NewE2EE(), Preparer: tinfoil.NewPreparer("test")}
		key, err := route.AuthorizationKey(prov.Name, "model")
		if err != nil {
			t.Fatal(err)
		}
		report := &attestation.VerificationReport{Provider: prov.Name, Model: "model", TLSAuthority: route.Authority(), TLSKeyFP: fp, Factors: []attestation.FactorResult{{Name: attestation.FactorTEEReportData, Status: attestation.Pass}, {Name: attestation.FactorE2EEUsable, Status: attestation.Skip}}}
		value, err := newAuthorization(key, report, hex.EncodeToString(private.PublicKey().Bytes()), true, false, time.Time{}, false, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		loadTestAuthorization(t, server.authorizations, key, value)
		input := &authorizedRequest{provider: prov, route: route, key: key, body: []byte(`{"model":"model","messages":[{"role":"user","content":"test"}]}`), path: "/v1/chat/completions", contentType: "application/json", endpoint: e2ee.EndpointChat}
		// Establish one pooled connection, then verify concurrent encrypted use.
		if _, err := server.inferAuthorized(context.Background(), newInferenceRecorder(), input); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for range 24 {
			wg.Go(func() {
				rec := newInferenceRecorder()
				used, err := server.inferAuthorized(context.Background(), rec, input)
				if err != nil {
					t.Error(err)
				} else if used.report == nil || rec.Code != 200 {
					t.Error("missing successful attempt report")
				}
			})
		}
		wg.Wait()
		count := 0
		connections.Range(func(_, _ any) bool { count++; return true })
		if requests.Load() != 25 || count != 1 {
			t.Fatalf("requests=%d connections=%d", requests.Load(), count)
		}
	})
}

func TestAuthorizedRejectionPreservesReplacement(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		server := newTLSBindingTestServerHandle()
		server.authorizations = newAuthorizationStore(10, 2, time.Second)
		defer server.Close()
		oldKey, newKey := authorizedTestKey(t), authorizedTestKey(t)
		var requests atomic.Int32
		var old *authorization
		var replacement *authorization
		var key provider.AuthorizationKey
		upstream, fp := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if requests.Add(1) == 1 {
				// A simultaneous request has already replaced the rejected generation.
				server.authorizations.deleteGeneration(key, old.generation)
				_, _, loadErr := server.authorizations.load(r.Context(), key, nil, nil, func(context.Context) (authorizationVerification, error) {
					return authorizationVerification{candidate: replacement}, nil
				})
				if loadErr != nil {
					t.Error(loadErr)
					return
				}
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = io.WriteString(w, `{"type":"urn:ietf:params:ehbp:error:key-config"}`)
				return
			}
			encap, err := hex.DecodeString(r.Header.Get("Ehbp-Encapsulated-Key"))
			if err != nil {
				t.Error(err)
				return
			}
			decryptAuthorizedTestRequest(t, newKey, encap, io.LimitReader(r.Body, 1<<20))
			encrypted, nonce := encryptAuthorizedTestResponse(t, newKey, encap, [][]byte{[]byte("data: {\"id\":\"test\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello\"},\"finish_reason\":null}]}\n\ndata: [DONE]\n\n")})
			w.Header().Set("Ehbp-Response-Nonce", nonce)
			_, _ = w.Write(encrypted)
		}))
		defer upstream.Close()
		route, err := provider.NewResolvedRoute(upstream.URL, tinfoil.RouterRepo)
		if err != nil {
			t.Fatal(err)
		}
		key, err = route.AuthorizationKey("tinfoil_v3_cloud", "model")
		if err != nil {
			t.Fatal(err)
		}
		report := &attestation.VerificationReport{Provider: key.ProviderName(), Model: key.Model(), TLSAuthority: route.Authority(), TLSKeyFP: fp, Factors: []attestation.FactorResult{{Name: attestation.FactorTEEReportData, Status: attestation.Pass}, {Name: attestation.FactorE2EEUsable, Status: attestation.Skip}}}
		candidate, err := newAuthorization(key, report, hex.EncodeToString(oldKey.PublicKey().Bytes()), true, false, time.Time{}, false, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		replacement, err = newAuthorization(key, report, hex.EncodeToString(newKey.PublicKey().Bytes()), true, false, time.Time{}, false, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		replacement.report.Metadata = map[string]string{"generation": "replacement"}
		old = loadTestAuthorization(t, server.authorizations, key, candidate)
		prov := &provider.Provider{Name: key.ProviderName(), BaseURL: upstream.URL, StaticRoute: route, UsesTLSBinding: true, E2EE: true, Encryptor: tinfoil.NewE2EE(), Preparer: tinfoil.NewPreparer("test")}
		used, err := server.inferAuthorized(context.Background(), newInferenceRecorder(), &authorizedRequest{provider: prov, route: route, key: key, body: []byte(`{"model":"model"}`), path: "/v1/chat/completions", contentType: "application/json", endpoint: e2ee.EndpointChat})
		if err != nil {
			t.Fatal(err)
		}
		if requests.Load() != 2 || used.report.Metadata["generation"] != "replacement" {
			t.Fatal("retry did not use replacement authorization")
		}
		current, ok := server.authorizations.acquire(key)
		if !ok || current.generation == old.generation {
			t.Fatal("rejection erased replacement generation")
		}
	})
}

func TestAuthorizedReportLookup(t *testing.T) {
	server := newTLSBindingTestServerHandle()
	server.authorizations = newAuthorizationStore(10, 2, time.Second)
	defer server.Close()
	key, value := testAuthorizationCandidate(t, "model", time.Time{}, false)
	route, err := provider.NewResolvedRoute("https://a.near.ai", "")
	if err != nil {
		t.Fatal(err)
	}
	server.providers = map[string]*provider.Provider{"neardirect": {Name: "neardirect", UsesTLSBinding: true, StaticRoute: route}}
	loadTestAuthorization(t, server.authorizations, key, value)
	req := httptest.NewRequest(http.MethodGet, "https://proxy.test/report?provider=neardirect&model=model", http.NoBody)
	rec := newInferenceRecorder()
	server.handleReport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("report status=%d", rec.Code)
	}
	// A sticky inference request may have selected a different authority from
	// today's default route. Explicit lookup must use the cached scope directly.
	server.providers["neardirect"].ResolveRoute = func(context.Context, string) (provider.ResolvedRoute, error) {
		t.Error("explicit report lookup performed discovery")
		return provider.ResolvedRoute{}, errors.New("discovery unavailable")
	}
	for _, tc := range []struct {
		query  string
		status int
	}{
		{"provider=neardirect&model=model&authority=a.near.ai", http.StatusOK},
		{"provider=neardirect&model=model&authority=other.near.ai", http.StatusNotFound},
		{"provider=neardirect&model=other&authority=a.near.ai", http.StatusNotFound},
		{"provider=neardirect&model=model&authority=", http.StatusBadRequest},
		{"provider=neardirect&model=model&authority=a.near.ai/path", http.StatusBadRequest},
		{"provider=neardirect&model=model&authority=user@a.near.ai", http.StatusBadRequest},
		{"provider=neardirect&model=model&authority=a.near.ai&authority=b.near.ai", http.StatusBadRequest},
		{"provider=neardirect&model=model&authority=%ZZ", http.StatusBadRequest},
	} {
		rec := newInferenceRecorder()
		server.handleReport(rec, httptest.NewRequest(http.MethodGet, "https://proxy.test/report?"+tc.query, http.NoBody))
		if rec.Code != tc.status {
			t.Fatalf("query=%q status=%d want=%d", tc.query, rec.Code, tc.status)
		}
	}
	server.providers["neardirect"].ResolveRoute = nil

	server.authorizations.invalidate(key)
	rec = newInferenceRecorder()
	server.handleReport(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("invalidated report status=%d", rec.Code)
	}
}
