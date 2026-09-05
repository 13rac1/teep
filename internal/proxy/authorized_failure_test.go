package proxy

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	"github.com/13rac1/teep/internal/provider/tinfoil"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func authorizedFailureFixture(t *testing.T, upstream *httptest.Server, private *ecdh.PrivateKey) (*Server, *authorizedRequest, *authorization) {
	t.Helper()
	server := newTLSBindingTestServerHandle()
	server.authorizations = newAuthorizationStore(10, 2, time.Second)
	t.Cleanup(server.Close)
	route, err := provider.NewResolvedRoute(upstream.URL, tinfoil.RouterRepo)
	if err != nil {
		t.Fatal(err)
	}
	prov := &provider.Provider{Name: "tinfoil_v3_cloud", BaseURL: upstream.URL, StaticRoute: route, UsesTLSBinding: true, E2EE: true, Encryptor: tinfoil.NewE2EE(), Preparer: tinfoil.NewPreparer("test")}
	key, err := route.AuthorizationKey(prov.Name, "model")
	if err != nil {
		t.Fatal(err)
	}
	fp := sha256.Sum256(upstream.Certificate().RawSubjectPublicKeyInfo)
	report := &attestation.VerificationReport{Provider: prov.Name, Model: key.Model(), TLSAuthority: route.Authority(), TLSKeyFP: hex.EncodeToString(fp[:]), Factors: []attestation.FactorResult{{Name: attestation.FactorTEEReportData, Status: attestation.Pass}, {Name: attestation.FactorE2EEUsable, Status: attestation.Skip}}}
	candidate, err := newAuthorization(key, report, hex.EncodeToString(private.PublicKey().Bytes()), true, false, time.Time{}, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	value := loadTestAuthorization(t, server.authorizations, key, candidate)
	input := &authorizedRequest{provider: prov, route: route, key: key, body: []byte(`{"model":"model","messages":[{"role":"user","content":"test"}]}`), path: "/v1/chat/completions", contentType: "application/json", endpoint: e2ee.EndpointChat}
	return server, input, value
}

type countedResponseBody struct {
	io.ReadCloser
	closes *atomic.Int32
}

func (b *countedResponseBody) Close() error { b.closes.Add(1); return b.ReadCloser.Close() }

type countResponseCloses struct {
	base   http.RoundTripper
	closes *atomic.Int32
}

func (c countResponseCloses) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.base.RoundTrip(r)
	if resp != nil {
		resp.Body = &countedResponseBody{resp.Body, c.closes}
	}
	return resp, err
}

func TestAuthorizedEncryptedErrors(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, tc := range []struct {
			name               string
			status             int
			corrupt, truncated bool
		}{
			{"valid_422", 422, false, false}, {"corrupt_422", 422, true, false},
			{"valid_500", 500, false, false}, {"corrupt_500", 500, true, false},
			{"truncated_200", 200, false, true}, {"valid_200", 200, false, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				private := authorizedTestKey(t)
				var requests, closes atomic.Int32
				upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					encap, err := hex.DecodeString(r.Header.Get("Ehbp-Encapsulated-Key"))
					if err != nil {
						t.Error(err)
						return
					}
					_ = decryptAuthorizedTestRequest(t, private, encap, io.LimitReader(r.Body, 1<<20))
					body, nonce := encryptAuthorizedTestResponse(t, private, encap, [][]byte{[]byte(`{"type":"urn:ietf:params:ehbp:error:key-config"}`)})
					if tc.corrupt {
						body[len(body)-1] ^= 1
					}
					if tc.truncated {
						body = body[:len(body)-1]
					}
					w.Header().Set("Ehbp-Response-Nonce", nonce)
					w.Header().Set("Content-Type", "application/problem+json")
					w.WriteHeader(tc.status)
					_, _ = w.Write(body)
				}))
				defer upstream.Close()
				server, input, value := authorizedFailureFixture(t, upstream, private)
				client, err := server.pinnedUpstreamClient(input.provider, input.route.BaseURL(), value.identity.Fingerprint())
				if err != nil {
					t.Fatal(err)
				}
				client.Transport = countResponseCloses{client.Transport, &closes}
				recorder := newInferenceRecorder()
				outcome := server.handleAuthorizedEndpoint(t.Context(), recorder, input)
				if requests.Load() != 1 || closes.Load() != 1 {
					t.Fatalf("requests=%d body closes=%d", requests.Load(), closes.Load())
				}
				_, retained := server.authorizations.acquire(input.key)
				if retained == tc.corrupt {
					t.Fatalf("authorization retained=%v, corrupt=%v", retained, tc.corrupt)
				}
				if !tc.corrupt && !tc.truncated && (recorder.Code != tc.status || !strings.Contains(recorder.Body.String(), "key-config")) {
					t.Fatal("authenticated response was not relayed")
				}
				if outcome.attestDur <= 0 || outcome.e2eeDur <= 0 || outcome.upstreamDur <= 0 {
					t.Fatalf("missing phase timing: %+v", outcome)
				}
				wantErrors := int64(1)
				wantStatus := "upstream_failed"
				if tc.status == 200 && !tc.truncated {
					wantErrors, wantStatus = 0, "ok"
				}
				ms := server.stats.getModelStats(input.key.ProviderName(), input.key.Model()+"@"+input.key.Authority())
				if outcome.status != wantStatus || ms.errors.Load() != wantErrors || server.stats.errors.Load() != wantErrors {
					t.Fatalf("status=%s model_errors=%d total_errors=%d", outcome.status, ms.errors.Load(), server.stats.errors.Load())
				}
			})
		}
	})
}

type cancelResponseWriter struct {
	*inferenceRecorder
	cancel context.CancelFunc
}

func (w cancelResponseWriter) Write(_ []byte) (int, error) {
	w.cancel()
	return 0, errors.New("downstream disconnected")
}

func TestAuthorizedCancellationRetainsSharedAuthorization(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		private := authorizedTestKey(t)
		var requests atomic.Int32
		upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := requests.Add(1)
			encap, err := hex.DecodeString(r.Header.Get("Ehbp-Encapsulated-Key"))
			if err != nil {
				t.Error(err)
				return
			}
			_ = decryptAuthorizedTestRequest(t, private, encap, io.LimitReader(r.Body, 1<<20))
			body, nonce := encryptAuthorizedTestResponse(t, private, encap, [][]byte{[]byte("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n")})
			w.Header().Set("Ehbp-Response-Nonce", nonce)
			_, _ = w.Write(body)
			if n == 1 {
				_ = http.NewResponseController(w).Flush()
				<-r.Context().Done()
			}
		}))
		defer upstream.Close()
		server, input, first := authorizedFailureFixture(t, upstream, private)
		input.stream = true
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		outcome := server.handleAuthorizedEndpoint(ctx, cancelResponseWriter{newInferenceRecorder(), cancel}, input)
		if outcome.status != "canceled" {
			t.Fatalf("status=%q", outcome.status)
		}
		value, ok := server.authorizations.acquire(input.key)
		if !ok || value.generation != first.generation {
			t.Fatal("cancellation invalidated shared authorization")
		}
		next := server.handleAuthorizedEndpoint(t.Context(), newInferenceRecorder(), input)
		if next.status != "ok" || requests.Load() != 2 {
			t.Fatal("another client could not use the existing authorization")
		}
	})
}

func TestAuthorizedConcurrentProviderModelMetrics(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		private := authorizedTestKey(t)
		upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			encap, err := hex.DecodeString(r.Header.Get("Ehbp-Encapsulated-Key"))
			if err != nil {
				t.Error(err)
				return
			}
			_ = decryptAuthorizedTestRequest(t, private, encap, io.LimitReader(r.Body, 1<<20))
			body, nonce := encryptAuthorizedTestResponse(t, private, encap, [][]byte{[]byte(`{"error":"busy"}`)})
			w.Header().Set("Ehbp-Response-Nonce", nonce)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write(body)
		}))
		defer upstream.Close()
		server, input, original := authorizedFailureFixture(t, upstream, private)
		server.providers = make(map[string]*provider.Provider)
		models := make([]string, 0, 4)
		for _, name := range []string{"tinfoil_v3_cloud", "tinfoil_v3_direct"} {
			prov := *input.provider
			prov.Name, prov.ChatPath = name, input.path
			server.providers[name] = &prov
			for _, model := range []string{"one", "two"} {
				key, err := input.route.AuthorizationKey(name, model)
				if err != nil {
					t.Fatal(err)
				}
				report := original.report.Clone()
				report.Provider, report.Model = name, model
				candidate, err := newAuthorization(key, report, original.signingKey, true, false, time.Time{}, false, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				loadTestAuthorization(t, server.authorizations, key, candidate)
				models = append(models, name+":"+model)
			}
		}
		var wg sync.WaitGroup
		for _, model := range models {
			for range 4 {
				wg.Go(func() {
					body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"test"}]}`, model)
					req := httptest.NewRequest(http.MethodPost, "https://proxy.example/v1/chat/completions", strings.NewReader(body))
					req.Header.Set("Content-Type", "application/json")
					rec := newInferenceRecorder()
					server.handleEndpoint(&chatEndpoint)(rec, req)
					if rec.Code != http.StatusServiceUnavailable {
						t.Errorf("HTTP status=%d", rec.Code)
					}
				})
			}
		}
		wg.Wait()
		for _, combined := range models {
			name, model, _ := strings.Cut(combined, ":")
			ms := server.stats.getModelStats(name, model+"@"+input.route.Authority())
			if ms.requests.Load() != 4 || ms.errors.Load() != 4 {
				t.Errorf("%s: requests=%d errors=%d", combined, ms.requests.Load(), ms.errors.Load())
			}
		}
		if server.stats.requests.Load() != 16 || server.stats.errors.Load() != 16 || server.stats.cacheHits.Load() != 16 {
			t.Fatal("aggregate request, error, or cache counts differ")
		}
	})
}
