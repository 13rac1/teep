package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestAuthorizedNearCompletionRetainsAuthorization(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, name := range []string{"nearcloud", "neardirect"} {
			for _, kind := range []string{"missing_done", "provider_error", "extra_data"} {
				t.Run(name+"/"+kind, func(t *testing.T) {
					var requests atomic.Int32
					var complete atomic.Bool
					upstream, fp := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						requests.Add(1)
						_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
						public, err := hex.DecodeString(r.Header.Get("X-Client-Pub-Key"))
						if err != nil {
							t.Error(err)
							return
						}
						recipient, err := e2ee.Ed25519PubToX25519(public)
						if err != nil {
							t.Error(err)
							return
						}
						encrypted, err := e2ee.EncryptXChaCha20([]byte("answer"), recipient)
						if err != nil {
							t.Error(err)
							return
						}
						suffix := "data: [DONE]\n\n"
						if !complete.Load() {
							switch kind {
							case "missing_done":
								suffix = ""
							case "provider_error":
								suffix = "data: {\"error\":{\"message\":\"generation failed\"}}\n\n" + suffix
							case "extra_data":
								suffix += "data: {}\n\n"
							}
						}
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q}}]}\n\n%s", encrypted, suffix)
					}))
					server, input, first := nearCompletionAuthorization(t, name, upstream.URL, fp)
					for _, success := range []bool{false, true} {
						complete.Store(success)
						var wg sync.WaitGroup
						for _, stream := range []bool{false, true} {
							wg.Go(func() {
								request := *input
								request.stream = stream
								rec := newInferenceRecorder()
								out, err := server.inferAuthorized(t.Context(), rec, &request)
								if (err == nil) != success {
									t.Errorf("success=%v error=%v", success, err)
								}
								if errors.Is(err, e2ee.ErrDecryptionFailed) {
									t.Error("protocol error classified as authentication failure")
								}
								if !success && (out.status == "ok" || strings.Contains(rec.Body.String(), "data: [DONE]")) {
									t.Error("failed response reported success")
								}
							})
						}
						wg.Wait()
						current, ok := server.authorizations.acquire(input.key)
						if !ok || current.generation != first.generation {
							t.Fatal("response error changed authorization generation")
						}
						for _, factor := range current.report.Factors {
							if factor.Name == attestation.FactorE2EEUsable && (factor.Status == attestation.Pass) != success {
								t.Fatal("E2EE promotion does not reflect response completion")
							}
						}
					}
					if requests.Load() != 4 {
						t.Fatalf("requests=%d want=4; responses must not trigger replay", requests.Load())
					}
				})
			}
		}
	})
}

func nearCompletionAuthorization(t *testing.T, name, origin, fp string) (*Server, *authorizedRequest, *authorization) {
	t.Helper()
	server := newTLSBindingTestServerHandle()
	server.authorizations = newAuthorizationStore(10, 2, time.Second)
	t.Cleanup(server.Close)
	route, err := provider.NewResolvedRoute(origin, "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := route.AuthorizationKey(name, "model")
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	prov := &provider.Provider{Name: name, BaseURL: origin, StaticRoute: route, UsesTLSBinding: true, E2EE: true, Encryptor: neardirect.NewE2EE(), Preparer: neardirect.NewPreparer("test"), Attester: &mockAttester{err: errors.New("unexpected re-attestation")}}
	// This negative test isolates response failure policy with an authenticated
	// key. Fixture and live integration suites validate complete evidence.
	report := &attestation.VerificationReport{Provider: name, Model: key.Model(), TLSAuthority: route.Authority(), TLSKeyFP: fp, Factors: []attestation.FactorResult{{Name: attestation.FactorTEEReportData, Status: attestation.Pass}, {Name: attestation.FactorE2EEUsable, Status: attestation.Skip}}}
	candidate, err := newAuthorization(key, report, hex.EncodeToString(public), true, false, time.Time{}, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	value := loadTestAuthorization(t, server.authorizations, key, candidate)
	input := &authorizedRequest{provider: prov, route: route, key: key, body: []byte(`{"model":"model","messages":[{"role":"user","content":"test"}]}`), path: "/v1/chat/completions", contentType: "application/json", endpoint: e2ee.EndpointChat}
	return server, input, value
}
