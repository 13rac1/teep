package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/aci"
	"github.com/13rac1/teep/internal/provider/chutes"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/provider/tinfoil"
	"github.com/13rac1/teep/internal/provider/venice"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// newCoverageServer returns an offline server with one provider, E2EE on.
func newCoverageServer(t *testing.T, name string) *Server {
	t.Helper()
	s, err := New(&config.Config{Offline: true, Providers: map[string]*config.Provider{
		name: {Name: name, BaseURL: "https://example.com", APIKey: "test-key", E2EE: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// uncoveredRequest builds a request for path: multipart for the file
// endpoints, JSON for the others.
func uncoveredRequest(path, model string) *http.Request {
	var body io.Reader = strings.NewReader(`{"model":"` + model + `","input":"hello"}`)
	contentType := "application/json"
	if path == "/v1/images/edits" || path == "/v1/audio/transcriptions" {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		_ = mw.WriteField("model", model)
		fw, _ := mw.CreateFormFile("file", "in.bin")
		_, _ = fw.Write([]byte("data"))
		_ = mw.Close()
		body, contentType = &buf, mw.FormDataContentType()
	}
	req := httptest.NewRequest(http.MethodPost, path, body)
	req.Header.Set("Content-Type", contentType)
	return req
}

// With E2EE enabled, an endpoint outside the provider's E2EE coverage is
// refused with 403, an e2ee_not_covered body that names the provider, the
// endpoint and the setting, and a counted refusal; no request is sent.
func TestUncoveredEndpointRefused(t *testing.T) {
	near := []string{"/v1/privacy/classify", "/v1/privacy/redact", "/v1/responses", "/v1/images/edits", "/v1/audio/transcriptions"}
	tests := []struct {
		provider string
		paths    []string
	}{
		{"neardirect", near},
		{"nearcloud", near},
		{"phalacloud", []string{"/v1/embeddings"}},
		{"tinfoil_v3_cloud", []string{"/v1/audio/transcriptions"}},
	}
	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			s := newCoverageServer(t, tt.provider)
			for i, path := range tt.paths {
				t.Run(strings.TrimPrefix(path, "/v1/"), func(t *testing.T) {
					rec := httptest.NewRecorder()
					s.mux.ServeHTTP(rec, uncoveredRequest(path, tt.provider+":m"))
					if rec.Code != http.StatusForbidden {
						t.Fatalf("status %d, want 403; body %s", rec.Code, rec.Body.String())
					}
					var out notCoveredError
					if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
						t.Fatalf("body %s: %v", rec.Body.String(), err)
					}
					e := out.Error
					if e.Type != "e2ee_not_covered" || e.Provider != tt.provider || e.Endpoint != path ||
						e.Message != notCoveredMessage(s.providers[tt.provider], path) {
						t.Errorf("error = %+v", e)
					}
					if got := s.stats.notCovered.get(tt.provider); got != int64(i+1) {
						t.Errorf("refused count = %d, want %d", got, i+1)
					}
				})
			}
		})
	}
}

// The message names the setting, and states attested TLS only for a
// provider that uses TLS binding.
func TestNotCoveredMessage(t *testing.T) {
	bound := notCoveredMessage(&provider.Provider{Name: "p", UsesTLSBinding: true}, "/v1/x")
	unbound := notCoveredMessage(&provider.Provider{Name: "p"}, "/v1/x")
	for _, m := range []string{bound, unbound} {
		if !strings.Contains(m, "set e2ee = false for the provider") || !strings.Contains(m, "e2ee_usable") ||
			!strings.Contains(m, "provider p") || !strings.Contains(m, "/v1/x") {
			t.Errorf("message %q lacks the setting, the provider or the endpoint", m)
		}
	}
	if !strings.Contains(bound, "attested TLS connection") {
		t.Errorf("TLS-binding message %q does not state attested TLS", bound)
	}
	if strings.Contains(unbound, "attested TLS") || !strings.Contains(unbound, "attestation does not bind") {
		t.Errorf("message without TLS binding %q claims attested TLS", unbound)
	}
}

// With e2ee = false a new route is a plain route: the body is sent as it
// is over the attested TLS connection, and the answer is relayed.
func TestUncoveredEndpointWithoutE2EE(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		const body = `{"model":"model","input":"hello"}`
		upstream, fp := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if string(got) != body || r.URL.Path != "/v1/privacy/classify" {
				t.Errorf("upstream got %s at %s", got, r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"data":[]}`)
		}))
		server, input, _ := nearCompletionAuthorization(t, "neardirect", upstream.URL, fp)
		prov := *input.provider
		prov.E2EE = false
		request := *input
		request.provider = &prov
		request.body = []byte(body)
		request.path = "/v1/privacy/classify"
		request.endpoint = e2ee.EndpointPrivacy
		rec := newInferenceRecorder()
		out, err := server.inferAuthorized(t.Context(), rec, &request)
		if err != nil || out.status != "ok" || rec.Body.String() != `{"data":[]}` {
			t.Fatalf("status %q err %v body %s", out.status, err, rec.Body.String())
		}
	})
}

// The coverage split follows each encryptor's declaration, a covered
// endpoint is not refused, and with E2EE on a provider without an
// encryptor covers nothing.
func TestE2EECoverage(t *testing.T) {
	tests := []struct {
		provider   string
		covered    []string
		notCovered []string
	}{
		{"neardirect", []string{"/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/v1/images/generations", "/v1/rerank", "/v1/score"},
			[]string{"/v1/responses", "/v1/images/edits", "/v1/audio/transcriptions", "/v1/privacy/classify", "/v1/privacy/redact"}},
		{"nearcloud", []string{"/v1/chat/completions", "/v1/embeddings", "/v1/images/generations", "/v1/rerank", "/v1/score"},
			[]string{"/v1/responses", "/v1/images/edits", "/v1/audio/transcriptions", "/v1/privacy/classify", "/v1/privacy/redact"}},
		{"tinfoil_v3_cloud", []string{"/v1/chat/completions", "/v1/responses", "/v1/embeddings", "/v1/audio/speech"},
			[]string{"/v1/audio/transcriptions"}},
		{"phalacloud", []string{"/v1/chat/completions"}, []string{"/v1/embeddings"}},
		{"chutes", []string{"/v1/chat/completions", "/v1/embeddings"}, nil},
		{"venice", []string{"/api/v1/chat/completions"}, nil},
		{"nanogpt", []string{"/v1/chat/completions"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			s := newCoverageServer(t, tt.provider)
			prov := s.providers[tt.provider]
			covered, notCovered := e2eeCoverage(prov)
			if !slices.Equal(covered, tt.covered) || !slices.Equal(notCovered, tt.notCovered) {
				t.Errorf("coverage = %v / %v, want %v / %v", covered, notCovered, tt.covered, tt.notCovered)
			}
			data := s.buildDashboardData()
			if p := data.Providers[tt.provider]; !slices.Equal(p.E2EECovers, tt.covered) || !slices.Equal(p.E2EEDoesNotCover, tt.notCovered) {
				t.Errorf("dashboard provider = %+v", p)
			}
			off := *prov
			off.E2EE = false
			if c, n := e2eeCoverage(&off); c != nil || n != nil {
				t.Errorf("E2EE off: coverage = %v / %v, want none", c, n)
			}
			for _, ep := range routedEndpoints() {
				if !endpointCovered(&off, ep) {
					t.Errorf("E2EE off: %s refused", ep.name)
				}
			}
			none := *prov
			none.Encryptor = nil
			c, n := e2eeCoverage(&none)
			if c != nil || len(n) != len(tt.covered)+len(tt.notCovered) {
				t.Errorf("no encryptor: coverage = %v / %v, want every endpoint not covered", c, n)
			}
		})
	}
}

// Concurrent refusals of several providers are all counted.
func TestNotCoveredStatsConcurrent(t *testing.T) {
	var st notCoveredStats
	names := []string{"a", "b", "c"}
	const perName = 200
	var wg sync.WaitGroup
	for _, name := range names {
		for range perName {
			wg.Go(func() {
				st.add(name)
				_ = st.get(name)
			})
		}
	}
	wg.Wait()
	for _, name := range names {
		if got := st.get(name); got != perName {
			t.Errorf("%s: count = %d, want %d", name, got, perName)
		}
	}
}

// Each production encryptor refuses, before it reads the key or the body,
// every endpoint outside its declared coverage, so the declaration and the
// encryption cannot disagree.
func TestEncryptorsRefuseUncoveredEndpoints(t *testing.T) {
	encryptors := map[string]provider.RequestEncryptor{
		"aci":        aci.NewE2EE(),
		"chutes":     chutes.NewE2EE(),
		"neardirect": neardirect.NewE2EE(),
		"tinfoil":    tinfoil.NewE2EE(),
		"venice":     venice.NewE2EE(),
	}
	endpoints := []e2ee.EndpointType{
		e2ee.EndpointChat, e2ee.EndpointEmbeddings, e2ee.EndpointImages, e2ee.EndpointRerank,
		e2ee.EndpointScore, e2ee.EndpointAudio, e2ee.EndpointResponses, e2ee.EndpointSpeech,
		e2ee.EndpointCompletions, e2ee.EndpointPrivacy, e2ee.EndpointImagesEdits,
	}
	for name, enc := range encryptors {
		t.Run(name, func(t *testing.T) {
			for _, ep := range endpoints {
				_, err := enc.EncryptRequest([]byte(`{}`), &attestation.RawAttestation{}, ep)
				notCovered := errors.Is(err, e2ee.ErrEndpointNotCovered)
				if enc.CoversE2EE(ep) == notCovered {
					t.Errorf("%s: CoversE2EE = %v, EncryptRequest error = %v", ep, enc.CoversE2EE(ep), err)
				}
			}
		})
	}
}
