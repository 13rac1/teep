package proxy

import (
	"context"
	"crypto/sha256"
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
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestAuthorizedExploreWithoutE2EE(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"hello"}}]}`))
		}))
		server := newTLSBindingTestServerHandle()
		server.authorizations = newAuthorizationStore(10, 2, time.Second)
		defer server.Close()
		route, err := provider.NewResolvedRoute(upstream.URL, "")
		if err != nil {
			t.Fatal(err)
		}
		prov := &provider.Provider{Name: "neardirect", UsesTLSBinding: true, StaticRoute: route, ChatPath: "/v1/chat/completions", E2EE: false}
		server.providers = map[string]*provider.Provider{prov.Name: prov}
		key, err := route.AuthorizationKey(prov.Name, "model")
		if err != nil {
			t.Fatal(err)
		}
		fp := sha256.Sum256(upstream.Certificate().RawSubjectPublicKeyInfo)
		report := &attestation.VerificationReport{Provider: prov.Name, Model: "model", TLSAuthority: route.Authority(), TLSKeyFP: hex.EncodeToString(fp[:]), Factors: []attestation.FactorResult{{Name: attestation.FactorTEEReportData, Status: attestation.Pass}}}
		value, err := newAuthorization(key, report, "", false, false, time.Time{}, false, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		loadTestAuthorization(t, server.authorizations, key, value)
		result := server.loopbackInfer(t.Context(), "neardirect:model", []byte(`{"model":"neardirect:model","messages":[{"role":"user","content":"hello"}]}`))
		if result.Error != "" {
			t.Fatal(result.Error)
		}
		if result.E2EE {
			t.Fatal("Explore reported E2EE for an inference request with E2EE disabled")
		}
		prov.ChatPath = ""
		rejected := server.loopbackInfer(t.Context(), "neardirect:model", []byte(`{"model":"neardirect:model"}`))
		if rejected.Error == "" || server.stats.requests.Load() != 1 {
			t.Fatal("Explore bypassed the endpoint guard or miscounted a rejected request")
		}
	})
}

func TestAuthorizedExploreConcurrentAccounting(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		const requestCount = 12
		arrived := make(chan struct{}, requestCount)
		release := make(chan struct{})
		var releaseOnce sync.Once
		defer releaseOnce.Do(func() { close(release) })
		upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Model string `json:"model"`
			}
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			if _, _, err := jsonstrict.Unmarshal(data, &body); err != nil {
				t.Error(err)
				return
			}
			if strings.Contains(body.Model, ":") {
				t.Error("upstream model was not normalized")
			}
			arrived <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"hello"}}]}`))
		}))
		server := newTLSBindingTestServerHandle()
		server.authorizations = newAuthorizationStore(32, 4, time.Second)
		defer server.Close()
		server.providers = make(map[string]*provider.Provider)
		fp := sha256.Sum256(upstream.Certificate().RawSubjectPublicKeyInfo)
		var resolutions atomic.Int32
		models := make([]string, 0, 6)
		for _, name := range []string{"neardirect", "nearcloud", "tinfoil_v3_cloud"} {
			for _, model := range []string{"first", "second"} {
				input := tlsAuthorizationInput(t, server, name, model, upstream.URL, hex.EncodeToString(fp[:]))
				prov := input.provider
				prov.ChatPath = "/v1/chat/completions"
				prov.ResolveRoute = func(context.Context, string) (provider.ResolvedRoute, error) {
					resolutions.Add(1)
					return input.route, nil
				}
				server.providers[name] = prov
				models = append(models, name+":"+model)
			}
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		var wg sync.WaitGroup
		for _, model := range models {
			for range 2 {
				wg.Go(func() {
					result := server.loopbackInfer(ctx, model, []byte(fmt.Sprintf(`{"model":%q}`, model)))
					if result.Error != "" {
						t.Error(result.Error)
						return
					}
					name, upstreamModel, _ := strings.Cut(model, ":")
					if result.Report == nil || result.Report.Provider != name || result.Report.Model != upstreamModel {
						t.Errorf("Explore returned another request's report for %s", model)
					}
				})
			}
		}
		for range requestCount {
			select {
			case <-arrived:
			case <-ctx.Done():
				t.Fatal("concurrent requests did not reach upstream")
			}
		}
		if got := server.stats.activeNonStream.Load(); got != requestCount {
			t.Errorf("active requests=%d", got)
		}
		releaseOnce.Do(func() { close(release) })
		wg.Wait()
		if server.stats.requests.Load() != requestCount || server.stats.nonStream.Load() != requestCount || server.stats.plaintext.Load() != requestCount {
			t.Fatal("Explore request totals disagree")
		}
		if server.stats.activeNonStream.Load() != 0 || server.stats.lastRequestAt.Load() == 0 || server.stats.errors.Load() != 0 {
			t.Fatal("Explore completion accounting is incorrect")
		}
		if resolutions.Load() != requestCount {
			t.Fatalf("resolved %d times for %d requests", resolutions.Load(), requestCount)
		}
		for _, model := range models {
			name, upstreamModel, _ := strings.Cut(model, ":")
			route := server.providers[name].StaticRoute
			ms := server.stats.getModelStats(name, upstreamModel+"@"+route.Authority())
			if ms.requests.Load() != 2 || ms.lastRequestAt.Load() == 0 {
				t.Errorf("incorrect model accounting for %s", model)
			}
		}
	})
}
