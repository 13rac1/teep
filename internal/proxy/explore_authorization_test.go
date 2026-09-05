package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
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
