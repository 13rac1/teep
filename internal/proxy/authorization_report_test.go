package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
)

func TestReportLookupDoesNotObserveModels(t *testing.T) {
	server := newTLSBindingTestServerHandle()
	server.authorizations = newAuthorizationStore(2, 2, time.Second)
	defer server.Close()
	route, err := provider.NewResolvedRoute("https://router.example", "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := route.AuthorizationKey("tinfoil_v3_cloud", "used")
	if err != nil {
		t.Fatal(err)
	}
	_, candidate := testAuthorizationCandidate(t, "used")
	candidate.key = key
	candidate.report.Provider = key.ProviderName()
	value := loadTestAuthorization(t, server.authorizations, key, candidate)
	server.authorizations.promote(key, value.generation, "successful inference")
	server.providers = make(map[string]*provider.Provider)
	server.providers[key.ProviderName()] = &provider.Provider{Name: key.ProviderName(), UsesTLSBinding: true, StaticRoute: route}
	before := server.authorizations.entries[key.EvidenceScope()].lastUsed
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			request := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://proxy.example/v1/tee/report?provider=tinfoil_v3_cloud&model=query-%d&authority=router.example", i), http.NoBody)
			recorder := httptest.NewRecorder()
			server.handleReport(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Errorf("status=%d", recorder.Code)
			}
		})
	}
	wg.Wait()
	record := server.authorizations.entries[key.EvidenceScope()]
	if !record.lastUsed.Equal(before) {
		t.Fatal("report lookup updated authorization recency")
	}
	if len(record.models) != 1 || record.models[key] != "successful inference" {
		t.Fatal("report lookup changed observed models")
	}
	report, ok := server.authorizations.reportSnapshot(key)
	if !ok {
		t.Fatal("missing report")
	}
	report.Factors = []attestation.FactorResult{{Name: attestation.FactorE2EEUsable, Status: attestation.Fail}}
	again, _ := server.authorizations.reportSnapshot(key)
	if again.Blocked() {
		t.Fatal("report snapshot mutated cached authorization")
	}
}
