package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct"
)

type capacityAttester struct {
	calls     atomic.Int32
	exhausted atomic.Bool
}

func (a *capacityAttester) FetchAttestation(context.Context, string, attestation.Nonce) (*attestation.RawAttestation, error) {
	a.calls.Add(1)
	if a.exhausted.Load() {
		return nil, tlsct.ErrConnectionCapacity
	}
	return nil, errors.New("test attestation unavailable")
}

func TestAuthorizationAttestationCapacityRecovery(t *testing.T) {
	s, err := New(&config.Config{Offline: true, Providers: map[string]*config.Provider{"neardirect": {Name: "neardirect", BaseURL: "https://test.near.ai"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	route, err := provider.NewResolvedRoute("https://test.near.ai", "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := route.AuthorizationKey("neardirect", "test")
	if err != nil {
		t.Fatal(err)
	}
	attester := &capacityAttester{}
	attester.exhausted.Store(true)
	prov := s.providers["neardirect"]
	prov.ResolveRoute, prov.StaticRoute, prov.Attester = nil, route, attester
	input := &authorizedRequest{provider: prov, route: route, key: key}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			rec := newInferenceRecorder()
			s.handleAuthorizedEndpoint(t.Context(), rec, input)
			if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "1" {
				t.Errorf("capacity status=%d backoff=%q", rec.Code, rec.Header().Get("Retry-After"))
			}
		})
	}
	wg.Wait()
	if _, blocked := s.negCache.ActiveInfo(key.ProviderName(), key.SingleflightKey()); blocked {
		t.Fatal("capacity exhaustion entered negative cache")
	}
	before := attester.calls.Load()
	attester.exhausted.Store(false)
	_, _, err = s.loadAuthorization(t.Context(), prov, route, key)
	if err == nil || attester.calls.Load() != before+1 {
		t.Fatal("restored capacity did not permit new attestation")
	}
	if _, blocked := s.negCache.ActiveInfo(key.ProviderName(), key.SingleflightKey()); !blocked {
		t.Fatal("ordinary attestation failure did not enter negative cache")
	}
}

func TestAuthorizationCollateralCapacityRecovery(t *testing.T) {
	s := newMinimalServer()
	s.authorizations = newAuthorizationStore(10, 2, time.Second)
	defer s.Close()
	// Isolate certificate-chain enforcement. This tests resource failure policy,
	// not the cryptographic validity of the injected SEV verification result.
	for _, name := range attestation.KnownFactors {
		if name != attestation.FactorTEECertChain {
			s.cfg.AllowFail = append(s.cfg.AllowFail, name)
		}
	}
	var exhausted atomic.Bool
	exhausted.Store(true)
	var calls atomic.Int32
	s.sevVerifier = func(context.Context, []byte) *attestation.SEVVerifyResult {
		calls.Add(1)
		if exhausted.Load() {
			return &attestation.SEVVerifyResult{CertChainErr: fmt.Errorf("fetch certificate: %w", tlsct.ErrConnectionCapacity)}
		}
		return &attestation.SEVVerifyResult{CertChainErr: errors.New("invalid certificate")}
	}
	route, err := provider.NewResolvedRoute("https://test.near.ai", "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := route.AuthorizationKey("neardirect", "test")
	if err != nil {
		t.Fatal(err)
	}
	prov := &provider.Provider{Name: "neardirect", StaticRoute: route, UsesTLSBinding: true,
		SupplyChainPolicy: attestation.NoSupplyChainPolicy(),
		Attester:          &mockAttesterWithRaw{raw: &attestation.RawAttestation{SEVReportBytes: []byte("injected verifier input")}}}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			rec := newInferenceRecorder()
			s.handleAuthorizedEndpoint(t.Context(), rec, &authorizedRequest{provider: prov, route: route, key: key})
			if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "1" {
				t.Errorf("collateral capacity status=%d backoff=%q", rec.Code, rec.Header().Get("Retry-After"))
			}
		})
	}
	wg.Wait()
	if _, blocked := s.negCache.ActiveInfo(key.ProviderName(), key.SingleflightKey()); blocked {
		t.Fatal("collateral capacity exhaustion entered negative cache")
	}
	before := calls.Load()
	exhausted.Store(false)
	_, blocked, err := s.loadAuthorization(t.Context(), prov, route, key)
	if err != nil || blocked == nil || calls.Load() != before+1 {
		t.Fatalf("restored capacity did not evaluate evidence: blocked=%v err=%v calls=%d", blocked != nil, err, calls.Load()-before)
	}
	if _, active := s.negCache.ActiveInfo(key.ProviderName(), key.SingleflightKey()); !active {
		t.Fatal("invalid certificate did not enter negative cache")
	}
}

func TestAllowedCollateralCapacityFailure(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(fmt.Sprintf("force=%v", force), func(t *testing.T) {
			s := newMinimalServer()
			defer s.Close()
			s.cfg.Force = force
			if !force {
				s.cfg.AllowFail = append([]string(nil), attestation.KnownFactors...)
			}
			s.sevVerifier = func(context.Context, []byte) *attestation.SEVVerifyResult {
				return &attestation.SEVVerifyResult{CertChainErr: tlsct.ErrConnectionCapacity}
			}
			prov := &provider.Provider{Name: "neardirect", SupplyChainPolicy: attestation.NoSupplyChainPolicy(),
				Attester: &mockAttesterWithRaw{raw: &attestation.RawAttestation{SEVReportBytes: []byte("injected verifier input")}}}
			report, _, err := s.fetchVerified(t.Context(), prov, "test", func(_ string, err error) {
				t.Errorf("allowed failure triggered failure callback: %v", err)
			})
			if err != nil || report == nil {
				t.Fatalf("explicit enforcement policy was ignored: %v", err)
			}
		})
	}
}
