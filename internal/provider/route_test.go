package provider_test

import (
	"context"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
)

func TestResolvedRouteIdentity(t *testing.T) {
	a, err := provider.NewResolvedRoute("https://EXAMPLE.com.:443", "repo/a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := provider.NewResolvedRoute("https://example.com", "repo/b")
	if err != nil {
		t.Fatal(err)
	}
	ka, err := a.AuthorizationKey("provider", "model")
	if err != nil {
		t.Fatal(err)
	}
	kb, err := b.AuthorizationKey("provider", "model")
	if err != nil {
		t.Fatal(err)
	}
	if a.BaseURL() != "https://example.com" || a.Authority() != ka.Authority() || ka != kb {
		t.Fatal("authority normalization or repository-independent cache identity failed")
	}
	if a.SupplyChainRepo() != "repo/a" || b.SupplyChainRepo() != "repo/b" {
		t.Fatal("repository snapshot changed")
	}
	kc, err := a.AuthorizationKey("provider:model", "x")
	if err != nil {
		t.Fatal(err)
	}
	kd, err := a.AuthorizationKey("provider", "model:x")
	if err != nil {
		t.Fatal(err)
	}
	if kc.SingleflightKey() == kd.SingleflightKey() {
		t.Fatal("ambiguous key serialization")
	}
	if _, err := (provider.ResolvedRoute{}).AuthorizationKey("p", "m"); err == nil {
		t.Fatal("accepted missing route")
	}
}

type routeRecorder struct{ route provider.ResolvedRoute }

func (r *routeRecorder) FetchAttestationForRoute(_ context.Context, route provider.ResolvedRoute, _ string, _ attestation.Nonce) (*attestation.RawAttestation, error) {
	r.route = route
	return &attestation.RawAttestation{TransportTLSAuthority: route.Authority()}, nil
}

func TestAttesterRouteSnapshot(t *testing.T) {
	route, err := provider.NewResolvedRoute("https://example.com", "repo")
	if err != nil {
		t.Fatal(err)
	}
	recorder := &routeRecorder{}
	adapter, err := provider.AttesterForRoute(recorder, route)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.FetchAttestation(context.Background(), "model", attestation.NewNonce()); err != nil {
		t.Fatal(err)
	}
	if recorder.route != route {
		t.Fatal("attester received another route snapshot")
	}
	if _, err := provider.AttesterForRoute(recorder, provider.ResolvedRoute{}); err == nil {
		t.Fatal("adapter accepted missing route")
	}
}
