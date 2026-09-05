package proxy

import (
	"context"
	"testing"

	"github.com/13rac1/teep/internal/provider"
)

func TestResolveRequestRouteUsesOneSnapshot(t *testing.T) {
	route, err := provider.NewResolvedRoute("https://a.near.ai", "repo")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	prov := &provider.Provider{Name: "neardirect", ResolveRoute: func(context.Context, string) (provider.ResolvedRoute, error) {
		calls++
		return route, nil
	}}
	got, key, err := resolveRequestRoute(context.Background(), prov, "model")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || got != route || key.Authority() != got.Authority() {
		t.Fatal("route and key did not use one snapshot")
	}
	prov.ResolveRoute = nil
	if _, _, err := resolveRequestRoute(context.Background(), prov, "model"); err == nil {
		t.Fatal("accepted missing static route")
	}
	prov.StaticRoute = route
	if _, _, err := resolveRequestRoute(context.Background(), prov, "model"); err != nil {
		t.Fatal(err)
	}
}
