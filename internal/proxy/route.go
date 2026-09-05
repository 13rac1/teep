package proxy

import (
	"context"
	"fmt"

	"github.com/13rac1/teep/internal/provider"
)

// resolveRequestRoute supplies the same route and key to all authorization
// consumers. Dynamic resolution is performed once by the request entry point.
func resolveRequestRoute(ctx context.Context, prov *provider.Provider, model string) (provider.ResolvedRoute, provider.AuthorizationKey, error) {
	route := prov.StaticRoute
	if prov.ResolveRoute != nil {
		var err error
		route, err = prov.ResolveRoute(ctx, model)
		if err != nil {
			return provider.ResolvedRoute{}, provider.AuthorizationKey{}, fmt.Errorf("resolve request route: %w", err)
		}
	}
	key, err := route.AuthorizationKey(prov.Name, model)
	return route, key, err
}
