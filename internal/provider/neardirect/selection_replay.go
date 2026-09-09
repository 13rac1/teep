package neardirect

import (
	"errors"

	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/nearroute"
)

// ValidateRecordedSelection validates routing metadata without network access or entropy.
// Evidence and transport identity must still pass the production verification path.
func ValidateRecordedSelection(model, origin string, selection Selection, endpoints, count []byte) (provider.ResolvedRoute, error) {
	if err := nearroute.ValidateModel(model); err != nil {
		return provider.ResolvedRoute{}, err
	}
	configured, err := nearroute.ParseOrigin(origin)
	if err != nil {
		return provider.ResolvedRoute{}, err
	}
	if configured.Static {
		if selection.Mode != "static" || selection.Canonical != "" || selection.Index != 0 || selection.Authority != configured.Authority {
			return provider.ResolvedRoute{}, errors.New("recorded static route does not match configured origin")
		}
		return provider.NewResolvedRoute("https://"+selection.Authority, "")
	}
	mapping, err := parseEndpointMapping(endpoints, true)
	if err != nil {
		return provider.ResolvedRoute{}, err
	}
	canonical, ok := mapping[model]
	if !ok || canonical != selection.Canonical || (configured.Canonical != "" && configured.Canonical != canonical) {
		return provider.ResolvedRoute{}, errors.New("recorded canonical route does not match discovery or configuration")
	}
	expectedMode := "discovered"
	if configured.Indexed {
		expectedMode = "explicit"
		if selection.Index != configured.Index || selection.Authority != configured.Authority {
			return provider.ResolvedRoute{}, errors.New("recorded explicit index does not match configuration")
		}
	} else {
		parsed, unknown, err := parseBackendCount(count, canonical)
		if err != nil {
			return provider.ResolvedRoute{}, err
		}
		if len(unknown) != 0 || selection.Index >= parsed.Healthy {
			return provider.ResolvedRoute{}, errors.New("recorded index is outside validated initial count")
		}
	}
	authority, err := nearroute.IndexedAuthority(canonical, selection.Index)
	if err != nil {
		return provider.ResolvedRoute{}, err
	}
	if selection.Mode != expectedMode || selection.Authority != authority {
		return provider.ResolvedRoute{}, errors.New("recorded route mode or authority is inconsistent")
	}
	return provider.NewResolvedRoute("https://"+authority, "")
}

// LookupSelection returns completed routing metadata for capture without starting work.
func (a *Attester) LookupSelection(model string) (Selection, bool) {
	if nearroute.ValidateModel(model) != nil {
		return Selection{}, false
	}
	origin := a.origin
	if origin.Static {
		return Selection{Authority: origin.Authority, Mode: "static"}, true
	}
	resolver, ok := a.resolver.(interface {
		LookupSelection(string) (Selection, bool)
	})
	if !ok {
		return Selection{}, false
	}
	return resolver.LookupSelection(model)
}
