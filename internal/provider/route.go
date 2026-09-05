package provider

import (
	"context"
	"errors"
	"net/url"
	"strconv"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/tlsct"
)

// ResolvedRoute is one immutable discovery snapshot. The repository is a
// verification input; it is not part of the authorization cache identity.
type ResolvedRoute struct {
	authority  string
	repository string
}

// NewResolvedRoute validates and normalizes an origin-only HTTPS URL.
func NewResolvedRoute(origin, repository string) (ResolvedRoute, error) {
	authority, err := tlsct.HTTPSOriginAuthority(origin)
	if err != nil {
		return ResolvedRoute{}, err
	}
	return ResolvedRoute{authority: authority, repository: repository}, nil
}

// Authority returns the canonical HTTPS authority.
func (r ResolvedRoute) Authority() string { return r.authority }

// BaseURL returns the canonical origin without exposing a mutable URL.
func (r ResolvedRoute) BaseURL() string {
	return (&url.URL{Scheme: "https", Host: r.authority}).String()
}

// SupplyChainRepo returns the repository selected from this discovery snapshot.
func (r ResolvedRoute) SupplyChainRepo() string { return r.repository }

// AuthorizationKey identifies a provider, model, and resolved authority.
type AuthorizationKey struct {
	provider  string
	model     string
	authority string
}

// AuthorizationKey derives the key from this route's validated authority.
func (r ResolvedRoute) AuthorizationKey(providerName, model string) (AuthorizationKey, error) {
	if r.authority == "" || providerName == "" || model == "" {
		return AuthorizationKey{}, errors.New("authorization key requires provider, model, and resolved route")
	}
	return AuthorizationKey{provider: providerName, model: model, authority: r.authority}, nil
}

// SingleflightKey provides one unambiguous serialization for shared work.
func (k AuthorizationKey) SingleflightKey() string {
	return keyPart(k.provider) + keyPart(k.model) + keyPart(k.authority)
}

func keyPart(value string) string { return strconv.Itoa(len(value)) + ":" + value }

// ProviderName returns the provider scope.
func (k AuthorizationKey) ProviderName() string { return k.provider }

// Model returns the model scope.
func (k AuthorizationKey) Model() string { return k.model }

// Authority returns the route authority scope.
func (k AuthorizationKey) Authority() string { return k.authority }

// RouteAttester fetches evidence using a previously resolved route.
type RouteAttester interface {
	FetchAttestationForRoute(context.Context, ResolvedRoute, string, attestation.Nonce) (*attestation.RawAttestation, error)
}

// AttesterForRoute adapts an immutable route to the ordinary attester interface.
// Orchestration resolves once and supplies this adapter at the fetch boundary.
func AttesterForRoute(attester RouteAttester, route ResolvedRoute) (Attester, error) {
	if attester == nil || route.authority == "" {
		return nil, errors.New("route attester requires a resolved route")
	}
	return resolvedAttester{attester: attester, route: route}, nil
}

type resolvedAttester struct {
	attester RouteAttester
	route    ResolvedRoute
}

func (a resolvedAttester) FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	return a.attester.FetchAttestationForRoute(ctx, a.route, model, nonce)
}

// EvidenceScope identifies the independently verified boot. Tinfoil cloud
// authenticates one model-independent router; its backend models are not attested.
// Other providers retain model-specific evidence scopes.
func (k AuthorizationKey) EvidenceScope() AuthorizationKey {
	if k.provider == "tinfoil_v3_cloud" {
		k.model = ""
	}
	return k
}
