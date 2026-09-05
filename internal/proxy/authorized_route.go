package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
)

// Close cancels shared verification and closes idle inference, attestation,
// and provider discovery connections. Active inference streams may finish.
// Callers that serve Server through another HTTP server must call Close.
func (s *Server) Close() {
	if s.authorizations != nil {
		s.authorizations.close()
	}
	if s.upstreamClient != nil {
		s.upstreamClient.CloseIdleConnections()
	}
	if s.attestClient != nil {
		s.attestClient.CloseIdleConnections()
	}
	for _, prov := range s.providers {
		for _, owner := range []any{prov.Attester, prov.ModelLister, prov.E2EEMaterialFetcher} {
			if closer, ok := owner.(interface{ CloseIdleConnections() }); ok {
				closer.CloseIdleConnections()
			}
		}
	}
	if s.pinnedUpstreams != nil {
		s.pinnedUpstreams.mu.Lock()
		defer s.pinnedUpstreams.mu.Unlock()
		for _, entry := range s.pinnedUpstreams.entries {
			entry.transport.CloseIdleConnections()
		}
		clear(s.pinnedUpstreams.entries)
	}
}

func providerForRoute(prov *provider.Provider, route provider.ResolvedRoute) (*provider.Provider, error) {
	scoped := *prov
	scoped.StaticRoute = route
	scoped.BaseURL = route.BaseURL()
	if attester, ok := prov.Attester.(provider.RouteAttester); ok {
		var err error
		scoped.Attester, err = provider.AttesterForRoute(attester, route)
		if err != nil {
			return nil, err
		}
	} else if prov.ResolveRoute != nil {
		return nil, errors.New("dynamic TLS-binding provider has no route-aware attester")
	} else if prov.StaticRoute.Authority() != route.Authority() {
		return nil, errors.New("static attester authority differs from request route")
	}
	return &scoped, nil
}

func (s *Server) loadAuthorization(ctx context.Context, prov *provider.Provider, route provider.ResolvedRoute, key provider.AuthorizationKey) (*authorization, *attestation.VerificationReport, error) {
	derived, err := route.AuthorizationKey(prov.Name, key.Model())
	if err != nil || derived != key {
		return nil, nil, errors.New("authorization route and key differ")
	}
	negative := func() error {
		if _, blocked := s.negCache.ActiveInfo(key.ProviderName(), key.EvidenceScope().SingleflightKey()); blocked {
			return &httpError{503, "neg_cached", errors.New("attestation recently failed for this route")}
		}
		return nil
	}
	observe := func(hit bool) {
		if hit {
			s.stats.cacheHits.Add(1)
		} else {
			s.stats.cacheMisses.Add(1)
		}
	}

	value, blocked, loadErr := s.authorizations.load(ctx, key, negative, observe, func(verifyCtx context.Context) (authorizationVerification, error) {
		scoped, err := providerForRoute(prov, route)
		if err != nil {
			return authorizationVerification{}, err
		}
		recordFailure := func(action string, err error) {
			if verifyCtx.Err() != nil {
				return
			}
			s.negCache.Record(key.ProviderName(), key.EvidenceScope().SingleflightKey())
			slog.WarnContext(verifyCtx, "route attestation failed", "provider", key.ProviderName(), "model", key.Model(), "action", action, "err", err)
		}
		report, raw := s.fetchVerified(withCacheModel(verifyCtx, key.Model()+"@"+key.Authority()), scoped, key.Model(), recordFailure)
		if report == nil || raw == nil {
			return authorizationVerification{}, errors.New("attestation fetch failed")
		}
		s.logReportAllowedFailures(verifyCtx, report, scoped, key.Model())
		if report.Blocked() && !s.cfg.Force {
			recordFailure("factor_failed", errors.New("enforced attestation factor failed"))
			return authorizationVerification{blocked: report}, nil
		}
		expires, present := report.Validity.Expiry()
		candidate, err := newAuthorization(key, report, raw.SigningKey, scoped.E2EE, s.cfg.Force, expires, present, time.Now())
		if err != nil {
			recordFailure("invalid_authorization", err)
			return authorizationVerification{}, fmt.Errorf("construct authorization: %w", err)
		}
		return authorizationVerification{candidate: candidate}, nil
	})
	if blocked != nil {
		blocked.Model = key.Model()
	}
	return value, blocked, loadErr
}

func (s *authorizationStore) snapshots() []*authorization {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	values := make([]*authorization, 0, len(s.entries))
	for key, record := range s.entries {
		if s.closed || (record.value.hasExpiry && !s.now().Before(record.value.expiresAt)) {
			delete(s.entries, key)
			continue
		}
		if len(record.models) != 0 {
			for model, detail := range record.models {
				values = append(values, authorizationForModel(record.value, model, detail))
			}
		} else {
			values = append(values, authorizationForModel(record.value, record.value.key, ""))
		}
	}
	return values
}

type cachedReportSnapshot struct {
	info   attestation.CacheInfo
	report *attestation.VerificationReport
}

func (s *Server) cachedReportSnapshots() []cachedReportSnapshot {
	var values []cachedReportSnapshot
	for _, info := range s.cache.Models() {
		if report, ok := s.cache.Get(info.Provider, info.Model); ok {
			values = append(values, cachedReportSnapshot{info, report})
		}
	}
	for _, value := range s.authorizations.snapshots() {
		info := attestation.CacheInfo{Provider: value.key.ProviderName(), Model: value.key.Model() + "@" + value.key.Authority(), FetchedAt: value.report.Timestamp}
		values = append(values, cachedReportSnapshot{info, value.report})
	}
	return values
}
