package proxy

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync/atomic"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/reqid"
)

// errReportInvalidated fails a shared verification whose provider and model
// had their cached report invalidated while the verification ran.
var errReportInvalidated = errors.New("attestation cache was invalidated during verification")

// sharedReport is the result of one shared report verification. The raw
// attestation can contain single-use E2EE material, so only one waiter
// receives it. Other waiters continue as after a report cache hit.
// publication is the number that the report cache assigned to the report.
type sharedReport struct {
	report      *attestation.VerificationReport
	raw         *attestation.RawAttestation
	publication uint64
	claimed     atomic.Bool
}

// reportFlightKey returns the singleflight key for a provider and model.
// Each name is quoted, so no two pairs produce the same key.
func reportFlightKey(key providerModelKey) string {
	return strconv.Quote(key.provider) + strconv.Quote(key.model)
}

// loadReport starts or joins the report verification for a provider and
// model that miss in the report cache, and returns the report, the raw
// attestation for one waiter, and the report's publication number. The caller's
// context limits only its wait for the result.
func (s *Server) loadReport(ctx context.Context, prov *provider.Provider, upstreamModel string) (*attestation.VerificationReport, *attestation.RawAttestation, uint64, error) {
	key := providerModelKey{prov.Name, cacheModelFor(ctx, upstreamModel)}
	leader := reqid.FromContext(ctx)
	// Waiters share the leader's upstreamModel: the key's cache model scopes the cached report and key.
	result := s.reportFlight.DoChan(reportFlightKey(key), func() (any, error) { //nolint:contextcheck // The server owns the shared verification context, independent of each waiter.
		return s.verifyReportShared(prov, upstreamModel, key, leader)
	})
	select {
	case <-ctx.Done():
		return nil, nil, 0, ctx.Err()
	case completed := <-result:
		if completed.Err != nil {
			return nil, nil, 0, completed.Err
		}
		shared, ok := completed.Val.(*sharedReport)
		if !ok {
			return nil, nil, 0, errors.New("invalid shared report result")
		}
		if shared.claimed.CompareAndSwap(false, true) {
			return shared.report, shared.raw, shared.publication, nil
		}
		return shared.report, nil, shared.publication, nil
	}
}

// verifyReportShared runs one report verification under a server-owned
// context with the authorization store's time limit. It checks the report and
// negative caches again because a verification that completed after the
// caller's lookup can have populated them. A panic becomes an error for the
// waiters, because the verification does not run in a request goroutine.
func (s *Server) verifyReportShared(prov *provider.Provider, upstreamModel string, key providerModelKey, leader string) (shared *sharedReport, err error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("shared attestation verification panicked", "provider", prov.Name, "model", upstreamModel, "panic", r)
			shared, err = nil, fmt.Errorf("shared attestation verification panicked: %v", r)
		}
	}()
	slog.Info("shared attestation verification started", "provider", prov.Name, "model", upstreamModel, "leader_req", leader)
	if report, publication, ok := s.cache.GetPublication(key.provider, key.model); ok {
		return &sharedReport{report: report, publication: publication}, nil
	}
	if s.negCache.IsBlocked(key.provider, key.model) {
		slog.Warn("attestation recently failed; shared verification not started", "provider", prov.Name, "model", upstreamModel)
		return nil, errors.New("attestation recently failed")
	}
	select {
	case s.reportAdmission <- struct{}{}:
		defer func() { <-s.reportAdmission }()
	default:
		return nil, &verificationOverloadError{}
	}
	epoch := s.reportEpoch(key)
	ctx, cancel := s.authorizations.verificationContext()
	defer cancel()
	ctx = withCacheModel(ctx, key.model)
	report, raw, admission, _ := s.fetchVerified(ctx, prov, upstreamModel, func(action string, err error) {
		s.recordNegativeCache(ctx, prov, upstreamModel, action, nil, err)
	})
	if report == nil {
		// fetchVerified logs the cause, and the callback records the negative cache entry.
		return nil, errors.New("attestation fetch failed")
	}
	if raw == nil {
		slog.ErrorContext(ctx, "attestation verification returned a report without raw attestation", "provider", prov.Name, "model", upstreamModel)
		return nil, errors.New("attestation verification returned no raw attestation")
	}
	s.logReportAllowedFailures(ctx, report, prov, upstreamModel)
	publication, err := s.publishReport(ctx, prov, upstreamModel, key, epoch, admission, report, raw)
	if err != nil {
		return nil, err
	}
	return &sharedReport{report: report, raw: raw, publication: publication}, nil
}

// reportEpoch returns the number of invalidations of the cached report for a
// provider and model. A verification publishes only if the epoch that it read
// before its fetch is still current.
func (s *Server) reportEpoch(key providerModelKey) uint64 {
	s.reportMu.Lock()
	defer s.reportMu.Unlock()
	return s.reportEpochs[key]
}

// invalidateReportLocked makes a shared verification that read an earlier
// epoch fail instead of publishing, ends the current publication, and makes
// the next cache miss start a new verification. The caller holds reportMu.
func (s *Server) invalidateReportLocked(key providerModelKey) {
	s.reportEpochs[key]++
	delete(s.reportPubs, key)
	s.reportFlight.Forget(reportFlightKey(key))
}

// storeReportLocked writes report to the report cache and records its
// publication number as the current publication for key, which stays current
// after the cache entry expires until the next publication or invalidation.
// The caller holds reportMu.
func (s *Server) storeReportLocked(key providerModelKey, report *attestation.VerificationReport) uint64 {
	publication := s.cache.Put(key.provider, key.model, report)
	s.reportPubs[key] = publication
	return publication
}

// publishReport writes the signing key and then the report of a shared
// verification, unless the verified NRAS evidence is not time eligible now or
// the cached report was invalidated after the verification read epoch, and
// returns the report's publication number.
// It caches the signing key only if the report passes enforceReport: a key
// from a failed attestation must not be reused on a cache hit. Waiters
// without the raw attestation then use this key instead of fetching
// attestation again. The key is written first, so that a request that finds
// the report also finds its key. A passing report is the fresh
// re-attestation for every waiter, so it clears a prior E2EE failure.
func (s *Server) publishReport(ctx context.Context, prov *provider.Provider, upstreamModel string, key providerModelKey, epoch uint64,
	admission attestation.AdmissionTime, report *attestation.VerificationReport, raw *attestation.RawAttestation,
) (uint64, error) {
	s.reportMu.Lock()
	defer s.reportMu.Unlock()
	if err := admission.Check(s.authorizations.now()); err != nil {
		slog.WarnContext(ctx, "verified NRAS evidence is not time eligible; result not published", "provider", prov.Name, "model", upstreamModel, "err", err)
		return 0, err
	}
	if s.reportEpochs[key] != epoch {
		slog.WarnContext(ctx, "attestation cache was invalidated during verification; result not published", "provider", prov.Name, "model", upstreamModel)
		return 0, errReportInvalidated
	}
	passed := !report.Blocked() || s.cfg.Force
	if passed && raw.SigningKey != "" {
		if prev, ok := s.signingKeyCache.Get(key.provider, key.model); ok && subtle.ConstantTimeCompare([]byte(prev), []byte(raw.SigningKey)) == 0 {
			slog.WarnContext(ctx, "signing key rotated (VM restart?)", "provider", prov.Name, "model", upstreamModel)
		}
		s.signingKeyCache.Put(key.provider, key.model, raw.SigningKey)
	}
	publication := s.storeReportLocked(key, report)
	if !passed {
		return publication, nil
	}
	if _, failed := s.e2eeFailed.LoadAndDelete(key); failed {
		slog.InfoContext(ctx, "Cleared prior E2EE failure after successful re-attestation", "provider", prov.Name, "model", upstreamModel)
	}
	return publication, nil
}

// markReportE2EEUsable records a successful E2EE round trip in a copy of
// report, the report that the request used. It changes the cache only if the
// cache still holds that report's publication, and keeps the entry's
// publication number and fetch time. A request outcome must not restore an
// invalidated or expired report, overwrite a replacement, or extend the
// lifetime of the report.
func (s *Server) markReportE2EEUsable(key providerModelKey, publication uint64, report *attestation.VerificationReport) {
	cloned := report.Clone()
	cloned.MarkE2EEUsable("E2EE roundtrip succeeded via proxy")
	s.reportMu.Lock()
	defer s.reportMu.Unlock()
	s.cache.Replace(key.provider, key.model, publication, cloned)
}

// writeReportLoadError writes the response for a failed report load and
// returns the request status.
func writeReportLoadError(ctx context.Context, w http.ResponseWriter, prov *provider.Provider, upstreamModel string, err error) string {
	var overload *verificationOverloadError
	switch {
	case errors.As(err, &overload):
		slog.WarnContext(ctx, "attestation verification capacity is exhausted",
			"provider", prov.Name, "model", upstreamModel, "limit", maxAuthorizationVerifications, "err", err)
		http.Error(w, "attestation verification capacity is exhausted; try again later", http.StatusServiceUnavailable)
		return "attest_overloaded"
	case ctx.Err() != nil && errors.Is(err, ctx.Err()):
		// Only this caller stopped waiting. The shared verification continues.
		slog.WarnContext(ctx, "request ended before shared attestation verification completed",
			"provider", prov.Name, "model", upstreamModel, "err", err)
		http.Error(w, "request ended before attestation completed", http.StatusBadGateway)
		return "canceled"
	default:
		http.Error(w, "attestation fetch failed; see server logs", http.StatusBadGateway)
		return "attest_failed"
	}
}
