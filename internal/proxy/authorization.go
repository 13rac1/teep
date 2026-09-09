package proxy

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct"
	"golang.org/x/sync/singleflight"
)

const (
	maxAuthorizations                = 1000
	maxAuthorizationVerifications    = 16
	authorizationVerificationTimeout = 2 * time.Minute
)

// authorizationGeneration is an opaque equality token, not a key ordering.
type authorizationGeneration uint64

// authorization contains only immutable, verified authorization material.
// Callers must clone its report before modifying it or returning it to a client.
type authorization struct {
	key        provider.AuthorizationKey
	report     *attestation.VerificationReport
	signingKey string
	identity   tlsct.TransportIdentity
	generation authorizationGeneration
}

func newAuthorization(key provider.AuthorizationKey, report *attestation.VerificationReport, signingKey string, requireE2EE, force bool) (*authorization, error) {
	if report == nil || report.Provider != key.ProviderName() || report.Model != key.Model() {
		return nil, errors.New("authorization report does not match provider and model")
	}
	if report.Blocked() && !force {
		return nil, errors.New("authorization report is blocked")
	}
	identity, err := report.TransportIdentity()
	if err != nil {
		return nil, err
	}
	if identity.Authority() != key.Authority() {
		return nil, errors.New("authorization authority does not match route")
	}
	if requireE2EE {
		if !report.ReportDataBindingPassed() {
			return nil, errors.New("authorization E2EE key is not authenticated by REPORTDATA")
		}
		if err := validateAuthorizationKey(key.ProviderName(), signingKey); err != nil {
			return nil, err
		}
	} else {
		signingKey = ""
	}
	return &authorization{key: key, report: report.Clone(), signingKey: signingKey, identity: identity}, nil
}

func validateAuthorizationKey(name, key string) error {
	switch name {
	case "nearcloud", "neardirect":
		return e2ee.ValidateModelKeyEd25519(key)
	case "tinfoil_v3_cloud", "tinfoil_v3_direct":
		decoded, err := hex.DecodeString(key)
		if err != nil {
			return fmt.Errorf("invalid EHBP public key: %w", err)
		}
		// Exercise the production key agreement to reject low-order public keys.
		session, err := e2ee.NewEHBPSession(decoded)
		if err != nil {
			return err
		}
		session.Zero()
		return nil
	default:
		return errors.New("unsupported TLS-binding authorization provider")
	}
}

type authorizationRecord struct {
	value    *authorization
	lastUsed time.Time
	models   map[provider.AuthorizationKey]string // Bounded model-specific E2EE outcomes for a shared router.
}

type authorizationOperation struct {
	ctx    context.Context //nolint:containedctx // Shared operation owns a bounded context independent of request callers.
	cancel context.CancelFunc
}

// verificationOverloadError identifies fail-fast verification admission failure.
type verificationOverloadError struct{}

func (*verificationOverloadError) Error() string {
	return "authorization verification capacity is exhausted"
}

type authorizationStore struct {
	mu             sync.Mutex
	entries        map[provider.AuthorizationKey]authorizationRecord
	active         map[provider.AuthorizationKey]*authorizationOperation
	flight         singleflight.Group
	capacity       int
	admission      chan struct{}
	timeout        time.Duration
	lifecycle      context.Context //nolint:containedctx // Store lifetime cancels detached verification on server shutdown.
	cancel         context.CancelFunc
	closed         bool
	nextGeneration authorizationGeneration
	now            func() time.Time
}

func newAuthorizationStore(capacity, verifications int, timeout time.Duration) *authorizationStore {
	if capacity <= 0 || verifications <= 0 || timeout <= 0 {
		panic("authorization store requires finite positive limits")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &authorizationStore{entries: make(map[provider.AuthorizationKey]authorizationRecord), active: make(map[provider.AuthorizationKey]*authorizationOperation), capacity: capacity, admission: make(chan struct{}, verifications), timeout: timeout, lifecycle: ctx, cancel: cancel, now: time.Now}
}

// acquire is the attempt boundary: deletion prevents subsequent acquisitions,
// while callers that already acquired immutable material may finish naturally.
func (s *authorizationStore) acquire(key provider.AuthorizationKey) (*authorization, bool) {
	s.mu.Lock()
	record, ok := s.lookupLocked(key)
	if !ok {
		s.mu.Unlock()
		return nil, false
	}
	detail := ""
	if key.EvidenceScope() != key {
		record.observeModel(key, s.capacity)
		detail = record.models[key]
		s.entries[key.EvidenceScope()] = record
	}
	s.mu.Unlock()
	return authorizationForModel(record.value, key, detail), true
}

func authorizationForModel(value *authorization, key provider.AuthorizationKey, detail string) *authorization {
	snapshot := *value
	snapshot.key = key
	snapshot.report = value.report.Clone()
	snapshot.report.Model = key.Model()
	if detail != "" {
		snapshot.report.MarkE2EEUsable(detail)
	}
	return &snapshot
}

func (r *authorizationRecord) observeModel(key provider.AuthorizationKey, limit int) {
	if r.models == nil {
		r.models = make(map[provider.AuthorizationKey]string)
	}
	if _, exists := r.models[key]; exists {
		return
	}
	if len(r.models) >= limit {
		for previous := range r.models {
			delete(r.models, previous)
			break
		}
	}
	r.models[key] = ""
}

// lookup returns immutable published material. Callers must clone its report.
func (s *authorizationStore) lookup(key provider.AuthorizationKey) (*authorization, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.lookupLocked(key)
	return record.value, ok
}

func (s *authorizationStore) lookupLocked(key provider.AuthorizationKey) (authorizationRecord, bool) {
	key = key.EvidenceScope()
	if s.closed {
		return authorizationRecord{}, false
	}
	record, ok := s.entries[key]
	if !ok {
		return authorizationRecord{}, false
	}
	now := s.now()
	record.lastUsed = now
	s.entries[key] = record
	return record, true
}

// authorizationVerification returns a validated candidate or a blocked report.
// It must never retain raw attestation or request-specific state in its result.
type authorizationVerification struct {
	candidate *authorization
	blocked   *attestation.VerificationReport
	admission attestation.AdmissionTime
}

type authorizationVerifyFunc func(context.Context) (authorizationVerification, error)

// load collapses verification while allowing each caller to cancel its wait.
// Verification failures are recorded by the shared callback, once per run.
func (s *authorizationStore) load(ctx context.Context, key provider.AuthorizationKey, negative func() error, observe func(bool), verify authorizationVerifyFunc) (*authorization, *attestation.VerificationReport, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		value, hit := s.acquire(key)
		if observe != nil {
			observe(hit)
			observe = nil // Count only the initial lookup, not acquisition after verification.
		}
		if hit {
			return value, nil, nil
		}
		if negative != nil {
			if err := negative(); err != nil {
				return nil, nil, err
			}
		}
		result := s.flight.DoChan(key.EvidenceScope().SingleflightKey(), func() (any, error) {
			return s.verifyShared(key, negative, verify)
		})
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case completed := <-result:
			if completed.Err != nil {
				return nil, nil, completed.Err
			}
			verified, ok := completed.Val.(authorizationVerification)
			if !ok {
				return nil, nil, errors.New("invalid shared authorization result")
			}
			if verified.blocked != nil {
				return nil, verified.blocked.Clone(), nil
			}
			// Receiving a shared result is not acquisition. Recheck the current
			// generation under the state lock before preparing an attempt.
		}
	}
}

func (s *authorizationStore) verifyShared(key provider.AuthorizationKey, negative func() error, verify authorizationVerifyFunc) (authorizationVerification, error) {
	if _, ok := s.lookup(key); ok {
		return authorizationVerification{}, nil
	}
	if negative != nil {
		if err := negative(); err != nil {
			return authorizationVerification{}, err
		}
	}
	op, err := s.begin(key)
	if err != nil {
		return authorizationVerification{}, err
	}
	defer s.finish(key, op)
	result, err := verify(op.ctx)
	if err != nil {
		return authorizationVerification{}, err
	}
	if result.blocked != nil {
		return authorizationVerification{blocked: result.blocked.Clone()}, nil
	}
	if result.candidate == nil {
		return authorizationVerification{}, errors.New("verification did not produce authorization")
	}
	if err := s.publish(key, op, result.candidate, result.admission); err != nil {
		slog.WarnContext(op.ctx, "authorization publication failed", "provider", key.ProviderName(), "model", key.Model(), "authority", key.Authority(), "err", err)
		return authorizationVerification{}, err
	}
	return authorizationVerification{}, nil
}

func (s *authorizationStore) begin(key provider.AuthorizationKey) (*authorizationOperation, error) {
	key = key.EvidenceScope()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("authorization store is closed")
	}
	select {
	case s.admission <- struct{}{}:
	default:
		return nil, &verificationOverloadError{}
	}
	ctx, cancel := context.WithTimeout(s.lifecycle, s.timeout)
	op := &authorizationOperation{ctx: ctx, cancel: cancel}
	s.active[key] = op
	return op, nil
}

func (s *authorizationStore) finish(key provider.AuthorizationKey, op *authorizationOperation) {
	key = key.EvidenceScope()
	op.cancel()
	s.mu.Lock()
	if s.active[key] == op {
		delete(s.active, key)
	}
	s.mu.Unlock()
	<-s.admission
}

func (s *authorizationStore) publish(key provider.AuthorizationKey, op *authorizationOperation, candidate *authorization, admission attestation.AdmissionTime) error {
	key = key.EvidenceScope()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.active[key] != op || op.ctx.Err() != nil {
		return errors.New("authorization verification was invalidated")
	}
	if candidate.key.EvidenceScope() != key {
		return errors.New("authorization candidate does not match publication key")
	}
	if err := admission.Check(s.now()); err != nil {
		return err
	}
	if s.nextGeneration == ^authorizationGeneration(0) {
		panic("authorization generation exhausted")
	}
	s.nextGeneration++
	value := *candidate
	value.report = candidate.report.Clone()
	value.generation = s.nextGeneration
	s.entries[key] = authorizationRecord{value: &value, lastUsed: s.now()}
	s.evictLocked(key)
	return nil
}

func (s *authorizationStore) evictLocked(keep provider.AuthorizationKey) {
	if len(s.entries) <= s.capacity {
		return
	}
	var oldest provider.AuthorizationKey
	var at time.Time
	for key, record := range s.entries {
		if key != keep && (at.IsZero() || record.lastUsed.Before(at)) {
			oldest, at = key, record.lastUsed
		}
	}
	if len(s.entries) > s.capacity {
		delete(s.entries, oldest)
	}
}

func (s *authorizationStore) deleteGeneration(key provider.AuthorizationKey, generation authorizationGeneration) bool {
	key = key.EvidenceScope()
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.entries[key]
	if !ok || record.value.generation != generation {
		return false
	}
	delete(s.entries, key)
	return true
}

func (s *authorizationStore) promote(key provider.AuthorizationKey, generation authorizationGeneration, detail string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.entries[key.EvidenceScope()]
	if !ok || record.value.generation != generation {
		return false
	}
	if key.EvidenceScope() != key {
		record.observeModel(key, s.capacity)
		record.models[key] = detail
		s.entries[key.EvidenceScope()] = record
		return true
	}
	for _, factor := range record.value.report.Factors {
		if factor.Name != attestation.FactorE2EEUsable {
			continue
		}
		if factor.Status != attestation.Skip {
			return true
		}
		value := *record.value
		value.report = value.report.Clone()
		value.report.MarkE2EEUsable(detail)
		record.value = &value
		s.entries[key] = record
		break
	}
	return true
}

func (s *authorizationStore) invalidate(key provider.AuthorizationKey) {
	key = key.EvidenceScope()
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, key)
	if op := s.active[key]; op != nil {
		op.cancel()
	}
}

func (s *authorizationStore) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.cancel()
	clear(s.entries)
}

// counts returns live authorizations and retained encryption keys without
// copying reports or changing cache recency.
func (s *authorizationStore) counts() (entries, signingKeys int) {
	if s == nil {
		return 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, 0
	}
	for _, record := range s.entries {
		entries++
		if record.value.signingKey != "" {
			signingKeys++
		}
	}
	return entries, signingKeys
}
