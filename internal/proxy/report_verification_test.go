package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
)

// heldReportAttester holds every attestation fetch until the test releases it.
// It records the context of each fetch to show who owns the verification.
type heldReportAttester struct {
	calls    atomic.Int32
	release  chan struct{}
	err      error
	mu       sync.Mutex
	contexts []context.Context
}

func newHeldReportAttester(err error) *heldReportAttester {
	return &heldReportAttester{release: make(chan struct{}), err: err}
}

func (a *heldReportAttester) FetchAttestation(ctx context.Context, _ string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	a.calls.Add(1)
	a.mu.Lock()
	a.contexts = append(a.contexts, ctx)
	a.mu.Unlock()
	select {
	case <-a.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if a.err != nil {
		return nil, a.err
	}
	return &attestation.RawAttestation{Nonce: nonce.Hex(), NonceSource: "client", SigningKey: "attested-key"}, nil
}

// newReportTestServer builds the production server for a provider that uses
// the report cache, with the default factor enforcement and the test attester.
func newReportTestServer(t *testing.T, attester provider.Attester) (*Server, *provider.Provider) {
	t.Helper()
	s, err := New(&config.Config{Offline: true, Providers: map[string]*config.Provider{"venice": {Name: "venice", BaseURL: "https://venice.test", APIKey: "test-key"}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	prov := s.providers["venice"]
	if prov.UsesTLSBinding {
		t.Fatal("test provider must use the report cache")
	}
	prov.Attester = attester
	return s, prov
}

func waitForCondition(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

type reportAttempt struct {
	status string
	code   int
	result *attestResult
}

func startReportAttempt(ctx context.Context, s *Server, prov *provider.Provider, model string, done chan<- reportAttempt) {
	go func() {
		rec := httptest.NewRecorder()
		result, status := s.attestAndCache(ctx, rec, prov, model, &modelStats{})
		done <- reportAttempt{status: status, code: rec.Code, result: result}
	}()
}

func TestReportVerificationSharedAcrossConcurrentMisses(t *testing.T) {
	attester := newHeldReportAttester(nil)
	s, prov := newReportTestServer(t, attester)
	const n = 24
	done := make(chan reportAttempt, n)
	for range n {
		startReportAttempt(t.Context(), s, prov, "model", done)
	}
	waitForCondition(t, "all cache misses", func() bool { return s.stats.cacheMisses.Load() == n })
	close(attester.release)
	for range n {
		attempt := <-done
		// The default policy blocks the test evidence. Every request enforces
		// the shared report as after a cache hit.
		if attempt.status != "blocked" || attempt.code != http.StatusBadGateway {
			t.Errorf("status=%q code=%d, want blocked 502", attempt.status, attempt.code)
		}
	}
	if cached, ok := s.cache.Get(prov.Name, "model"); !ok || !cached.Blocked() {
		t.Fatal("shared verification did not populate the report cache")
	}
	if got := attester.calls.Load(); got != 1 {
		t.Fatalf("attestation fetches = %d, want 1", got)
	}
	if s.stats.cacheHits.Load() != 0 || s.stats.cacheMisses.Load() != n {
		t.Fatalf("cache hits=%d misses=%d", s.stats.cacheHits.Load(), s.stats.cacheMisses.Load())
	}
	if _, blocked := s.negCache.ActiveInfo(prov.Name, "model"); blocked {
		t.Fatal("blocked report entered the negative cache")
	}
}

// Raw attestation can carry a single-use E2EE nonce, so exactly one waiter
// receives it. The others use the shared report as after a cache hit.
func TestReportVerificationGivesRawToOneWaiter(t *testing.T) {
	attester := newHeldReportAttester(nil)
	s, prov := newReportTestServer(t, attester)
	const n = 16
	var raws atomic.Int32
	reports := make(chan *attestation.VerificationReport, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			report, raw, _, err := s.loadReport(t.Context(), prov, "model")
			if err != nil {
				t.Error(err)
				return
			}
			if raw != nil {
				raws.Add(1)
			}
			reports <- report
		})
	}
	waitForCondition(t, "shared fetch", func() bool { return attester.calls.Load() == 1 })
	close(attester.release)
	wg.Wait()
	close(reports)
	cached, ok := s.cache.Get(prov.Name, "model")
	if !ok {
		t.Fatal("report was not cached")
	}
	for report := range reports {
		if report != cached {
			t.Error("waiter received a report that differs from the cache entry")
		}
	}
	if raws.Load() != 1 || attester.calls.Load() != 1 {
		t.Fatalf("raw receivers=%d fetches=%d, want 1 and 1", raws.Load(), attester.calls.Load())
	}
}

func TestReportVerificationCallerCancellation(t *testing.T) {
	attester := newHeldReportAttester(nil)
	s, prov := newReportTestServer(t, attester)
	callerCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	canceled := make(chan reportAttempt, 1)
	startReportAttempt(callerCtx, s, prov, "model", canceled)
	waitForCondition(t, "shared fetch", func() bool { return attester.calls.Load() == 1 })
	waiting := make(chan reportAttempt, 1)
	startReportAttempt(t.Context(), s, prov, "model", waiting)
	waitForCondition(t, "second cache miss", func() bool { return s.stats.cacheMisses.Load() == 2 })

	var attempt reportAttempt
	logs := captureSlog(t, func() {
		cancel()
		attempt = <-canceled
	})
	if attempt.status != "canceled" || attempt.code != http.StatusBadGateway {
		t.Fatalf("canceled caller status=%q code=%d", attempt.status, attempt.code)
	}
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "request ended before shared attestation verification completed") || !strings.Contains(logs, "provider=venice") {
		t.Fatalf("cancellation diagnostic missing:\n%s", logs)
	}
	attester.mu.Lock()
	verifyCtx := attester.contexts[0]
	attester.mu.Unlock()
	if verifyCtx.Err() != nil {
		t.Fatal("caller cancellation canceled the shared verification")
	}
	deadline, bounded := verifyCtx.Deadline()
	if !bounded || time.Until(deadline) > authorizationVerificationTimeout {
		t.Fatal("shared verification has no server time limit")
	}
	if _, blocked := s.negCache.ActiveInfo(prov.Name, "model"); blocked {
		t.Fatal("caller cancellation entered the negative cache")
	}

	close(attester.release)
	if attempt := <-waiting; attempt.status != "blocked" {
		t.Fatalf("waiting caller status=%q, want enforcement of the shared report", attempt.status)
	}
	if _, ok := s.cache.Get(prov.Name, "model"); !ok {
		t.Fatal("shared verification did not populate the cache after caller cancellation")
	}
	if attester.calls.Load() != 1 {
		t.Fatalf("attestation fetches = %d, want 1", attester.calls.Load())
	}
}

func TestReportVerificationAdmissionLimit(t *testing.T) {
	attester := newHeldReportAttester(nil)
	s, prov := newReportTestServer(t, attester)
	done := make(chan reportAttempt, maxAuthorizationVerifications)
	for i := range maxAuthorizationVerifications {
		startReportAttempt(t.Context(), s, prov, fmt.Sprintf("model-%d", i), done)
	}
	waitForCondition(t, "full admission", func() bool { return attester.calls.Load() == maxAuthorizationVerifications })

	var attempt reportAttempt
	logs := captureSlog(t, func() {
		rec := httptest.NewRecorder()
		result, status := s.attestAndCache(t.Context(), rec, prov, "extra", &modelStats{})
		attempt = reportAttempt{status: status, code: rec.Code, result: result}
	})
	if attempt.status != "attest_overloaded" || attempt.code != http.StatusServiceUnavailable {
		t.Fatalf("attempt past the limit: status=%q code=%d", attempt.status, attempt.code)
	}
	for _, want := range []string{"attestation verification capacity is exhausted", "provider=venice", "model=extra", fmt.Sprintf("limit=%d", maxAuthorizationVerifications)} {
		if !strings.Contains(logs, want) {
			t.Fatalf("overload diagnostic missing %q:\n%s", want, logs)
		}
	}
	if _, blocked := s.negCache.ActiveInfo(prov.Name, "extra"); blocked {
		t.Fatal("admission failure entered the negative cache")
	}
	if attester.calls.Load() != maxAuthorizationVerifications {
		t.Fatal("attempt past the limit fetched attestation")
	}

	close(attester.release)
	for range maxAuthorizationVerifications {
		<-done
	}
	rec := httptest.NewRecorder()
	if _, status := s.attestAndCache(t.Context(), rec, prov, "extra", &modelStats{}); status != "blocked" {
		t.Fatalf("released admission did not permit verification: status=%q", status)
	}
	if attester.calls.Load() != maxAuthorizationVerifications+1 {
		t.Fatal("released admission did not fetch attestation")
	}
}

func TestReportVerificationFailureFailsEveryWaiter(t *testing.T) {
	attester := newHeldReportAttester(errors.New("attestation endpoint unavailable"))
	s, prov := newReportTestServer(t, attester)
	const n = 12
	done := make(chan reportAttempt, n)
	logs := captureSlog(t, func() {
		for range n {
			startReportAttempt(t.Context(), s, prov, "model", done)
		}
		waitForCondition(t, "all cache misses", func() bool { return s.stats.cacheMisses.Load() == n })
		close(attester.release)
		for range n {
			attempt := <-done
			if attempt.status != "attest_failed" || attempt.code != http.StatusBadGateway {
				t.Errorf("status=%q code=%d, want attest_failed 502", attempt.status, attempt.code)
			}
		}
	})
	if attester.calls.Load() != 1 {
		t.Fatalf("attestation fetches = %d, want 1", attester.calls.Load())
	}
	if got := strings.Count(logs, "negative cache recorded"); got != 1 {
		t.Fatalf("negative cache records = %d, want 1:\n%s", got, logs)
	}
	if _, blocked := s.negCache.ActiveInfo(prov.Name, "model"); !blocked {
		t.Fatal("shared failure did not enter the negative cache")
	}
	if _, ok := s.cache.Get(prov.Name, "model"); ok {
		t.Fatal("failed verification populated the report cache")
	}
}

// The shared verification caches the signing key once, under the same
// condition that enforceReport uses. Waiters without the raw attestation then
// use the cached key instead of fetching attestation again for E2EE.
func TestReportVerificationCachesSigningKeyOnce(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(fmt.Sprintf("force=%v", force), func(t *testing.T) {
			attester := newHeldReportAttester(nil)
			s, prov := newReportTestServer(t, attester)
			// The enforcement policy is the subject of this test.
			s.cfg.Force = force
			s.signingKeyCache.Put(prov.Name, "model", "previous-key")
			const n = 8
			done := make(chan reportAttempt, n)
			raws := 0
			logs := captureSlog(t, func() {
				for range n {
					startReportAttempt(t.Context(), s, prov, "model", done)
				}
				waitForCondition(t, "all cache misses", func() bool { return s.stats.cacheMisses.Load() == n })
				close(attester.release)
				for range n {
					attempt := <-done
					if attempt.result.Raw != nil {
						raws++
					}
					if force != (attempt.status == "") {
						t.Errorf("force=%v status=%q", force, attempt.status)
					}
				}
			})
			key, _ := s.signingKeyCache.Get(prov.Name, "model")
			rotations := strings.Count(logs, "signing key rotated")
			if force && (key != "attested-key" || rotations != 1 || raws != 1) {
				t.Fatalf("passing report: cached key=%q rotation warnings=%d raw receivers=%d", key, rotations, raws)
			}
			if !force && (key != "previous-key" || rotations != 0) {
				t.Fatalf("blocked report changed the signing key cache: key=%q rotation warnings=%d", key, rotations)
			}
			if attester.calls.Load() != 1 {
				t.Fatalf("attestation fetches = %d, want 1", attester.calls.Load())
			}
		})
	}
}

func TestReportVerificationEndsAtServerClose(t *testing.T) {
	attester := newHeldReportAttester(nil)
	s, prov := newReportTestServer(t, attester)
	done := make(chan reportAttempt, 1)
	startReportAttempt(t.Context(), s, prov, "model", done)
	waitForCondition(t, "shared fetch", func() bool { return attester.calls.Load() == 1 })
	s.Close()
	if attempt := <-done; attempt.status != "attest_failed" {
		t.Fatalf("status=%q, want attest_failed", attempt.status)
	}
	attester.mu.Lock()
	verifyCtx := attester.contexts[0]
	attester.mu.Unlock()
	if !errors.Is(verifyCtx.Err(), context.Canceled) {
		t.Fatal("server close did not end the shared verification")
	}
	if _, ok := s.cache.Get(prov.Name, "model"); ok {
		t.Fatal("ended verification populated the report cache")
	}
}

// A passing shared verification is the fresh re-attestation for every waiter.
// A waiter without the raw attestation must not fail with 503 or delete the
// report and signing key that the verification published.
func TestReportVerificationClearsE2EEFailureForEveryWaiter(t *testing.T) {
	attester := newHeldReportAttester(nil)
	s, prov := newReportTestServer(t, attester)
	// The test evidence fails TDX verification, and the default policy blocks
	// it. Force is the only policy that gives a passing report here.
	s.cfg.Force = true
	failure := providerModelKey{prov.Name, "model"}
	s.e2eeFailed.Store(failure, true)
	const n = 12
	codes := make(chan int, n)
	logs := captureSlog(t, func() {
		var wg sync.WaitGroup
		for range n {
			wg.Go(func() {
				rec := httptest.NewRecorder()
				ms := &modelStats{}
				ar, status := s.attestAndCache(t.Context(), rec, prov, "model", ms)
				if status != "" {
					t.Errorf("status=%q, want a passing report", status)
					return
				}
				// endpointHandler runs this check for an E2EE-active report.
				// The test evidence cannot pass the report data binding.
				if !s.checkE2EEFailure(t.Context(), rec, prov, "model", ar, ms) {
					t.Error("waiter of the passing verification failed the E2EE failure check")
				}
				codes <- rec.Code
			})
		}
		waitForCondition(t, "all cache misses", func() bool { return s.stats.cacheMisses.Load() == n })
		close(attester.release)
		wg.Wait()
	})
	close(codes)
	for code := range codes {
		if code == http.StatusServiceUnavailable {
			t.Error("waiter got 503")
		}
	}
	if got := strings.Count(logs, "Cleared prior E2EE failure"); got != 1 {
		t.Fatalf("E2EE failure cleared %d times, want 1:\n%s", got, logs)
	}
	if _, failed := s.e2eeFailed.Load(failure); failed {
		t.Fatal("E2EE failure is still recorded")
	}
	if _, ok := s.cache.Get(prov.Name, "model"); !ok {
		t.Fatal("report cache is empty after the passing verification")
	}
	if key, ok := s.signingKeyCache.Get(prov.Name, "model"); !ok || key != "attested-key" {
		t.Fatalf("signing key cache = %q, %v after the passing verification", key, ok)
	}
	if attester.calls.Load() != 1 {
		t.Fatalf("attestation fetches = %d, want 1", attester.calls.Load())
	}
}

// An invalidation while a shared verification runs prevents its publication.
// The next request starts a new verification instead of joining the old one.
func TestReportVerificationInvalidatedDuringVerification(t *testing.T) {
	attester := newHeldReportAttester(nil)
	s, prov := newReportTestServer(t, attester)
	expiredPub := publishTestReport(s, providerModelKey{prov.Name, "model"}, &attestation.VerificationReport{})
	s.cache.Delete(prov.Name, "model")
	before := make(chan reportAttempt, 1)
	var after *attestation.VerificationReport
	afterDone := make(chan struct{})
	logs := captureSlog(t, func() {
		startReportAttempt(t.Context(), s, prov, "model", before)
		waitForCondition(t, "first fetch", func() bool { return attester.calls.Load() == 1 })
		// The failing request used a report that expired before the verification started.
		s.handleE2EEDecryptionFailure(t.Context(), prov, "model", expiredPub, &modelStats{}, false, "", errors.New("decrypt error"))
		go func() {
			defer close(afterDone)
			report, _, _, err := s.loadReport(t.Context(), prov, "model")
			if err != nil {
				t.Error(err)
			}
			after = report
		}()
		waitForCondition(t, "new verification", func() bool { return attester.calls.Load() == 2 })
		close(attester.release)
		if attempt := <-before; attempt.status != "attest_failed" || attempt.code != http.StatusBadGateway {
			t.Errorf("waiter of the invalidated verification: status=%q code=%d, want attest_failed 502", attempt.status, attempt.code)
		}
		<-afterDone
	})
	if got := strings.Count(logs, "result not published"); got != 1 {
		t.Fatalf("unpublished verification warnings = %d, want 1:\n%s", got, logs)
	}
	if cached, ok := s.cache.Get(prov.Name, "model"); !ok || after == nil || cached != after {
		t.Fatal("report cache does not hold the report of the new verification")
	}
	if _, blocked := s.negCache.ActiveInfo(prov.Name, "model"); blocked {
		t.Fatal("invalidated verification entered the negative cache")
	}
	// The default policy blocks the new report, so the E2EE failure remains.
	if _, failed := s.e2eeFailed.Load(providerModelKey{prov.Name, "model"}); !failed {
		t.Fatal("blocked report cleared the E2EE failure")
	}
}

// A shared verification that finds a negative cache entry fails with a
// warning and does not fetch attestation.
func TestReportVerificationNegativeCacheRecheck(t *testing.T) {
	attester := newHeldReportAttester(nil)
	s, prov := newReportTestServer(t, attester)
	s.negCache.Record(prov.Name, "model")
	var err error
	logs := captureSlog(t, func() {
		_, _, _, err = s.loadReport(t.Context(), prov, "model")
	})
	if err == nil {
		t.Fatal("shared verification ignored the negative cache entry")
	}
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "shared verification not started") || !strings.Contains(logs, "provider=venice") {
		t.Fatalf("negative cache diagnostic missing:\n%s", logs)
	}
	if attester.calls.Load() != 0 {
		t.Fatal("shared verification fetched attestation despite the negative cache entry")
	}
}

type panicReportAttester struct{}

func (panicReportAttester) FetchAttestation(context.Context, string, attestation.Nonce) (*attestation.RawAttestation, error) {
	panic("attester failure")
}

// A panic in the shared verification fails its waiter and does not end the
// process.
func TestReportVerificationPanicFailsWaiters(t *testing.T) {
	s, prov := newReportTestServer(t, panicReportAttester{})
	var status string
	logs := captureSlog(t, func() {
		_, status = s.attestAndCache(t.Context(), httptest.NewRecorder(), prov, "model", &modelStats{})
	})
	if status != "attest_failed" {
		t.Fatalf("status=%q, want attest_failed", status)
	}
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "shared attestation verification panicked") {
		t.Fatalf("panic diagnostic missing:\n%s", logs)
	}
}

func e2eeUsableStatus(report *attestation.VerificationReport) attestation.Status {
	for _, f := range report.Factors {
		if f.Name == attestation.FactorE2EEUsable {
			return f.Status
		}
	}
	return attestation.Skip
}

// publishTestReport stores report as the current publication for key, as a
// shared verification does after its epoch check passes.
func publishTestReport(s *Server, key providerModelKey, report *attestation.VerificationReport) uint64 {
	s.reportMu.Lock()
	defer s.reportMu.Unlock()
	return s.storeReportLocked(key, report)
}

// A successful request changes the cached report only if the cache still holds
// the publication of the report that the request used, and it does not extend
// the entry's lifetime.
func TestReportVerificationSuccessChangesOnlyItsReport(t *testing.T) {
	s, prov := newReportTestServer(t, newHeldReportAttester(nil))
	key := providerModelKey{prov.Name, "model"}
	used := &attestation.VerificationReport{Factors: []attestation.FactorResult{{Name: attestation.FactorE2EEUsable, Status: attestation.Skip}}}
	usedPub := publishTestReport(s, key, used)
	fetchedAt := s.cache.Models()[0].FetchedAt
	time.Sleep(time.Millisecond)

	s.markReportE2EEUsable(key, usedPub, used)
	marked, pub, ok := s.cache.GetPublication(key.provider, key.model)
	if !ok || marked == used || e2eeUsableStatus(marked) != attestation.Pass {
		t.Fatal("success did not record e2ee_usable in the report that it used")
	}
	if pub != usedPub {
		t.Fatalf("success changed the report publication from %d to %d", usedPub, pub)
	}
	if e2eeUsableStatus(used) != attestation.Skip {
		t.Fatal("success changed the shared report in place")
	}
	if got := s.cache.Models()[0].FetchedAt; !got.Equal(fetchedAt) {
		t.Fatalf("success extended the report fetch time from %v to %v", fetchedAt, got)
	}

	// The cache now holds a later publication.
	replacement := &attestation.VerificationReport{}
	replacementPub := publishTestReport(s, key, replacement)
	s.markReportE2EEUsable(key, usedPub, used)
	if got, _ := s.cache.Get(key.provider, key.model); got != replacement {
		t.Fatal("success on an earlier publication overwrote the replacement")
	}

	// An E2EE failure invalidated the report that the request used.
	s.cache.Delete(key.provider, key.model)
	s.markReportE2EEUsable(key, replacementPub, replacement)
	if _, ok := s.cache.Get(key.provider, key.model); ok {
		t.Fatal("success restored an invalidated report")
	}
}

// newShortTTLReportTestServer replaces the report cache with one whose entries
// expire after ttl.
func newShortTTLReportTestServer(t *testing.T, ttl time.Duration) (*Server, *provider.Provider) {
	t.Helper()
	s, prov := newReportTestServer(t, newHeldReportAttester(nil))
	s.cache = attestation.NewCache(ttl)
	return s, prov
}

// publishExpiredThenBlocked publishes a passing report, lets it expire, and
// publishes a blocked replacement under the same invalidation epoch, as a new
// verification does after the TTL. It returns the expired report, its
// publication, and the replacement.
func publishExpiredThenBlocked(t *testing.T, s *Server, prov *provider.Provider) (old *attestation.VerificationReport, oldPub uint64, blocked *attestation.VerificationReport) {
	t.Helper()
	key := providerModelKey{prov.Name, "model"}
	old = &attestation.VerificationReport{Factors: []attestation.FactorResult{{Name: attestation.FactorE2EEUsable, Status: attestation.Skip}}}
	raw := &attestation.RawAttestation{SigningKey: "old-key"}
	oldPub, err := s.publishReport(t.Context(), prov, "model", key, s.reportEpoch(key), attestation.AdmissionTime{}, old, raw)
	if err != nil {
		t.Fatal(err)
	}
	s.signingKeyCache.Delete(key.provider, key.model)
	waitForCondition(t, "report expiry", func() bool {
		_, ok := s.cache.Get(key.provider, key.model)
		return !ok
	})
	blocked = &attestation.VerificationReport{Factors: []attestation.FactorResult{{Name: attestation.FactorTEEQuotePresent, Status: attestation.Fail, Enforced: true}}}
	blockedPub, err := s.publishReport(t.Context(), prov, "model", key, s.reportEpoch(key), attestation.AdmissionTime{}, blocked, &attestation.RawAttestation{SigningKey: "blocked-key"})
	if err != nil {
		t.Fatal(err)
	}
	if blockedPub == oldPub {
		t.Fatalf("replacement published under the expired publication %d", oldPub)
	}
	return old, oldPub, blocked
}

// A success on a report that expired and was replaced by a new verification
// under the same invalidation epoch does not overwrite the replacement. A
// passing expired report must not replace a newer blocked one.
func TestReportVerificationSuccessOnExpiredReportKeepsReplacement(t *testing.T) {
	s, prov := newShortTTLReportTestServer(t, 200*time.Millisecond)
	old, oldPub, blocked := publishExpiredThenBlocked(t, s, prov)

	s.markReportE2EEUsable(providerModelKey{prov.Name, "model"}, oldPub, old)
	if got, ok := s.cache.Get(prov.Name, "model"); !ok || got != blocked || !got.Blocked() {
		t.Fatal("success on the expired report replaced the blocked replacement")
	}
	if key, ok := s.signingKeyCache.Get(prov.Name, "model"); ok {
		t.Fatalf("signing key %q is cached for a blocked report", key)
	}
}

// A late decryption failure on a report that expired and was replaced does
// not remove the replacement or change the invalidation epoch.
func TestReportVerificationFailureOnExpiredReportKeepsReplacement(t *testing.T) {
	s, prov := newShortTTLReportTestServer(t, 200*time.Millisecond)
	_, oldPub, blocked := publishExpiredThenBlocked(t, s, prov)
	key := providerModelKey{prov.Name, "model"}

	logs := captureSlog(t, func() {
		s.handleE2EEDecryptionFailure(t.Context(), prov, "model", oldPub, &modelStats{}, false, "", errors.New("decrypt error"))
	})
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "current report kept") || strings.Contains(logs, "caches invalidated") {
		t.Fatalf("late failure diagnostic:\n%s", logs)
	}
	if got, ok := s.cache.Get(prov.Name, "model"); !ok || got != blocked {
		t.Fatal("late failure on the expired report removed the replacement")
	}
	if s.reportEpoch(key) != 0 {
		t.Fatal("late failure on the expired report changed the invalidation epoch")
	}
	if _, failed := s.e2eeFailed.Load(key); failed {
		t.Fatal("late failure on the expired report recorded an E2EE failure")
	}
}

// Requests A and B use the same report publication. A succeeds and replaces
// the cached report with an annotated copy. A decryption failure on B still
// applies to the current publication and invalidates it.
func TestReportVerificationFailureAfterSiblingSuccessInvalidates(t *testing.T) {
	s, prov := newReportTestServer(t, newHeldReportAttester(nil))
	key := providerModelKey{prov.Name, "model"}
	used := &attestation.VerificationReport{Factors: []attestation.FactorResult{{Name: attestation.FactorE2EEUsable, Status: attestation.Skip}}}
	usedPub := publishTestReport(s, key, used)
	s.signingKeyCache.Put(key.provider, key.model, "used-key")

	arA, status := s.attestAndCache(t.Context(), httptest.NewRecorder(), prov, "model", &modelStats{})
	if status != "" {
		t.Fatalf("request A: status=%q", status)
	}
	arB, status := s.attestAndCache(t.Context(), httptest.NewRecorder(), prov, "model", &modelStats{})
	if status != "" {
		t.Fatalf("request B: status=%q", status)
	}
	if arA.Publication != usedPub || arB.Publication != usedPub {
		t.Fatalf("request publications = %d, %d, want %d", arA.Publication, arB.Publication, usedPub)
	}
	s.markReportE2EEUsable(key, arA.Publication, arA.Report)
	if got, _ := s.cache.Get(key.provider, key.model); got == arB.Report {
		t.Fatal("success did not replace the cached report")
	}

	logs := captureSlog(t, func() {
		s.handleE2EEDecryptionFailure(t.Context(), prov, "model", arB.Publication, &modelStats{}, false, "", errors.New("decrypt error"))
	})
	if !strings.Contains(logs, "caches invalidated") {
		t.Fatalf("failure after a sibling success did not invalidate:\n%s", logs)
	}
	if _, failed := s.e2eeFailed.Load(key); !failed {
		t.Fatal("failure after a sibling success recorded no E2EE failure")
	}
	if _, ok := s.cache.Get(key.provider, key.model); ok {
		t.Fatal("failure after a sibling success kept the report")
	}
	if _, ok := s.signingKeyCache.Get(key.provider, key.model); ok {
		t.Fatal("failure after a sibling success kept the signing key")
	}
	if got := s.reportEpoch(key); got != 1 {
		t.Fatalf("epoch = %d, want 1", got)
	}
}

// A decryption failure on an earlier publication does not remove the current
// report, its signing key, or the epoch.
func TestReportVerificationLateDecryptionFailureKeepsNewReport(t *testing.T) {
	for _, chutes := range []bool{false, true} {
		t.Run(fmt.Sprintf("chutes=%v", chutes), func(t *testing.T) {
			s, prov := newReportTestServer(t, newHeldReportAttester(nil))
			key := providerModelKey{prov.Name, "model"}
			earlierPub := publishTestReport(s, key, &attestation.VerificationReport{})
			current := &attestation.VerificationReport{}
			currentPub := publishTestReport(s, key, current)
			s.signingKeyCache.Put(key.provider, key.model, "current-key")
			var status string
			logs := captureSlog(t, func() {
				status = s.handleE2EEDecryptionFailure(t.Context(), prov, "model", earlierPub, &modelStats{}, chutes, "", errors.New("decrypt error"))
			})
			if status != "e2ee_decrypt_failed" {
				t.Fatalf("status=%q, want e2ee_decrypt_failed", status)
			}
			if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "current report kept") || strings.Contains(logs, "caches invalidated") {
				t.Fatalf("late failure diagnostic:\n%s", logs)
			}
			if got, _ := s.cache.Get(key.provider, key.model); got != current {
				t.Fatal("late failure removed the current report")
			}
			if got, ok := s.signingKeyCache.Get(key.provider, key.model); !ok || got != "current-key" {
				t.Fatal("late failure removed the current signing key")
			}
			if s.reportEpoch(key) != 0 {
				t.Fatal("late failure invalidated the current report")
			}
			if _, failed := s.e2eeFailed.Load(key); failed {
				t.Fatal("late failure recorded an E2EE failure")
			}

			// A failure on the current publication invalidates it.
			s.handleE2EEDecryptionFailure(t.Context(), prov, "model", currentPub, &modelStats{}, chutes, "", errors.New("decrypt error"))
			if _, ok := s.cache.Get(key.provider, key.model); ok {
				t.Fatal("failure on the current report did not delete it")
			}
			if _, ok := s.signingKeyCache.Get(key.provider, key.model); ok {
				t.Fatal("failure on the current report did not delete its signing key")
			}
			if s.reportEpoch(key) != 1 {
				t.Fatal("failure on the current report did not increment the epoch")
			}
			if _, failed := s.e2eeFailed.Load(key); failed == chutes {
				t.Fatalf("chutes=%v: E2EE failure recorded=%v", chutes, failed)
			}
		})
	}
}

// A late decryption failure on an invalidated publication does not stop the
// verification of the next epoch, which runs while the cache is empty.
func TestReportVerificationLateFailureKeepsVerificationInFlight(t *testing.T) {
	attester := newHeldReportAttester(nil)
	s, prov := newReportTestServer(t, attester)
	key := providerModelKey{prov.Name, "model"}
	usedPub := publishTestReport(s, key, &attestation.VerificationReport{})
	s.handleE2EEDecryptionFailure(t.Context(), prov, "model", usedPub, &modelStats{}, false, "", errors.New("decrypt error"))

	type loaded struct {
		report      *attestation.VerificationReport
		publication uint64
		err         error
	}
	done := make(chan loaded, 1)
	go func() {
		report, _, publication, err := s.loadReport(t.Context(), prov, "model")
		done <- loaded{report, publication, err}
	}()
	waitForCondition(t, "verification of the next epoch", func() bool { return attester.calls.Load() == 1 })
	logs := captureSlog(t, func() {
		s.handleE2EEDecryptionFailure(t.Context(), prov, "model", usedPub, &modelStats{}, false, "", errors.New("decrypt error"))
	})
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "current report kept") {
		t.Fatalf("late failure diagnostic missing:\n%s", logs)
	}
	close(attester.release)
	got := <-done
	if got.err != nil {
		t.Fatalf("late failure stopped the verification in flight: %v", got.err)
	}
	if got.publication == usedPub || s.reportEpoch(key) != 1 {
		t.Fatalf("report publication = %d (invalidated %d), epoch = %d, want a new publication and epoch 1", got.publication, usedPub, s.reportEpoch(key))
	}
	if cached, pub, ok := s.cache.GetPublication(key.provider, key.model); !ok || cached != got.report || pub != got.publication {
		t.Fatal("report cache does not hold the report of the verification in flight")
	}
	// A shared verification that finds the published report returns its
	// publication without a fetch.
	report, _, pub, err := s.loadReport(t.Context(), prov, "model")
	if err != nil || report != got.report || pub != got.publication || attester.calls.Load() != 1 {
		t.Fatalf("cached shared result: same report=%v publication=%d fetches=%d err=%v", report == got.report, pub, attester.calls.Load(), err)
	}
}

// A shared verification rechecks the time eligibility of its verified NRAS
// evidence under the publication lock, as the authorization store does. A
// report whose NRAS evidence expired before publication is not published, and
// its waiters get a failed verification.
func TestReportVerificationNRASAdmissionBeforePublication(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	admission := testNRASAdmission(t, now)
	for _, delayed := range []bool{false, true} {
		t.Run(fmt.Sprintf("delayed=%v", delayed), func(t *testing.T) {
			s, prov := newReportTestServer(t, newHeldReportAttester(nil))
			// Force gives a passing report, which writes the signing key and
			// clears the E2EE failure when it publishes.
			s.cfg.Force = true
			key := providerModelKey{prov.Name, "model"}
			s.e2eeFailed.Store(key, true)
			at := now
			if delayed {
				at = now.Add(time.Hour + 10*time.Second)
			}
			s.authorizations.now = func() time.Time { return at }
			var err error
			logs := captureSlog(t, func() {
				_, err = s.publishReport(t.Context(), prov, "model", key, s.reportEpoch(key), admission,
					&attestation.VerificationReport{}, &attestation.RawAttestation{SigningKey: "attested-key"})
			})
			_, cached := s.cache.Get(key.provider, key.model)
			_, keyCached := s.signingKeyCache.Get(key.provider, key.model)
			_, failed := s.e2eeFailed.Load(key)
			if !delayed {
				if err != nil || !cached || !keyCached || failed {
					t.Fatalf("eligible evidence: err=%v report=%v key=%v failure kept=%v", err, cached, keyCached, failed)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "expired") {
				t.Fatalf("expired NRAS evidence was published: err=%v", err)
			}
			if cached || keyCached {
				t.Fatalf("expired NRAS evidence cached: report=%v key=%v", cached, keyCached)
			}
			if !failed {
				t.Fatal("unpublished report cleared the E2EE failure")
			}
			if got := strings.Count(logs, "level=WARN"); got != 1 || !strings.Contains(logs, "not time eligible") {
				t.Fatalf("warnings = %d, want 1 time eligibility warning:\n%s", got, logs)
			}
			// A waiter reports the publication error as a failed verification.
			if status := writeReportLoadError(t.Context(), httptest.NewRecorder(), prov, "model", err); status != "attest_failed" {
				t.Fatalf("waiter status = %q, want attest_failed", status)
			}
		})
	}
}
