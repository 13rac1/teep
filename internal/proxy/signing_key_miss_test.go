package proxy

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
)

// tdxReportDataOffset is the offset of REPORTDATA in a TDX v4 quote: a
// 48-byte header and 520 bytes of the TD report body before it.
const tdxReportDataOffset = 568

// forgedQuoteAttester returns a TDX quote that parses but whose signature is
// not valid: it is a real production quote with REPORTDATA replaced, so that
// REPORTDATA binds the request nonce and a signing key that the provider
// chose.
type forgedQuoteAttester struct {
	quote []byte
	key   []byte
	mu    sync.Mutex
	calls int
}

func newForgedQuoteAttester(t *testing.T) *forgedQuoteAttester {
	t.Helper()
	quote, err := os.ReadFile("../attestation/testdata/tdx_prod_quote_SPR_E4.dat")
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 65)
	key[0] = 0x04
	for i := 1; i < len(key); i++ {
		key[i] = byte(i)
	}
	return &forgedQuoteAttester{quote: quote, key: key}
}

func (a *forgedQuoteAttester) FetchAttestation(_ context.Context, _ string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()
	quote := append([]byte(nil), a.quote...)
	h := sha3.NewLegacyKeccak256()
	h.Write(a.key[1:])
	reportData := quote[tdxReportDataOffset : tdxReportDataOffset+64]
	clear(reportData)
	copy(reportData[:20], h.Sum(nil)[12:])
	copy(reportData[32:], nonce[:])
	return &attestation.RawAttestation{
		Nonce:       nonce.Hex(),
		NonceSource: "client",
		SigningKey:  hex.EncodeToString(a.key),
		IntelQuote:  hex.EncodeToString(quote),
	}, nil
}

func (a *forgedQuoteAttester) fetches() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

// recordingEncryptor records the signing key of each request that it encrypts.
type recordingEncryptor struct {
	mu   sync.Mutex
	keys []string
}

func (e *recordingEncryptor) EncryptRequest(_ []byte, raw *attestation.RawAttestation, _ e2ee.EndpointType) (e2ee.EncryptResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.keys = append(e.keys, raw.SigningKey)
	return e2ee.EncryptResult{Body: []byte("encrypted")}, nil
}

func (e *recordingEncryptor) encrypted() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.keys...)
}

// bindingReport returns a passing report whose REPORTDATA binding passed, so
// that a request uses E2EE with it.
func bindingReport() *attestation.VerificationReport {
	return &attestation.VerificationReport{Factors: []attestation.FactorResult{{Name: attestation.FactorTEEReportData, Status: attestation.Pass}}}
}

// newKeyMissTestServer builds a report test server for an E2EE provider with
// a recording encryptor and a cached passing report but no signing key.
func newKeyMissTestServer(t *testing.T, attester provider.Attester) (*Server, *provider.Provider, *recordingEncryptor, uint64) {
	t.Helper()
	s, prov := newReportTestServer(t, attester)
	prov.E2EE = true
	enc := &recordingEncryptor{}
	prov.Encryptor = enc
	pub := publishTestReport(s, providerModelKey{prov.Name, "model"}, bindingReport())
	return s, prov, enc, pub
}

// A report cache hit without a cached signing key must not accept a key from
// attestation that was not fully verified. The quote parses and REPORTDATA
// binds the nonce and the key, but the signature is not valid.
func TestBuildUpstreamBodyKeyMissRejectsUnverifiedQuote(t *testing.T) {
	attester := newForgedQuoteAttester(t)
	nonce := attestation.NewNonce()
	forged, err := attester.FetchAttestation(t.Context(), "model", nonce)
	if err != nil {
		t.Fatal(err)
	}
	tdx := attestation.VerifyTDXQuoteOffline(t.Context(), forged.IntelQuote, time.Time{})
	if tdx.ParseErr != nil || tdx.SignatureErr == nil {
		t.Fatalf("forged quote: parse=%v signature=%v", tdx.ParseErr, tdx.SignatureErr)
	}
	attester.calls = 0

	s, prov, enc, pub := newKeyMissTestServer(t, attester)
	if _, err := prov.ReportDataVerifier.VerifyReportData(tdx.ReportData, forged, nonce); err != nil {
		t.Fatalf("forged quote does not bind the nonce and key: %v", err)
	}
	logs := captureSlog(t, func() {
		_, err = s.buildUpstreamBody(t.Context(), []byte(`{}`), "model", true, prov, nil, e2ee.EndpointChat)
	})
	if err == nil {
		t.Fatal("request with an unverified signing key was not blocked")
	}
	if key, ok := s.signingKeyCache.Get(prov.Name, "model"); ok {
		t.Fatalf("unverified signing key %q was cached", key)
	}
	if got := enc.encrypted(); len(got) != 0 {
		t.Fatalf("request was encrypted to %v", got)
	}
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "request blocked") {
		t.Fatalf("block was not logged at WARN:\n%s", logs)
	}
	report, newPub, ok := s.cache.GetPublication(prov.Name, "model")
	if !ok || newPub == pub || !report.Blocked() {
		t.Fatal("full verification did not publish the blocked report")
	}
	if attester.fetches() != 1 {
		t.Fatalf("attestation fetches = %d, want 1", attester.fetches())
	}
}

// Concurrent requests that find the report but no signing key share one full
// verification and use the key that it publishes.
func TestBuildUpstreamBodyKeyMissUsesPublishedKey(t *testing.T) {
	attester := newHeldReportAttester(nil)
	s, prov, enc, pub := newKeyMissTestServer(t, attester)
	// The test evidence fails TDX. The force policy gives a report that passes.
	bindTestEvidence(s, prov)
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	logs := captureSlog(t, func() {
		for range n {
			wg.Go(func() {
				_, err := s.buildUpstreamBody(t.Context(), []byte(`{}`), "model", true, prov, nil, e2ee.EndpointChat)
				errs <- err
			})
		}
		waitForCondition(t, "shared fetch", func() bool { return attester.calls.Load() == 1 })
		close(attester.release)
		wg.Wait()
	})
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
	}
	got := enc.encrypted()
	if len(got) != n {
		t.Fatalf("encrypted requests = %d, want %d", len(got), n)
	}
	for _, key := range got {
		if key != "attested-key" {
			t.Fatalf("request used key %q, want the published key", key)
		}
	}
	if key, _ := s.signingKeyCache.Get(prov.Name, "model"); key != "attested-key" {
		t.Fatalf("cached key = %q", key)
	}
	if _, newPub, _ := s.cache.GetPublication(prov.Name, "model"); newPub == pub {
		t.Fatal("full verification did not publish a report")
	}
	if attester.calls.Load() != 1 || !strings.Contains(logs, "shared attestation verification started") {
		t.Fatalf("attestation fetches = %d, want 1 shared verification", attester.calls.Load())
	}
}

// A signing key that expires before its report is a cache miss: the request
// starts full verification and does not fetch attestation on its own.
func TestBuildUpstreamBodyKeyExpiryStartsVerification(t *testing.T) {
	attester := &mockAttester{}
	s, prov := newReportTestServer(t, attester)
	prov.E2EE = true
	prov.Encryptor = &recordingEncryptor{}
	s.signingKeyCache = attestation.NewSigningKeyCache(50 * time.Millisecond)
	key := providerModelKey{prov.Name, "model"}
	pub, err := s.publishReport(t.Context(), prov, "model", key, s.reportEpoch(key), attestation.AdmissionTime{}, bindingReport(), &attestation.RawAttestation{SigningKey: "old-key"})
	if err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, "signing key expiry", func() bool {
		_, ok := s.signingKeyCache.Get(key.provider, key.model)
		return !ok
	})

	_, err = s.buildUpstreamBody(t.Context(), []byte(`{}`), "model", true, prov, nil, e2ee.EndpointChat)
	// The default policy blocks the test evidence, so no key is published.
	if err == nil || !strings.Contains(err.Error(), "no verified signing key") {
		t.Fatalf("err = %v, want no verified signing key", err)
	}
	report, newPub, ok := s.cache.GetPublication(key.provider, key.model)
	if !ok || newPub == pub || !report.Blocked() {
		t.Fatal("key expiry did not start full verification")
	}
	if _, ok := s.signingKeyCache.Get(key.provider, key.model); ok {
		t.Fatal("a signing key was cached for a blocked report")
	}
}

// A verification error blocks the request and caches no key.
func TestBuildUpstreamBodyKeyMissVerificationError(t *testing.T) {
	s, prov, enc, _ := newKeyMissTestServer(t, &mockAttester{err: errors.New("attester network error")})
	var err error
	logs := captureSlog(t, func() {
		_, err = s.buildUpstreamBody(t.Context(), []byte(`{}`), "model", true, prov, nil, e2ee.EndpointChat)
	})
	if err == nil || !strings.Contains(err.Error(), "verify signing key") {
		t.Fatalf("err = %v, want a verification error", err)
	}
	if !strings.Contains(logs, "verification for the signing key failed; request blocked") {
		t.Fatalf("block was not logged:\n%s", logs)
	}
	if len(enc.encrypted()) != 0 {
		t.Fatal("request was encrypted")
	}
}

// newChutesKeyMissTestServer builds the production Chutes provider with the
// test attester, the test nonce pool, and a recording encryptor. The cache
// holds a passing report and the signing key cachedKey.
func newChutesKeyMissTestServer(t *testing.T, attester provider.Attester, fetcher *mockE2EEMaterialFetcher, cachedKey string) (*Server, *provider.Provider, *recordingEncryptor, uint64) {
	t.Helper()
	s, err := New(&config.Config{Offline: true, Providers: map[string]*config.Provider{"chutes": {Name: "chutes", BaseURL: "https://chutes.test", APIKey: "test-key", E2EE: true}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	prov := s.providers["chutes"]
	if prov.E2EEMaterialFetcher == nil || !prov.SkipSigningKeyCache {
		t.Fatal("test provider must use a nonce pool")
	}
	prov.Attester = attester
	prov.E2EEMaterialFetcher = fetcher
	enc := &recordingEncryptor{}
	prov.Encryptor = enc
	key := providerModelKey{prov.Name, "model"}
	pub, err := s.publishReport(t.Context(), prov, "model", key, s.reportEpoch(key), attestation.AdmissionTime{}, bindingReport(), &attestation.RawAttestation{SigningKey: cachedKey})
	if err != nil {
		t.Fatal(err)
	}
	return s, prov, enc, pub
}

// A nonce pool key mismatch or fetch failure deletes the stale signing key and
// starts full verification. The mismatch also invalidates the pool for the
// chute.
func TestBuildUpstreamBodyChutesPoolFailureStartsVerification(t *testing.T) {
	tests := []struct {
		name    string
		fetcher *mockE2EEMaterialFetcher
	}{
		{"key mismatch", &mockE2EEMaterialFetcher{material: &provider.E2EEMaterial{E2EPubKey: "pool-key", InstanceID: "inst-1", E2ENonce: "nonce", ChuteID: "chute-1"}}},
		{"fetch failure", &mockE2EEMaterialFetcher{err: errors.New("pool fetch failed")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attester := newHeldReportAttester(nil)
			close(attester.release)
			s, prov, enc, pub := newChutesKeyMissTestServer(t, attester, tt.fetcher, "cached-key")
			_, err := s.buildUpstreamBody(t.Context(), []byte(`{}`), "model", true, prov, nil, e2ee.EndpointChat)
			// The default policy blocks the test evidence, so no key is published.
			if err == nil || !strings.Contains(err.Error(), "no verified signing key") {
				t.Fatalf("err = %v, want no verified signing key", err)
			}
			if attester.calls.Load() != 1 {
				t.Fatalf("attestation fetches = %d, want 1", attester.calls.Load())
			}
			if _, newPub, _ := s.cache.GetPublication(prov.Name, "model"); newPub == pub {
				t.Fatal("pool failure did not start full verification")
			}
			if key, ok := s.signingKeyCache.Get(prov.Name, "model"); ok {
				t.Fatalf("stale signing key %q is still cached", key)
			}
			if len(enc.encrypted()) != 0 {
				t.Fatal("request was encrypted")
			}
			wantInvalidated := 0
			if tt.fetcher.err == nil {
				wantInvalidated = 1
			}
			if len(tt.fetcher.invalidated) != wantInvalidated {
				t.Fatalf("pool invalidations = %v, want %d", tt.fetcher.invalidated, wantInvalidated)
			}
		})
	}
}

// A Chutes pool mismatch whose full verification passes uses the verified
// attestation for the request.
func TestBuildUpstreamBodyChutesPoolMismatchUsesVerifiedAttestation(t *testing.T) {
	attester := newHeldReportAttester(nil)
	close(attester.release)
	fetcher := &mockE2EEMaterialFetcher{material: &provider.E2EEMaterial{E2EPubKey: "pool-key", ChuteID: "chute-1"}}
	s, prov, enc, _ := newChutesKeyMissTestServer(t, attester, fetcher, "cached-key")
	// The test evidence fails TDX. The force policy gives a report that passes.
	bindTestEvidence(s, prov)
	if _, err := s.buildUpstreamBody(t.Context(), []byte(`{}`), "model", true, prov, nil, e2ee.EndpointChat); err != nil {
		t.Fatal(err)
	}
	if got := enc.encrypted(); len(got) != 1 || got[0] != "attested-key" {
		t.Fatalf("encrypted with %v, want the verified key", got)
	}
}

// A request deletes a stale key only if the cache still holds it, so a key
// that a later verification published stays, and the shared verification
// returns the cached report without a fetch. A Chutes request that does not
// receive the verified instance and nonce fails, and its retry uses the pool.
func TestLoadSigningKeyKeepsReplacementKey(t *testing.T) {
	t.Run("venice", func(t *testing.T) {
		attester := &mockAttester{err: errors.New("unexpected fetch")}
		s, prov, _, pub := newKeyMissTestServer(t, attester)
		s.signingKeyCache.Put(prov.Name, "model", "new-key")
		raw, _, err := s.loadSigningKey(t.Context(), prov, "model", keyPublication{signingKey: "old-key", publication: pub})
		if err != nil || raw.SigningKey != "new-key" {
			t.Fatalf("raw=%v err=%v, want the replacement key", raw, err)
		}
	})
	t.Run("chutes", func(t *testing.T) {
		attester := newHeldReportAttester(nil)
		s, prov, _, pub := newChutesKeyMissTestServer(t, attester, &mockE2EEMaterialFetcher{}, "new-key")
		_, _, err := s.loadSigningKey(t.Context(), prov, "model", keyPublication{signingKey: "old-key", publication: pub})
		if err == nil || !strings.Contains(err.Error(), "went to another request") {
			t.Fatalf("err = %v, want material for another request", err)
		}
		if key, _ := s.signingKeyCache.Get(prov.Name, "model"); key != "new-key" {
			t.Fatalf("cached key = %q, want the replacement key", key)
		}
		if attester.calls.Load() != 0 {
			t.Fatal("complete cached report started a fetch")
		}
	})
}

// A request that read a key with publication A must not delete the key of a
// later publication B, also when B published the same key bytes while the
// request waited for the nonce pool.
func TestLoadSigningKeyKeepsSameKeyOfReplacementPublication(t *testing.T) {
	attester := newHeldReportAttester(nil)
	close(attester.release)
	s, prov, _, _ := newChutesKeyMissTestServer(t, attester, &mockE2EEMaterialFetcher{}, "attested-key")
	key := providerModelKey{prov.Name, "model"}
	read, ok := s.currentSigningKey(key)
	if !ok {
		t.Fatal("no signing key for publication A")
	}
	// While the request waits for the nonce pool, a decryption failure ends
	// publication A and a new verification publishes B with the same key.
	s.handleE2EEDecryptionFailure(t.Context(), prov, "model", read.publication, &modelStats{}, true, "", errors.New("decrypt error"))
	replacement, err := s.publishReport(t.Context(), prov, "model", key, s.reportEpoch(key), attestation.AdmissionTime{}, bindingReport(), &attestation.RawAttestation{SigningKey: "attested-key"})
	if err != nil || replacement == read.publication {
		t.Fatalf("publication B = %d (A %d), err=%v", replacement, read.publication, err)
	}

	// The nonce pool failed, so the request starts or joins full verification
	// with the key that it read.
	_, _, err = s.loadSigningKey(t.Context(), prov, "model", read)
	if err == nil || !strings.Contains(err.Error(), "went to another request") {
		t.Fatalf("err = %v, want material for another request", err)
	}
	if cached, ok := s.signingKeyCache.Get(prov.Name, "model"); !ok || cached != "attested-key" {
		t.Fatalf("cached key = %q (present %v), want the key of publication B", cached, ok)
	}
	if current, ok := s.currentSigningKey(key); !ok || current.publication != replacement {
		t.Fatalf("current publication = %d (present %v), want B %d", current.publication, ok, replacement)
	}
	if attester.calls.Load() != 0 {
		t.Fatalf("attestation fetches = %d, want 0: publication B is complete", attester.calls.Load())
	}
}
