package proxy

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/venice"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

const publicationTestBody = `{"model":"model","messages":[{"role":"user","content":"hello"}],"stream":true}`

// newVeniceSigningKey returns the hex of a new uncompressed secp256k1 public
// key, which the production Venice encryptor accepts as a signing key.
func newVeniceSigningKey(t *testing.T) string {
	t.Helper()
	key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(key.PubKey().SerializeUncompressed())
}

// keyAttester returns attestation that echoes the nonce and names key.
type keyAttester struct{ key string }

func (a keyAttester) FetchAttestation(_ context.Context, _ string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	return &attestation.RawAttestation{Nonce: nonce.Hex(), NonceSource: "client", SigningKey: a.key, IntelQuote: testQuote}, nil
}

// publicationUpstream is a Venice E2EE upstream. It records the model key of
// each request. If decrypt is true, it encrypts its reply to the client key of
// the request; otherwise it replies with plaintext content, which the proxy
// must treat as a decryption failure.
type publicationUpstream struct {
	decrypt bool
	mu      sync.Mutex
	keys    []string
}

func (u *publicationUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.keys = append(u.keys, r.Header.Get("X-Venice-Tee-Model-Pub-Key"))
	u.mu.Unlock()
	content := "plaintext"
	if u.decrypt {
		raw, err := hex.DecodeString(r.Header.Get("X-Venice-Tee-Client-Pub-Key"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		clientKey, err := secp256k1.ParsePubKey(raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if content, err = e2ee.EncryptVenice([]byte("hello"), clientKey); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "text/event-stream")
	_, _ = w.Write([]byte(`data: {"id":"c","object":"chat.completion.chunk","created":1,"model":"model","choices":[{"index":0,"delta":{"role":"assistant","content":"` + content + `"},"finish_reason":null}]}` + "\n\ndata: [DONE]\n\n"))
}

func (u *publicationUpstream) modelKeys() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.keys...)
}

// newPublicationTestServer builds the report test server for the production
// Venice E2EE encryptor and a TLS upstream that the production client trusts.
func newPublicationTestServer(t *testing.T, authority *testtls.Authority, attester provider.Attester, upstream http.Handler) (*Server, *provider.Provider) {
	t.Helper()
	s, prov := newReportTestServer(t, attester)
	prov.E2EE = true
	prov.Encryptor = venice.NewE2EE()
	prov.BaseURL = authority.NewTLSServer(t, upstream).URL
	return s, prov
}

// relayPublicationRequest enforces the cached report for a request and relays
// the request, as endpointHandler does.
func relayPublicationRequest(t *testing.T, s *Server, prov *provider.Provider) (*attestResult, relayResult) {
	t.Helper()
	ar, status := s.attestAndCache(t.Context(), httptest.NewRecorder(), prov, "model", &modelStats{})
	if status != "" || !ar.E2EEActive {
		t.Fatalf("attestation status=%q e2ee=%v", status, ar.E2EEActive)
	}
	return ar, relayPublicationAttempt(t, s, prov, ar)
}

func relayPublicationAttempt(t *testing.T, s *Server, prov *provider.Provider, ar *attestResult) relayResult {
	t.Helper()
	return s.relayWithRetry(t.Context(), httptest.NewRecorder(), prov, "model", []byte(publicationTestBody), ar,
		&modelStats{}, true, "/api/v1/chat/completions", e2ee.EndpointChat, "application/json")
}

// checkPublicationInvalidated checks that a decryption failure ended the
// current publication: the report, the key, the failure flag and the epoch.
func checkPublicationInvalidated(t *testing.T, s *Server, key providerModelKey, epoch uint64) {
	t.Helper()
	if _, ok := s.cache.Get(key.provider, key.model); ok {
		t.Error("the report of the failed key is still cached")
	}
	if _, ok := s.signingKeyCache.Get(key.provider, key.model); ok {
		t.Error("the failed key is still cached")
	}
	if _, failed := s.e2eeFailed.Load(key); !failed {
		t.Error("the decryption failure was not recorded")
	}
	if got := s.reportEpoch(key); got != epoch+1 {
		t.Errorf("report epoch = %d, want %d", got, epoch+1)
	}
}

// A cached report without a key starts a verification that publishes a new
// report and key. A decryption failure under that key ends the new
// publication.
func TestBuildUpstreamBodyKeyMissFailureInvalidatesKeyPublication(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		signingKey := newVeniceSigningKey(t)
		upstream := &publicationUpstream{}
		s, prov := newPublicationTestServer(t, authority, keyAttester{signingKey}, upstream)
		// The test evidence fails TDX. The force policy gives a report that passes.
		bindTestEvidence(s, prov)
		key := providerModelKey{prov.Name, "model"}
		oldPub := publishTestReport(s, key, bindingReport())
		epoch := s.reportEpoch(key)

		ar, rr := relayPublicationRequest(t, s, prov)
		if rr.status != "e2ee_decrypt_failed" {
			t.Fatalf("status = %q, want e2ee_decrypt_failed", rr.status)
		}
		if got := upstream.modelKeys(); len(got) != 1 || got[0] != signingKey {
			t.Fatalf("model keys = %v, want the verified key", got)
		}
		if ar.Publication == oldPub {
			t.Error("request outcome carries the publication that had no key")
		}
		checkPublicationInvalidated(t, s, key, epoch)
	})
}

// A verification publishes a new report and key after a request enforced its
// cached report and before it read the key. The request uses the new key, so
// its outcome carries the new publication, and a decryption failure ends it.
func TestBuildUpstreamBodyCacheHitUsesKeyPublication(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		upstream := &publicationUpstream{}
		s, prov := newPublicationTestServer(t, authority, &mockAttester{err: errors.New("unexpected fetch")}, upstream)
		key := providerModelKey{prov.Name, "model"}
		oldKey, newKey := newVeniceSigningKey(t), newVeniceSigningKey(t)
		publish := func(signingKey string) (*attestation.VerificationReport, uint64) {
			report := bindingReport()
			pub, err := s.publishReport(t.Context(), prov, "model", key, s.reportEpoch(key), attestation.AdmissionTime{}, report, &attestation.RawAttestation{SigningKey: signingKey})
			if err != nil {
				t.Fatal(err)
			}
			return report, pub
		}
		_, oldPub := publish(oldKey)
		ar, status := s.attestAndCache(t.Context(), httptest.NewRecorder(), prov, "model", &modelStats{})
		if status != "" || ar.Publication != oldPub {
			t.Fatalf("attestation status=%q publication=%d, want %d", status, ar.Publication, oldPub)
		}
		newReport, newPub := publish(newKey)
		epoch := s.reportEpoch(key)

		rr := relayPublicationAttempt(t, s, prov, ar)
		if rr.status != "e2ee_decrypt_failed" {
			t.Fatalf("status = %q, want e2ee_decrypt_failed", rr.status)
		}
		if got := upstream.modelKeys(); len(got) != 1 || got[0] != newKey {
			t.Fatalf("model keys = %v, want the new key", got)
		}
		if ar.Publication != newPub || ar.Report != newReport {
			t.Errorf("request outcome publication = %d, want %d of the key used", ar.Publication, newPub)
		}
		checkPublicationInvalidated(t, s, key, epoch)
	})
}

// A request that succeeds with a key that a verification published during the
// request marks the publication of that key as E2EE usable.
func TestBuildUpstreamBodySuccessMarksKeyPublication(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		signingKey := newVeniceSigningKey(t)
		upstream := &publicationUpstream{decrypt: true}
		s, prov := newPublicationTestServer(t, authority, keyAttester{signingKey}, upstream)
		// The test evidence fails TDX. The force policy gives a report that passes.
		bindTestEvidence(s, prov)
		key := providerModelKey{prov.Name, "model"}
		oldPub := publishTestReport(s, key, bindingReport())

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", strings.NewReader(strings.Replace(publicationTestBody, `"model":"model"`, `"model":"venice:model"`, 1)))
		req.Header.Set("Content-Type", "application/json")
		s.ServeHTTP(w, req)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "hello") {
			t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
		}
		if got := upstream.modelKeys(); len(got) != 1 || got[0] != signingKey {
			t.Fatalf("model keys = %v, want the verified key", got)
		}
		report, pub, ok := s.cache.GetPublication(key.provider, key.model)
		if !ok || pub == oldPub {
			t.Fatal("the verification did not publish a report")
		}
		if e2eeUsableStatus(report) != attestation.Pass {
			t.Error("success did not mark the publication of the key that the request used")
		}
	})
}

// A passing publication without a signing key deletes the key of the earlier
// publication. A request on the new publication must not encrypt to the
// earlier key; it starts full verification, which fails here.
func TestReportVerificationPassWithoutKeyDropsEarlierKey(t *testing.T) {
	s, prov := newReportTestServer(t, &mockAttester{err: errors.New("attestation endpoint unavailable")})
	prov.E2EE = true
	enc := &recordingEncryptor{}
	prov.Encryptor = enc
	key := providerModelKey{prov.Name, "model"}
	publish := func(signingKey string) {
		if _, err := s.publishReport(t.Context(), prov, "model", key, s.reportEpoch(key), attestation.AdmissionTime{}, bindingReport(), &attestation.RawAttestation{SigningKey: signingKey}); err != nil {
			t.Fatal(err)
		}
	}
	publish(newVeniceSigningKey(t))
	publish("")

	if current, ok := s.currentSigningKey(key); ok {
		t.Fatalf("publication without a key has key %q from an earlier publication", current.signingKey)
	}
	if _, err := s.buildUpstreamBody(t.Context(), []byte(`{}`), "model", true, prov, nil, e2ee.EndpointChat); err == nil {
		t.Fatal("request on a publication without a key was not blocked")
	}
	if got := enc.encrypted(); len(got) != 0 {
		t.Fatalf("request was encrypted to %v", got)
	}
}

// An operator allow_fail list that excuses tee_reportdata_binding lets a
// report whose binding failed pass enforcement. REPORTDATA does not bind its
// signing key, so the publication caches no key. A request that enforced an
// earlier report with a bound key must not encrypt to the earlier key or to
// the unbound key; it fails closed.
func TestReportVerificationAllowedBindingFailureCachesNoKey(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		boundKey, unboundKey := newVeniceSigningKey(t), newVeniceSigningKey(t)
		upstream := &publicationUpstream{}
		s, prov := newPublicationTestServer(t, authority, keyAttester{unboundKey}, upstream)
		// The allow_fail policy is the subject of this test.
		s.cfg.ProviderAllowFail = map[string][]string{prov.Name: append([]string(nil), attestation.KnownFactors...)}
		key := providerModelKey{prov.Name, "model"}
		if _, err := s.publishReport(t.Context(), prov, "model", key, s.reportEpoch(key), attestation.AdmissionTime{}, bindingReport(), &attestation.RawAttestation{SigningKey: boundKey}); err != nil {
			t.Fatal(err)
		}
		ar, status := s.attestAndCache(t.Context(), httptest.NewRecorder(), prov, "model", &modelStats{})
		if status != "" || !ar.E2EEActive {
			t.Fatalf("attestation status=%q e2ee=%v", status, ar.E2EEActive)
		}

		// The cached report expires, and a new verification publishes a report
		// whose REPORTDATA binding failed.
		s.reportMu.Lock()
		s.cache.Delete(key.provider, key.model)
		s.reportMu.Unlock()
		report, _, _, err := s.loadReport(t.Context(), prov, "model")
		if err != nil {
			t.Fatal(err)
		}
		if report.Blocked() || report.ReportDataBindingPassed() {
			t.Fatalf("report blocked=%v binding passed=%v, want an allowed binding failure", report.Blocked(), report.ReportDataBindingPassed())
		}
		if cached, ok := s.signingKeyCache.Get(key.provider, key.model); ok {
			t.Fatalf("publication with a failed binding cached key %q", cached)
		}

		rr := relayPublicationAttempt(t, s, prov, ar)
		if rr.status != "e2ee_failed" {
			t.Fatalf("status = %q, want e2ee_failed", rr.status)
		}
		if got := upstream.modelKeys(); len(got) != 0 {
			t.Fatalf("model keys = %v, want no upstream request", got)
		}

		// A cached key does not pair with a report whose binding failed.
		s.signingKeyCache.Put(key.provider, key.model, unboundKey)
		if current, ok := s.currentSigningKey(key); ok {
			t.Fatalf("report with a failed binding has key %q", current.signingKey)
		}
	})
}
