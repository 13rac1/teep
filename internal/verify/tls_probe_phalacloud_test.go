package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/e2ee/aciv2test"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/aci"
	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// pinnedSessionID stands for an attested session that the audit pinned.
const pinnedSessionID = "4d849e211f7078bd8d27a748a7ac0ddfe164d2ef5c0e29e6e30292a371276320"

// probeTimeout bounds one probe, so that a receipt GET that is not answered
// ends with the probe's context.
const probeTimeout = 2 * time.Second

// probeSessionExpires is the expires_at of the pinned session.
const probeSessionExpires = 1893456000

// probeGateway is the gateway side of TestStandalonePhalaCloudProbe: it
// answers the chat request and the receipt GET that follows it.
type probeGateway struct {
	t      *testing.T
	gw     *aciv2test.Gateway
	digest string
	calls  atomic.Int32
	// mu guards the fields below. A handler holds it while it runs, also
	// one that does not answer, so a test changes the case only between
	// requests.
	mu sync.Mutex
	// Per case: the served keyset digest ("" for the verified one), the
	// change to the signed receipt, no X-Receipt-Id, HTTP 404 on every
	// receipt GET, another HTTP status for the receipt GET, a receipt GET
	// that ends without an answer, one whose body is shorter than its
	// Content-Length, and one that does not answer before the probe's
	// deadline.
	served         string
	receipt        func(*aciv2test.Receipt)
	noReceiptID    bool
	receiptMissing bool
	receiptStatus  int
	receiptHangup  bool
	receiptShort   bool
	receiptStall   bool
	// streamResetAfterDone and streamResetAfterFirst reset the probe
	// stream after [DONE] or after its first content chunk.
	streamResetAfterDone  bool
	streamResetAfterFirst bool
	// streamNoDone ends the stream cleanly without [DONE]; streamBadTail
	// adds a chunk whose content is not ciphertext before [DONE]. The
	// receipt covers the stream the gateway built, unless signServed signs
	// it over the bytes served.
	streamNoDone  bool
	streamBadTail bool
	signServed    bool
	// refuse answers the chat request with session_not_accepted.
	refuse bool
	stream string
	signed string
}

func (p *probeGateway) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	p.calls.Add(1)
	p.mu.Lock()
	defer p.mu.Unlock()
	if req.Header.Get("Authorization") != "Bearer secret-api-key" {
		p.t.Errorf("request %s, Authorization %q", req.URL.Path, req.Header.Get("Authorization"))
	}
	if req.Method == http.MethodGet && req.URL.Path == aci.ReceiptsPath+"/rcpt-1" {
		if p.receiptHangup {
			// The server resets the stream or closes the connection.
			panic(http.ErrAbortHandler)
		}
		if p.receiptShort {
			w.Header().Set("Content-Length", strconv.Itoa(len(p.signed)+100))
			_, _ = io.WriteString(w, p.signed)
			return
		}
		if p.receiptStall {
			<-req.Context().Done()
			return
		}
		if p.receiptStatus != 0 {
			w.WriteHeader(p.receiptStatus)
			return
		}
		if p.receiptMissing || p.signed == "" {
			http.NotFound(w, req)
			return
		}
		_, _ = io.WriteString(w, p.signed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	if err != nil {
		p.t.Error(err)
		return
	}
	if req.URL.Path != "/v1/chat/completions" {
		p.t.Errorf("request %s", req.URL.Path)
	}
	var b struct {
		MaxTokens int `json:"max_tokens"`
		Messages  []struct {
			Content string `json:"content"`
		} `json:"messages"`
		Provider struct {
			ACISessionIDs []string `json:"aci_session_ids"`
		} `json:"provider"`
	}
	if err := json.Unmarshal(body, &b); err != nil || b.MaxTokens != aciv2ProbeMaxTokens || len(b.Messages) != 1 {
		p.t.Errorf("max_tokens = %d, %v", b.MaxTokens, err)
		return
	}
	if len(b.Provider.ACISessionIDs) != 1 || b.Provider.ACISessionIDs[0] != pinnedSessionID {
		p.t.Errorf("provider.aci_session_ids = %q, want the pinned session", b.Provider.ACISessionIDs)
	}
	if p.refuse {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPreconditionFailed)
		_, _ = io.WriteString(w, `{"error":{"message":"none of the requested attested sessions is available","type":"session_not_accepted","code":null,"param":null}}`)
		return
	}
	r := p.gw.ReadRequest(req.Header, body)
	built := p.gw.Stream(r, "chatcmpl-1", []string{"Hel", "lo"}, true)
	p.stream = built
	switch {
	case p.streamNoDone:
		p.stream = strings.TrimSuffix(built, "data: [DONE]\n\n")
	case p.streamBadTail:
		p.stream = strings.TrimSuffix(built, "data: [DONE]\n\n") +
			`data: {"choices":[{"delta":{"content":"not ciphertext"},"index":0}]}` + "\n\ndata: [DONE]\n\n"
	}
	signed := built
	if p.signServed {
		signed = p.stream
	}
	served := p.digest
	if p.served != "" {
		served = p.served
	}
	// The gateway hashes the request with the plaintext restored in place
	// of the ciphertext (E2EE v2 §8).
	restored := strings.Replace(string(body), `"`+b.Messages[0].Content+`"`, `"Say hello"`, 1)
	fields := &aciv2test.Receipt{ID: "rcpt-1", Model: "qwen/model", KeysetDigest: served, SessionID: pinnedSessionID, Request: []byte(restored), Response: []byte(signed), ServedAt: probeSessionExpires - 10}
	if p.receipt != nil {
		p.receipt(fields)
	}
	p.signed = string(p.gw.SignReceipt(fields))
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Aci-Keyset-Digest", served)
	if !p.noReceiptID {
		w.Header().Set("X-Receipt-Id", "rcpt-1")
	}
	switch {
	case p.streamResetAfterFirst:
		parts := strings.SplitAfter(p.stream, "\n\n")
		_, _ = io.WriteString(w, parts[0]+parts[1])
		http.NewResponseController(w).Flush()
		panic(http.ErrAbortHandler)
	case p.streamResetAfterDone:
		_, _ = io.WriteString(w, p.stream)
		http.NewResponseController(w).Flush()
		panic(http.ErrAbortHandler)
	default:
		_, _ = io.WriteString(w, p.stream)
	}
}

// The standalone Phala Cloud probe sends an E2EE v2 request over the
// connection pinned to the attested TLS key, decrypts the response and
// checks its keyset digest; the request pins the verified sessions. Then it
// fetches the receipt over the same connection pool and verifies it, as
// teep serve does. A capturing run records both exchanges without the API
// key. A connection of another TLS key sends no request, also when the run
// captures.
func TestStandalonePhalaCloudProbe(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		gw := &probeGateway{t: t, gw: aciv2test.New(t), digest: "sha256:" + strings.Repeat("aa", 32)}
		upstream := authority.NewTLSServer(t, gw)
		defer upstream.Close()
		route, err := provider.NewResolvedRoute(upstream.URL, "")
		if err != nil {
			t.Fatal(err)
		}
		raw := &attestation.RawAttestation{
			BackendFormat: attestation.FormatACI1, SigningKey: gw.gw.PubKeyHex(), ACICanonicalReport: true, ACIWorkloadKeysetDigest: gw.digest,
			ACIReceiptKeys:    []attestation.ACIReceiptKey{{KeyID: aciv2test.ReceiptKeyID, Algo: "ed25519", PublicKey: gw.gw.ReceiptPublicKeyHex()}},
			ACIKeysetNotAfter: probeSessionExpires + 3600,
		}
		pinned := []attestation.ACIPinnedSession{{ID: pinnedSessionID, EstablishedAt: probeSessionExpires - 3600, ExpiresAt: probeSessionExpires}}
		var lastRetry bool
		probe := func(t *testing.T, fingerprint string) (*standaloneProbe, *verificationCapture, error) {
			t.Helper()
			identity, err := tlsct.NewTransportIdentity(route.Authority(), fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			client, err := tlsct.NewSPKIPinnedHTTPClientWithTransport(0, tlsct.NewPooledTransport(), identity, false)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.CloseIdleConnections)
			capture := &verificationCapture{}
			opts := &Options{ProviderName: "phalacloud", Provider: &config.Provider{BaseURL: upstream.URL, APIKey: "secret-api-key", E2EE: true}, ModelName: "qwen/model", capture: capture}
			ctx, cancel := context.WithTimeout(t.Context(), probeTimeout)
			defer cancel()
			got, retry, err := testStandaloneInference(ctx, opts, route, raw, e2ee.NearModelKey{}, pinned, client)
			lastRetry = retry
			return got, capture, err
		}
		fp := sha256.Sum256(upstream.Certificate().RawSubjectPublicKeyInfo)
		attested := hex.EncodeToString(fp[:])

		t.Run("attested key", func(t *testing.T) {
			got, capture, err := probe(t, attested)
			if err != nil || got == nil || got.e2ee == nil || got.e2ee.Err != nil {
				t.Fatalf("probe = %+v, %v", got, err)
			}
			if f := completedReceiptFactor(t, got, err); f.Status != attestation.Pass || !f.Enforced {
				t.Errorf("aci_receipt_verified = %+v, want an enforced Pass", f)
			}
			if !strings.Contains(got.e2ee.Detail, "E2EE v2 secp256k1: 2 encrypted fields") {
				t.Errorf("detail = %q", got.e2ee.Detail)
			}
			if r := got.e2ee.Receipt; r == nil || r.Err != nil || r.Detail != "receipt verified, including the request hash" {
				t.Errorf("receipt = %+v", r)
			}
			entries := capture.entries()
			gw.mu.Lock()
			stream, signed := gw.stream, gw.signed
			gw.mu.Unlock()
			if len(entries) != 2 || string(entries[0].Body) != stream || entries[0].Headers.Get("X-Aci-Keyset-Digest") != gw.digest || string(entries[1].Body) != signed {
				t.Fatalf("recorded %d entries, want the raw exchange and the receipt", len(entries))
			}
			for _, e := range entries {
				if strings.Contains(string(e.ReqBody), "secret-api-key") || strings.Contains(e.URL, "secret-api-key") {
					t.Error("the API key was recorded")
				}
			}
		})

		otherResponse := func(r *aciv2test.Receipt) { r.Response = []byte("other") }
		// After a verified stream, every failure to obtain a verified
		// receipt fails aci_receipt_verified (e2ee.Receipt): a receipt that
		// the route does not serve or that fails the check, and a receipt
		// request that fails or does not end. A response of another keyset
		// fails the probe (e2ee_usable).
		for _, tc := range []struct {
			name      string
			set       func(*probeGateway)
			want      string
			inReceipt bool
		}{
			{"receipt of other response", func(p *probeGateway) { p.receipt = otherResponse }, "response.returned", true},
			{"receipt of other request", func(p *probeGateway) { p.receipt = func(r *aciv2test.Receipt) { r.Request = []byte("{}") } }, "request.received", true},
			{"served after the session", func(p *probeGateway) {
				p.receipt = func(r *aciv2test.Receipt) { r.ServedAt = probeSessionExpires + 1 }
			}, "outside the period", true},
			{"no receipt id", func(p *probeGateway) { p.noReceiptID = true }, "X-Receipt-Id", true},
			{"receipt not served", func(p *probeGateway) { p.receiptMissing = true }, "HTTP 404 after 3 attempts", true},
			{"receipt route error", func(p *probeGateway) { p.receiptStatus = http.StatusInternalServerError }, "HTTP 500", true},
			{"receipt route forbidden", func(p *probeGateway) { p.receiptStatus = http.StatusForbidden }, "HTTP 403", true},
			{"receipt fetch aborted", func(p *probeGateway) { p.receiptHangup = true }, "the receipt request failed", true},
			{"receipt body short", func(p *probeGateway) { p.receiptShort = true }, "the receipt request failed", true},
			{"receipt not answered", func(p *probeGateway) { p.receiptStall = true }, "the receipt request failed", true},
			{"other keyset", func(p *probeGateway) { p.served = "sha256:" + strings.Repeat("bb", 32) }, "another keyset digest", false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				gw.configure(tc.set)
				got, _, err := probe(t, attested)
				checkProbeFailure(t, got, err, tc.want, tc.inReceipt)
				checkReceiptFactor(t, got, err, tc.inReceipt)
			})
		}

		testProbeStreamResets(t, gw, func(t *testing.T) (*standaloneProbe, error) {
			t.Helper()
			got, _, err := probe(t, attested)
			return got, err
		})

		t.Run("sessions refused", func(t *testing.T) {
			gw.configure(func(p *probeGateway) { p.refuse = true })
			defer gw.configure(nil)
			got, _, err := probe(t, attested)
			checkSessionsRefused(t, got, lastRetry, err)
		})

		t.Run("other key", func(t *testing.T) {
			before := gw.calls.Load()
			got, _, err := probe(t, strings.Repeat("ab", 32))
			if err == nil || (got != nil && got.e2ee != nil && got.e2ee.Err == nil) {
				t.Fatal("probe to another TLS key succeeded")
			}
			if gw.calls.Load() != before {
				t.Error("request sent to a connection of another TLS key")
			}
		})
	})
}

// testProbeStreamResets runs the probe against a gateway that resets the
// probe stream.
func testProbeStreamResets(t *testing.T, gw *probeGateway, probe func(*testing.T) (*standaloneProbe, error)) {
	t.Helper()
	// A probe stream that stops with a read error still has its receipt
	// checked, against the bytes that arrived. After [DONE] every byte
	// arrived and the receipt verifies; e2ee_usable states the failed
	// stream. A stream cut after its first chunk does not match the
	// receipt, which covers the whole response, and the factor fails.
	t.Run("stream reset after [DONE]", func(t *testing.T) {
		gw.configure(func(p *probeGateway) { p.streamResetAfterDone = true })
		got, err := probe(t)
		if got == nil || got.e2ee == nil || got.e2ee.Err == nil {
			t.Fatalf("probe = %+v, %v; want the stream failure in e2ee_usable", got, err)
		}
		if r := got.e2ee.Receipt; r == nil || r.Err != nil {
			t.Fatalf("receipt = %+v, want it checked and verified", r)
		}
		if f := completedReceiptFactor(t, got, err); f.Status != attestation.Pass {
			t.Errorf("aci_receipt_verified = %+v, want Pass", f)
		}
	})
	// Once the response is an event stream, every outcome except a verified
	// receipt fails the factor: a reset without a receipt id, a stream that
	// ends without [DONE], and a chunk that does not decrypt. A receipt over
	// the bytes served still verifies; e2ee_usable states the bad chunk.
	for _, tc := range []struct {
		name string
		set  func(*probeGateway)
		want attestation.Status
	}{
		{"reset without a receipt id", func(p *probeGateway) { p.streamResetAfterFirst, p.noReceiptID = true, true }, attestation.Fail},
		{"no [DONE]", func(p *probeGateway) { p.streamNoDone = true }, attestation.Fail},
		{"chunk that does not decrypt", func(p *probeGateway) { p.streamBadTail = true }, attestation.Fail},
		{"chunk that does not decrypt, receipt over it", func(p *probeGateway) { p.streamBadTail, p.signServed = true, true }, attestation.Pass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw.configure(tc.set)
			got, err := probe(t)
			if got == nil || got.e2ee == nil || got.e2ee.Err == nil {
				t.Fatalf("probe = %+v, %v; want the stream failure in e2ee_usable", got, err)
			}
			if f := completedReceiptFactor(t, got, err); f.Status != tc.want || !f.Enforced {
				t.Errorf("aci_receipt_verified = %+v, want enforced %s", f, tc.want)
			}
		})
	}
	t.Run("stream reset after the first chunk", func(t *testing.T) {
		gw.configure(func(p *probeGateway) { p.streamResetAfterFirst = true })
		got, err := probe(t)
		if got == nil || got.e2ee == nil || got.e2ee.Err == nil {
			t.Fatalf("probe = %+v, %v; want the stream failure in e2ee_usable", got, err)
		}
		if r := got.e2ee.Receipt; r == nil || r.Err == nil || !strings.Contains(r.Err.Error(), "response.returned") {
			t.Fatalf("receipt = %+v, want a response hash failure", r)
		}
		if f := completedReceiptFactor(t, got, err); f.Status != attestation.Fail || !f.Enforced {
			t.Errorf("aci_receipt_verified = %+v, want an enforced Fail", f)
		}
	})
}

// configure resets the case and applies set (nil for none).
func (p *probeGateway) configure(set func(*probeGateway)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.served, p.receipt, p.noReceiptID, p.receiptMissing, p.receiptStatus, p.refuse = "", nil, false, false, 0, false
	p.receiptHangup, p.receiptShort, p.receiptStall = false, false, false
	p.streamResetAfterDone, p.streamResetAfterFirst = false, false
	p.streamNoDone, p.streamBadTail, p.signServed = false, false, false
	if set != nil {
		set(p)
	}
}

// completedReceiptFactor completes the probe outcome in a report as teep
// verify does: BuildReport has left aci_receipt_verified an enforced,
// deferred Skip, because the probe runs after it. It returns the factor.
func completedReceiptFactor(t *testing.T, got *standaloneProbe, err error) attestation.FactorResult {
	t.Helper()
	outcome := verificationOutcome{report: &attestation.VerificationReport{Factors: []attestation.FactorResult{
		{Name: attestation.FactorE2EEUsable, Status: attestation.Skip, Deferred: true},
		{Name: attestation.FactorACIReceiptVerified, Status: attestation.Skip, Deferred: true, Enforced: true},
	}}}
	if got != nil {
		outcome.e2ee = got.e2ee
	}
	completeTLSInference(&outcome, err)
	for _, f := range outcome.report.Factors {
		if f.Name == attestation.FactorACIReceiptVerified {
			return f
		}
	}
	t.Fatal("no aci_receipt_verified factor")
	return attestation.FactorResult{}
}

// checkReceiptFactor requires a receipt failure to block the report through
// aci_receipt_verified, and a probe failure to leave the factor a deferred
// Skip (e2ee_usable states it).
func checkReceiptFactor(t *testing.T, got *standaloneProbe, err error, inReceipt bool) {
	t.Helper()
	f := completedReceiptFactor(t, got, err)
	switch {
	case inReceipt && (f.Status != attestation.Fail || !f.Enforced):
		t.Errorf("aci_receipt_verified = %+v, want an enforced Fail", f)
	case !inReceipt && (f.Status != attestation.Skip || !f.Deferred):
		t.Errorf("aci_receipt_verified = %+v, want a deferred Skip", f)
	}
}

// checkProbeFailure requires the probe to fail with want: in the receipt
// result when inReceipt, else in the E2EE result.
func checkProbeFailure(t *testing.T, got *standaloneProbe, err error, want string, inReceipt bool) {
	t.Helper()
	if err != nil || got == nil || got.e2ee == nil {
		t.Fatalf("probe = %+v, %v", got, err)
	}
	if inReceipt {
		if got.e2ee.Err != nil || got.e2ee.Receipt == nil || got.e2ee.Receipt.Err == nil || !strings.Contains(got.e2ee.Receipt.Err.Error(), want) {
			t.Fatalf("e2ee err %v, receipt %+v; want a receipt error with %q", got.e2ee.Err, got.e2ee.Receipt, want)
		}
		return
	}
	if got.e2ee.Err == nil || !strings.Contains(got.e2ee.Err.Error(), want) {
		t.Fatalf("e2ee err %v; want an E2EE error with %q", got.e2ee.Err, want)
	}
}

// checkSessionsRefused requires a refusal of the pinned sessions to make the
// probe verify again, with an error that names the sessions, not an
// encryption key.
func checkSessionsRefused(t *testing.T, got *standaloneProbe, retry bool, err error) {
	t.Helper()
	if got != nil || !retry || err == nil {
		t.Fatalf("probe = %+v, retry %v, err %v; want a refusal that verifies again", got, retry, err)
	}
	if !strings.Contains(err.Error(), "refused the pinned attested sessions (session_not_accepted)") || strings.Contains(err.Error(), "encryption key") {
		t.Errorf("err = %v, want the session refusal", err)
	}
	if _, ok := errors.AsType[*standaloneKeyRejectionError](err); !ok {
		t.Errorf("err %T does not make the probe verify again", err)
	}
}
