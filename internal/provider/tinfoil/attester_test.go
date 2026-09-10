package tinfoil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"github.com/13rac1/teep/internal/provider"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
)

// testKeyAndCert generates an ECDSA P-256 key pair and a self-signed
// certificate. It returns the SPKI fingerprint and a DER certificate, so a test
// TLS server can present a key whose fingerprint the document endorses.
func testKeyAndCert(t *testing.T) (fpHex string, key *ecdsa.PrivateKey, certDER []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		// httptest TLS servers listen on 127.0.0.1; the cert must list it
		// as an IP SAN so the client (ts.Client()) can verify it.
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
	}
	certDER, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	// Take the fingerprint from the parsed certificate's RawSubjectPublicKeyInfo,
	// which is the same DER the TLS peer presents and the same computation
	// tlsct.PeerSPKI performs.
	parsed, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert for SPKI: %v", err)
	}
	fpHash := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(fpHash[:]), key, certDER
}

// serveDocument starts a TLS server that presents tlsCert and serves body from
// the attestation path.
func serveDocument(t *testing.T, body []byte, tlsCert *tls.Certificate, check func(*http.Request)) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if check != nil {
			check(r)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{*tlsCert}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

// makeServedDocument builds a document whose endorsed TLS key is the key the
// returned certificate carries, so the channel binding holds.
func makeServedDocument(t *testing.T) (body []byte, nonce attestation.Nonce, cert *tls.Certificate) {
	t.Helper()
	fpHex, key, certDER := testKeyAndCert(t)
	nonce = attestation.NewNonce()

	b := newDocBuilder()
	b.nonce = nonce
	fp, err := hex.DecodeString(fpHex)
	if err != nil {
		t.Fatalf("decode fingerprint: %v", err)
	}
	copy(b.tlsFP[:], fp)

	body, _ = b.build(t)
	return body, nonce, &tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}
}

func TestFetchAttestation_Success(t *testing.T) {
	body, nonce, tlsCert := makeServedDocument(t)

	ts := serveDocument(t, body, tlsCert, func(r *http.Request) {
		if r.URL.Path != attestationPath {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("nonce"); got != nonce.Hex() {
			t.Errorf("nonce = %q, want %q", got, nonce.Hex())
		}
	})

	attester := NewAttester(ts.URL, "test-key", true)
	attester.SetClient(ts.Client())

	raw, err := attester.FetchAttestation(context.Background(), "model", nonce)
	if err != nil {
		t.Fatalf("FetchAttestation failed: %v", err)
	}
	if raw.BackendFormat != attestation.FormatTinfoil {
		t.Errorf("BackendFormat = %q, want %q", raw.BackendFormat, attestation.FormatTinfoil)
	}
	// The cloud attester reports the router as a gateway, so the quote must
	// leave the core fields entirely.
	if len(raw.GatewaySEVReportBytes) == 0 {
		t.Error("GatewaySEVReportBytes is empty; the router quote was not moved to the gateway fields")
	}
	if len(raw.SEVReportBytes) != 0 {
		t.Error("SEVReportBytes is set; the router quote must not sit in the core fields")
	}
	if raw.TEEHardware != "" {
		t.Errorf("TEEHardware = %q; the model endpoint's platform is unknown", raw.TEEHardware)
	}
	if raw.GatewayNonceHex != raw.TinfoilNonce {
		t.Error("GatewayNonceHex does not carry the nonce the quote binds")
	}
	if subtle.ConstantTimeCompare([]byte(raw.Nonce), []byte(nonce.Hex())) != 1 {
		t.Error("nonce mismatch")
	}
}

func TestFetchAttestation_NonceMismatch(t *testing.T) {
	body, _, tlsCert := makeServedDocument(t)
	ts := serveDocument(t, body, tlsCert, nil)

	attester := NewAttester(ts.URL, "test-key", true)
	attester.SetClient(ts.Client())

	_, err := attester.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for nonce mismatch")
	}
}

// The endorsed TLS key is what binds the channel to the enclave. A live peer
// presenting a different key must be rejected before any request is sent.
func TestFetchAttestation_TLSBindingMismatch(t *testing.T) {
	nonce := attestation.NewNonce()

	// The document endorses the builder's default key, not the served one.
	b := newDocBuilder()
	b.nonce = nonce
	body, _ := b.build(t)

	_, key, certDER := testKeyAndCert(t)
	ts := serveDocument(t, body, &tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}, nil)

	attester := NewAttester(ts.URL, "test-key", true)
	attester.SetClient(ts.Client())

	_, err := attester.FetchAttestation(context.Background(), "model", nonce)
	if err == nil {
		t.Fatal("expected error for TLS channel binding mismatch")
	}
	if !strings.Contains(err.Error(), "TLS channel binding failed") {
		t.Errorf("error = %v, want a TLS channel binding failure", err)
	}
}

// An enclave that has not been migrated must be named, not reported as a list
// of absent members.
func TestFetchAttestation_SupersededDocument(t *testing.T) {
	nonce := attestation.NewNonce()
	_, key, certDER := testKeyAndCert(t)
	body := readFixture(t, fixtureSuperseded)
	ts := serveDocument(t, body, &tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}, nil)

	attester := NewAttester(ts.URL, "test-key", true)
	attester.SetClient(ts.Client())

	_, err := attester.FetchAttestation(context.Background(), "model", nonce)
	if err == nil {
		t.Fatal("expected error for the superseded document")
	}
	if !strings.Contains(err.Error(), "superseded") {
		t.Errorf("error = %v, want it to name the superseded document", err)
	}
}

// A TDX router would need a gateway TDX path that teep does not have. Routing
// it into GatewayIntelQuote would hand it to nearcloud's REPORTDATA verifier,
// so the cloud attester rejects it instead.
func TestFetchAttestation_RejectsTDXRouter(t *testing.T) {
	fpHex, key, certDER := testKeyAndCert(t)
	nonce := attestation.NewNonce()

	b := newDocBuilder()
	b.nonce = nonce
	b.cpuFormat = tdxQuoteV1Format
	fp, err := hex.DecodeString(fpHex)
	if err != nil {
		t.Fatalf("decode fingerprint: %v", err)
	}
	copy(b.tlsFP[:], fp)
	body, _ := b.build(t)

	ts := serveDocument(t, body, &tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}, nil)
	attester := NewAttester(ts.URL, "test-key", true)
	attester.SetClient(ts.Client())

	_, err = attester.FetchAttestation(context.Background(), "model", nonce)
	if err == nil {
		t.Fatal("expected a TDX router to be rejected")
	}
	if !strings.Contains(err.Error(), "TDX") {
		t.Errorf("error = %v, want it to name the TDX quote", err)
	}
}

func TestNewPreparer(t *testing.T) {
	p := NewPreparer("test-key")
	if p == nil {
		t.Fatal("NewPreparer returned nil")
	}
}

func TestPreparer_PrepareRequest(t *testing.T) {
	p := NewPreparer("test-key-123")
	req, _ := http.NewRequest(http.MethodPost, "http://localhost/v1/chat/completions", http.NoBody)
	if err := p.PrepareRequest(req, nil, nil, false, "", provider.PreparationData{}); err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}
	got := req.Header.Get("Authorization")
	want := "Bearer test-key-123"
	if got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
}

func TestDefaultMeasurementPolicy(t *testing.T) {
	pol := DefaultMeasurementPolicy()
	if len(pol.MRSeamAllow) == 0 {
		t.Error("DefaultMeasurementPolicy should have MRSeamAllow entries")
	}
	// Should not have MRTD — Tinfoil uses Sigstore, not MRTD allowlist.
	if len(pol.MRTDAllow) != 0 {
		t.Errorf("DefaultMeasurementPolicy should not set MRTDAllow, got %d", len(pol.MRTDAllow))
	}
}

func TestInapplicableFactors(t *testing.T) {
	inapplicable := InapplicableFactors()
	if len(inapplicable) == 0 {
		t.Fatal("InapplicableFactors returned empty map")
	}
	expected := []string{
		"nvidia_nonce_client_bound", "nvidia_nras_verified",
		"compose_binding",
		"sigstore_verification", "event_log_integrity",
	}
	for _, name := range expected {
		if _, ok := inapplicable[name]; !ok {
			t.Errorf("InapplicableFactors missing %q", name)
		}
	}
	// sigstore_code_verified should NOT be inapplicable for Tinfoil.
	if _, ok := inapplicable["sigstore_code_verified"]; ok {
		t.Error("sigstore_code_verified should be applicable for Tinfoil")
	}
	if _, ok := inapplicable["build_transparency_log"]; ok {
		t.Error("build_transparency_log should be applicable for Tinfoil")
	}
}

func TestNewDirectAttester(t *testing.T) {
	resolver := newTestResolver(t, `{"models":{"test-model":{"enclaves":{"test-model.inf10.tinfoil.sh":{"hpke_key":"abc","predicate":"x","tls_key_fp":"def"}}}}}`)
	da := NewDirectAttester(resolver, "key")
	if da == nil {
		t.Fatal("NewDirectAttester returned nil")
	}
}

func TestDirectAttester_SetClient(t *testing.T) {
	resolver := newTestResolver(t, `{"models":{"test-model":{"enclaves":{"test-model.inf10.tinfoil.sh":{"hpke_key":"abc","predicate":"x","tls_key_fp":"def"}}}}}`)
	da := NewDirectAttester(resolver, "key")
	client := &http.Client{}
	da.SetClient(client)
	if da.client != client {
		t.Error("SetClient did not update client")
	}
}

func TestDirectAttester_FetchAttestation_ResolveFails(t *testing.T) {
	// Empty model list — no model to resolve.
	resolver := newTestResolver(t, `{"models":{}}`)
	da := NewDirectAttester(resolver, "key")
	nonce := attestation.NewNonce()
	_, err := da.FetchAttestation(context.Background(), "nonexistent-model", nonce)
	if err == nil {
		t.Fatal("expected error when model cannot be resolved")
	}
}

// newTestResolver creates a DirectResolver backed by a TLS test server.
func newTestResolver(t *testing.T, proxyResponse string) *DirectResolver {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(proxyResponse))
	}))
	t.Cleanup(ts.Close)
	r := NewDirectResolver("key", true)
	r.proxyURL = ts.URL + "/.well-known/tinfoil-proxy"
	r.client = ts.Client()
	return r
}
