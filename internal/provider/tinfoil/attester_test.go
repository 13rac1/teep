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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
)

// testKeyAndCert generates an ECDSA P-256 key pair and self-signed certificate.
// Returns the PEM certificate string, the key fingerprint (SHA-256 of SPKI),
// the private key for signing, and the DER-encoded leaf certificate (for
// constructing a tls.Certificate that the test TLS server presents so the live
// peer SPKI matches the attested tls_key_fp).
func testKeyAndCert(t *testing.T) (pemCert, fpHex string, key *ecdsa.PrivateKey, certDER []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	// Create self-signed certificate.
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

	// Compute SPKI fingerprint from the certificate's RawSubjectPublicKeyInfo.
	// We parse the DER after CreateCertificate to get the exact SPKI bytes
	// that will be present in the TLS peer certificate, matching the
	// production fingerprint computation in extractPeerSPKI and
	// verifyEnvelopeSignature.
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert for SPKI: %v", err)
	}
	fpHash := sha256.Sum256(parsedCert.RawSubjectPublicKeyInfo)
	fpHex = hex.EncodeToString(fpHash[:])

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return string(pemBlock), fpHex, key, certDER
}

// makeSignedV3JSON builds a valid V3 attestation JSON document with a real
// ECDSA envelope signature. Returns the raw JSON bytes, the nonce used, and a
// tls.Certificate whose leaf SPKI matches the attested tls_key_fp (so a test
// TLS server can present it and the live peer SPKI check passes).
func makeSignedV3JSON(t *testing.T) ([]byte, attestation.Nonce, tls.Certificate) {
	t.Helper()

	pemCert, fpHex, privKey, certDER := testKeyAndCert(t)
	nonce := attestation.NewNonce()

	cpuReport := make([]byte, 64)
	for i := range cpuReport {
		cpuReport[i] = byte(i)
	}

	gpu := `{"evidences":[{"arch":"HOPPER","certificate":"Y2VydA==","evidence":"ZXZpZA==","nonce":"` + makeHex32(0xaa) + `"}]}`

	rd := map[string]any{
		"tls_key_fp":        fpHex,
		"hpke_key":          makeHex32(0x02),
		"nonce":             nonce.Hex(),
		"gpu_evidence_hash": fmt.Sprintf("%x", sha256.Sum256([]byte(gpu))),
	}

	// Build the document without signature first, then sign it.
	doc := map[string]any{
		"format":      FormatURI,
		"report_data": rd,
		"cpu": map[string]any{
			"platform": PlatformTDX,
			"report":   base64.StdEncoding.EncodeToString(cpuReport),
		},
		"gpu":         json.RawMessage(gpu),
		"certificate": pemCert,
		"signature":   "", // placeholder
	}

	// Marshal, compute hash, sign, then replace signature.
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal doc: %v", err)
	}

	// The hash is over the JSON with signature="" (which is what we have now).
	hash := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	sigB64 := base64.StdEncoding.EncodeToString(sig)
	doc["signature"] = sigB64

	data, err = json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal signed doc: %v", err)
	}

	tlsCert := tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: privKey}
	return data, nonce, tlsCert
}

func TestFetchAttestation_Success(t *testing.T) {
	body, nonce, tlsCert := makeSignedV3JSON(t)

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != attestationPath {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		gotNonce := r.URL.Query().Get("nonce")
		if gotNonce != nonce.Hex() {
			t.Errorf("nonce = %q, want %q", gotNonce, nonce.Hex())
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	ts.StartTLS()
	defer ts.Close()

	attester := NewAttester(ts.URL, "test-key", true)
	attester.SetClient(ts.Client())

	raw, err := attester.FetchAttestation(context.Background(), "model", nonce)
	if err != nil {
		t.Fatalf("FetchAttestation failed: %v", err)
	}

	if raw.BackendFormat != attestation.FormatTinfoil {
		t.Errorf("BackendFormat = %q, want %q", raw.BackendFormat, attestation.FormatTinfoil)
	}
	if raw.TEEHardware != HardwareIntelTDX {
		t.Errorf("TEEHardware = %q, want %q", raw.TEEHardware, HardwareIntelTDX)
	}
	if subtle.ConstantTimeCompare([]byte(raw.Nonce), []byte(nonce.Hex())) != 1 {
		t.Error("nonce mismatch")
	}
}

func TestFetchAttestation_NonceMismatch(t *testing.T) {
	// Build a signed response with a different nonce.
	body, _, tlsCert := makeSignedV3JSON(t)

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	ts.StartTLS()
	defer ts.Close()

	attester := NewAttester(ts.URL, "test-key", true)
	attester.SetClient(ts.Client())

	// Use a different nonce than what's in the response.
	differentNonce := attestation.NewNonce()
	_, err := attester.FetchAttestation(context.Background(), "model", differentNonce)
	if err == nil {
		t.Fatal("expected error for nonce mismatch")
	}
}

func TestVerifyEnvelopeSignature_Valid(t *testing.T) {
	body, _, _ := makeSignedV3JSON(t)
	_, resp, err := parseV3Response(body)
	if err != nil {
		t.Fatalf("parseV3Response failed: %v", err)
	}

	err = verifyEnvelopeSignature(body, resp)
	if err != nil {
		t.Fatalf("verifyEnvelopeSignature failed: %v", err)
	}
}

func TestVerifyEnvelopeSignature_TamperedBody(t *testing.T) {
	body, _, _ := makeSignedV3JSON(t)

	// Tamper with the body by replacing a character.
	tampered := make([]byte, len(body))
	copy(tampered, body)
	// Find and change the format field.
	for i := range tampered {
		if tampered[i] == 'v' && i+1 < len(tampered) && tampered[i+1] == '3' {
			tampered[i+1] = '4' // change v3 to v4 in the format URI
			break
		}
	}

	_, resp, err := parseV3Response(body) // parse original
	if err != nil {
		t.Fatalf("parseV3Response failed: %v", err)
	}

	// Verify with tampered body should fail.
	err = verifyEnvelopeSignature(tampered, resp)
	if err == nil {
		t.Fatal("expected error for tampered body")
	}
}

func TestVerifyEnvelopeSignature_FPMismatch(t *testing.T) {
	pemCert, _, privKey, _ := testKeyAndCert(t)
	nonce := attestation.NewNonce()

	cpuReport := make([]byte, 64)
	gpu := `{"evidences":[]}`

	// Use wrong fingerprint in report_data.
	rd := map[string]any{
		"tls_key_fp":        makeHex32(0xFF), // wrong fingerprint
		"hpke_key":          makeHex32(0x02),
		"nonce":             nonce.Hex(),
		"gpu_evidence_hash": fmt.Sprintf("%x", sha256.Sum256([]byte(gpu))),
	}

	doc := map[string]any{
		"format":      FormatURI,
		"report_data": rd,
		"cpu": map[string]any{
			"platform": PlatformTDX,
			"report":   base64.StdEncoding.EncodeToString(cpuReport),
		},
		"gpu":         json.RawMessage(gpu),
		"certificate": pemCert,
		"signature":   "",
	}

	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	hash := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1: %v", err)
	}
	doc["signature"] = base64.StdEncoding.EncodeToString(sig)
	data, err = json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	_, resp, err := parseV3Response(data)
	if err != nil {
		t.Fatalf("parseV3Response failed: %v", err)
	}

	err = verifyEnvelopeSignature(data, resp)
	if err == nil {
		t.Fatal("expected error for fingerprint mismatch")
	}
}

func TestReplaceSignatureValue(t *testing.T) {
	body := []byte(`{"format":"test","signature":"ABCD1234","other":"field"}`)
	modified, err := replaceSignatureValue(body, "ABCD1234")
	if err != nil {
		t.Fatalf("replaceSignatureValue failed: %v", err)
	}

	expected := `{"format":"test","signature":"","other":"field"}`
	if string(modified) != expected {
		t.Errorf("modified = %q, want %q", string(modified), expected)
	}
}

func TestReplaceSignatureValue_MissingField(t *testing.T) {
	body := []byte(`{"format":"test","other":"field"}`)
	_, err := replaceSignatureValue(body, "anything")
	if err == nil {
		t.Fatal("expected error when signature field is missing")
	}
}
