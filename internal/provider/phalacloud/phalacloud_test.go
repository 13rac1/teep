package phalacloud_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/phalacloud"
	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func makeServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func canonicalReport(t *testing.T) []byte {
	t.Helper()
	body, err := os.ReadFile("../aci/testdata/canonical_report.json")
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// fixtureTLSKey is the SPKI fingerprint that the canonical report fixture
// lists for tee.redpill.ai, in the keyset and in downstream_tls_binding.
const fixtureTLSKey = "951885459fbd27cad038c40a198e6a1fb63f4d18dd5d5a24d408d5d951488ffe"

// The attester requests the canonical ACI/1 report with the client nonce
// and no model over TLS, and pins the TLS key that the keyset lists for the
// host. The connection that carried the report must use that key.
func TestAttester_FetchesCanonicalReport(t *testing.T) {
	testAttesterTLSBinding(t, "matching", true)
}

func TestAttester_TLSBindingFailures(t *testing.T) {
	for _, mode := range []string{"other_peer_key", "downstream_differs", "no_entry_for_host", "duplicate_entry"} {
		t.Run(mode, func(t *testing.T) { testAttesterTLSBinding(t, mode, false) })
	}
}

// tlsBindingErrors names the failure that each mode must cause.
var tlsBindingErrors = map[string]string{
	"other_peer_key":     "attestation TLS binding",
	"downstream_differs": "downstream_tls_binding",
	"no_entry_for_host":  "lists no TLS key for tee.redpill.ai",
	"duplicate_entry":    "more than one TLS key for tee.redpill.ai",
}

func testAttesterTLSBinding(t *testing.T, mode string, wantSuccess bool) {
	t.Helper()
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		fixture := string(canonicalReport(t))
		nonce := attestation.NewNonce()
		var fingerprint, path, query, auth string
		ts := authority.NewTLSServerForHost(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path, query, auth = r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization")
			body := fixture
			switch mode {
			case "matching":
				body = strings.ReplaceAll(body, fixtureTLSKey, fingerprint)
			case "downstream_differs":
				// The keyset entry matches the peer; the binding does not.
				body = strings.Replace(body, fixtureTLSKey, fingerprint, 1)
			case "no_entry_for_host":
				body = strings.ReplaceAll(body, fixtureTLSKey, fingerprint)
				body = strings.Replace(body, `"domain":"tee.redpill.ai"`, `"domain":"other.example"`, 1)
			case "duplicate_entry":
				body = strings.ReplaceAll(body, fixtureTLSKey, fingerprint)
				body = strings.Replace(body, `"domain":"inference.phala.com"`, `"domain":"tee.redpill.ai"`, 1)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}), "tee.redpill.ai")
		fp := sha256.Sum256(ts.Certificate().RawSubjectPublicKeyInfo)
		fingerprint = hex.EncodeToString(fp[:])
		base := tlsct.NewPooledTransport()
		base.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, ts.Listener.Addr().String())
		}
		client := tlsct.NewHTTPClientWithTransport(5*time.Second, base, false)
		defer client.CloseIdleConnections()
		// The test certificate has no public-log SCTs. The attester selects
		// offline CT policy to test the attestation TLS binding.
		a := phalacloud.NewAttester("https://tee.redpill.ai", "sk-test-key-123", true)
		a.SetClient(client)
		raw, err := a.FetchAttestation(context.Background(), "phala/test-model", nonce)
		if !wantSuccess {
			if err == nil || raw != nil {
				t.Fatal("invalid TLS binding returned usable attestation")
			}
			if !strings.Contains(err.Error(), tlsBindingErrors[mode]) {
				t.Fatalf("error %q, want %q", err, tlsBindingErrors[mode])
			}
			return
		}
		if err != nil {
			t.Fatalf("FetchAttestation: %v", err)
		}
		if path != "/v1/aci/attestation" || query != "nonce="+nonce.Hex() {
			t.Errorf("request %s?%s, want /v1/aci/attestation?nonce=<nonce>", path, query)
		}
		if auth != "Bearer sk-test-key-123" {
			t.Errorf("Authorization = %q", auth)
		}
		if !raw.ACICanonicalReport || raw.BackendFormat != attestation.FormatACI1 {
			t.Errorf("canonical=%v format=%q", raw.ACICanonicalReport, raw.BackendFormat)
		}
		if raw.TransportTLSAuthority != "tee.redpill.ai" || !tlsct.SPKIFingerprintsEqual(raw.TransportTLSFingerprint, fingerprint) {
			t.Errorf("transport identity %q %q, want tee.redpill.ai and the server key", raw.TransportTLSAuthority, raw.TransportTLSFingerprint)
		}
	})
}

// The attester refuses a report that arrives over plain HTTP: the
// connection has no TLS key to compare with the keyset.
func TestAttester_RefusesPlainHTTP(t *testing.T) {
	body := canonicalReport(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	raw, err := phalacloud.NewAttester(srv.URL, "sk-test-key-123").FetchAttestation(context.Background(), "phala/test-model", attestation.NewNonce())
	if err == nil || raw != nil {
		t.Fatal("plain HTTP report returned usable attestation")
	}
}

// A body in any other format fails: Phala Cloud verifies only the
// canonical report.
func TestParseAttestationResponse_RefusesOtherFormats(t *testing.T) {
	gateway, err := os.ReadFile("../aci/testdata/gateway_variant.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		body string
	}{
		{"chutes", `{"attestation_type":"chutes","nonce":"00","all_attestations":[]}`},
		{"dstack", `{"intel_quote":"00","signing_address":"0x00","nonce":"00"}`},
		{"unrecognized", `{"foo":"bar"}`},
		{"gateway variant", string(gateway)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := phalacloud.ParseAttestationResponse(context.Background(), []byte(tc.body)); err == nil {
				t.Fatal("ParseAttestationResponse succeeded")
			}
		})
	}
}

func TestAttester_FetchAttestation_HTTP500(t *testing.T) {
	srv := makeServer(t, http.StatusInternalServerError, `{"error": "server error"}`)
	defer srv.Close()

	a := phalacloud.NewAttester(srv.URL, "test-key")
	_, err := a.FetchAttestation(context.Background(), "phala/test", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error should mention HTTP status, got: %v", err)
	}
}

func TestParseAttestationResponse_InvalidJSON(t *testing.T) {
	_, err := phalacloud.ParseAttestationResponse(context.Background(), []byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestPreparer_SetsAuthAndE2EEHeaders(t *testing.T) {
	p := phalacloud.NewPreparer("sk-test-123")
	req, _ := http.NewRequest(http.MethodPost, "https://tee.redpill.ai/v1/chat/completions", http.NoBody)
	e2eeHeaders := http.Header{}
	e2eeHeaders.Set("X-E2ee-Version", "2")

	if err := p.PrepareRequest(req, e2eeHeaders, nil, false, "", provider.PreparationData{}); err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}
	if req.Header.Get("Authorization") != "Bearer sk-test-123" || req.Header.Get("X-E2ee-Version") != "2" {
		t.Errorf("headers = %v", req.Header)
	}
}

func TestAttester_SetClient(t *testing.T) {
	a := phalacloud.NewAttester("https://attest.phala.network", "sk-key")
	a.SetClient(&http.Client{})
	t.Log("SetClient accepted non-nil client")
}
