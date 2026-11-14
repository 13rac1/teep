package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/e2ee/aciv2test"
	"github.com/13rac1/teep/internal/provider/aci"
)

// formatRecordingEncryptor records the attestation format of each request
// that it encrypts.
type formatRecordingEncryptor struct {
	mu      sync.Mutex
	formats []attestation.BackendFormat
}

func (e *formatRecordingEncryptor) EncryptRequest(_ []byte, raw *attestation.RawAttestation, _ e2ee.EndpointType) (e2ee.EncryptResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.formats = append(e.formats, raw.BackendFormat)
	return e2ee.EncryptResult{Body: []byte("encrypted")}, nil
}

// publishFormatReport publishes a passing report of format with a cached
// signing key.
func publishFormatReport(t *testing.T, s *Server, prov string, format attestation.BackendFormat, signingKey string) {
	t.Helper()
	report := bindingReport()
	report.BackendFormat = format
	if format == attestation.FormatACI1 {
		// An ACI/1 report is usable only before its keyset not_after.
		report.ACIKeysetNotAfter = time.Now().Add(time.Hour).Unix()
	}
	key := providerModelKey{prov, "model"}
	s.reportMu.Lock()
	s.storeReportLocked(key, report)
	s.reportMu.Unlock()
	s.signingKeyCache.Put(prov, "model", signingKey)
}

// A request that uses a cached signing key passes the format of the report
// that published the key to the encryptor.
func TestBuildUpstreamBodyCachedKeyCarriesFormat(t *testing.T) {
	s, prov := newReportTestServer(t, &mockAttester{})
	prov.E2EE = true
	enc := &formatRecordingEncryptor{}
	prov.Encryptor = enc
	publishFormatReport(t, s, prov.Name, attestation.FormatACI1, "cached-key")
	if _, err := s.buildUpstreamBody(t.Context(), []byte(`{}`), "model", true, prov, nil, e2ee.EndpointChat); err != nil {
		t.Fatal(err)
	}
	if len(enc.formats) != 1 || enc.formats[0] != attestation.FormatACI1 {
		t.Fatalf("encrypted formats = %v, want [%s]", enc.formats, attestation.FormatACI1)
	}
}

// E2EE v2 encrypts only to a key that an ACI/1 report published: a cached
// key of a dstack report fails before any request bytes are built.
func TestBuildUpstreamBodyACIv2RefusesOtherFormat(t *testing.T) {
	gw := aciv2test.New(t)
	body := []byte(`{"model":"model","messages":[{"role":"user","content":"hi"}]}`)
	for _, tc := range []struct {
		format  attestation.BackendFormat
		wantErr string
	}{
		{attestation.FormatACI1, ""},
		{attestation.FormatDstack, "requires an ACI/1 attestation"},
	} {
		t.Run(string(tc.format), func(t *testing.T) {
			s, prov := newReportTestServer(t, &mockAttester{})
			prov.E2EE = true
			prov.Encryptor = aci.NewE2EE()
			publishFormatReport(t, s, prov.Name, tc.format, gw.PubKeyHex())
			ub, err := s.buildUpstreamBody(t.Context(), body, "model", true, prov, nil, e2ee.EndpointChat)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer ub.Session.Zero()
			if _, ok := ub.Session.(*e2ee.ACIv2Session); !ok {
				t.Fatalf("session = %T, want *e2ee.ACIv2Session", ub.Session)
			}
		})
	}
}

// An E2EE v2 response confirms E2EE only after a field decrypted: a stream
// without a content field carries no ciphertext, so it must not mark the
// report's e2ee_usable factor.
func TestE2EEConfirmedRequiresDecryptedField(t *testing.T) {
	gw := aciv2test.New(t)
	raw := &attestation.RawAttestation{BackendFormat: attestation.FormatACI1, SigningKey: gw.PubKeyHex()}
	result, err := aci.NewE2EE().EncryptRequest([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`), raw, e2ee.EndpointChat)
	if err != nil {
		t.Fatal(err)
	}
	session := result.Session.(*e2ee.ACIv2Session)
	defer session.Zero()
	if e2eeConfirmed(session) {
		t.Fatal("E2EE v2 session without a decrypted field is confirmed")
	}
	h := http.Header{}
	for k, v := range session.Headers() {
		h.Set(k, v)
	}
	r := gw.ReadRequest(h, result.Body)
	stream := gw.Stream(r, "id-1", []string{"x"}, true)
	if _, err := e2ee.RelayStream(t.Context(), httptest.NewRecorder(), strings.NewReader(stream), session, e2ee.EndpointChat); err != nil {
		t.Fatal(err)
	}
	if !e2eeConfirmed(session) {
		t.Fatal("E2EE v2 session with a decrypted field is not confirmed")
	}
	venice, err := e2ee.NewVeniceSession()
	if err != nil {
		t.Fatal(err)
	}
	defer venice.Zero()
	if !e2eeConfirmed(venice) || !e2eeConfirmed(nil) {
		t.Error("sessions whose relay enforces encrypted fields must be confirmed")
	}
}

// CoversE2EE covers every endpoint, so the test reaches EncryptRequest.
func (*formatRecordingEncryptor) CoversE2EE(e2ee.EndpointType) bool { return true }
