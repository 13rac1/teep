package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/e2ee/aciv2test"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// pinnedSessionID stands for an attested session that the audit pinned.
const pinnedSessionID = "4d849e211f7078bd8d27a748a7ac0ddfe164d2ef5c0e29e6e30292a371276320"

// The standalone Phala Cloud probe sends an E2EE v2 request over the
// connection pinned to the attested TLS key, decrypts the response and
// checks its keyset digest; the request pins the verified sessions. A
// capturing run records the exchange without the
// API key. A connection of another TLS key sends no request, also when the
// run captures.
func TestStandalonePhalaCloudProbe(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		gw := aciv2test.New(t)
		var calls atomic.Int32
		var stream string
		upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			calls.Add(1)
			body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
			if err != nil {
				t.Error(err)
				return
			}
			if req.URL.Path != "/v1/chat/completions" || req.Header.Get("Authorization") != "Bearer secret-api-key" {
				t.Errorf("request %s, Authorization %q", req.URL.Path, req.Header.Get("Authorization"))
			}
			var b struct {
				MaxTokens int `json:"max_tokens"`
				Provider  struct {
					ACISessionIDs []string `json:"aci_session_ids"`
				} `json:"provider"`
			}
			if err := json.Unmarshal(body, &b); err != nil || b.MaxTokens != aciv2ProbeMaxTokens {
				t.Errorf("max_tokens = %d, %v", b.MaxTokens, err)
			}
			if len(b.Provider.ACISessionIDs) != 1 || b.Provider.ACISessionIDs[0] != pinnedSessionID {
				t.Errorf("provider.aci_session_ids = %q, want the pinned session", b.Provider.ACISessionIDs)
			}
			r := gw.ReadRequest(req.Header, body)
			stream = gw.Stream(r, "chatcmpl-1", []string{"Hel", "lo"}, true)
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("X-Aci-Keyset-Digest", "sha256:aa")
			_, _ = io.WriteString(w, stream)
		}))
		defer upstream.Close()
		route, err := provider.NewResolvedRoute(upstream.URL, "")
		if err != nil {
			t.Fatal(err)
		}
		raw := &attestation.RawAttestation{BackendFormat: attestation.FormatACI1, SigningKey: gw.PubKeyHex(), ACICanonicalReport: true, ACIWorkloadKeysetDigest: "sha256:aa"}
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
			got, _, err := testStandaloneInference(t.Context(), opts, route, raw, e2ee.NearModelKey{}, []string{pinnedSessionID}, client)
			return got, capture, err
		}

		t.Run("attested key", func(t *testing.T) {
			fp := sha256.Sum256(upstream.Certificate().RawSubjectPublicKeyInfo)
			got, capture, err := probe(t, hex.EncodeToString(fp[:]))
			if err != nil || got == nil || got.e2ee == nil || got.e2ee.Err != nil {
				t.Fatalf("probe = %+v, %v", got, err)
			}
			if !strings.Contains(got.e2ee.Detail, "E2EE v2 secp256k1: 2 encrypted fields") {
				t.Errorf("detail = %q", got.e2ee.Detail)
			}
			entries := capture.entries()
			if len(entries) != 1 || string(entries[0].Body) != stream || entries[0].Headers.Get("X-Aci-Keyset-Digest") != "sha256:aa" {
				t.Fatalf("recorded %d entries, want the raw exchange", len(entries))
			}
			if strings.Contains(string(entries[0].ReqBody), "secret-api-key") || strings.Contains(entries[0].URL, "secret-api-key") {
				t.Error("the API key was recorded")
			}
		})

		t.Run("other key", func(t *testing.T) {
			before := calls.Load()
			got, _, err := probe(t, strings.Repeat("ab", 32))
			if err == nil || (got != nil && got.e2ee != nil && got.e2ee.Err == nil) {
				t.Fatal("probe to another TLS key succeeded")
			}
			if calls.Load() != before {
				t.Error("request sent to a connection of another TLS key")
			}
		})
	})
}
