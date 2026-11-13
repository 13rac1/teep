package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/e2ee/aciv2test"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/aci"
	"github.com/13rac1/teep/internal/provider/phalacloud"
	"github.com/13rac1/teep/internal/tlsct/testtls"
	"golang.org/x/net/http2"
)

// A Phala Cloud request on the pinned path is encrypted with E2EE v2 to the
// authorized gateway key, goes to the attested TLS key, and its response
// decrypts. The keyset digest of the response decides whether the
// authorization generation stays: the verified digest keeps it, another
// digest relays the response and ends it, and no digest fails the request
// and ends it.
func TestAuthorizedPhalaCloudACIv2(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, tc := range []struct {
			name, served string
			wantErr      bool
			ended        bool
		}{
			{"verified digest", "sha256:aa", false, false},
			{"other digest", "sha256:bb", false, true},
			{"no digest", "", true, true},
		} {
			t.Run(tc.name, func(t *testing.T) { testAuthorizedPhalaCloud(t, authority, tc.served, tc.wantErr, tc.ended) })
		}
	})
}

func testAuthorizedPhalaCloud(t *testing.T, authority *testtls.Authority, served string, wantErr, ended bool) {
	t.Helper()
	gw := aciv2test.New(t)
	upstream := authority.NewTLSServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Error(err)
			return
		}
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer test" {
			t.Errorf("request %s, Authorization %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		req := gw.ReadRequest(r.Header, body)
		var b struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.Unmarshal(body, &b); err != nil || len(b.Messages) != 1 {
			t.Errorf("request body: %v", err)
			return
		}
		if got, err := gw.DecryptRequestField(req, "messages.0.content", b.Messages[0].Content); err != nil || got != "test" {
			t.Errorf("messages.0.content = %q, %v", got, err)
		}
		if served != "" {
			w.Header().Set("X-Aci-Keyset-Digest", served)
		}
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		_, _ = io.WriteString(w, gw.Stream(req, "chatcmpl-1", []string{"Hel", "lo"}, true))
	}), func(ts *httptest.Server) {
		ts.Config.TLSConfig = ts.TLS
		if err := http2.ConfigureServer(ts.Config, &http2.Server{}); err != nil {
			t.Fatal(err)
		}
	})
	defer upstream.Close()
	fingerprint := sha256.Sum256(upstream.Certificate().RawSubjectPublicKeyInfo)
	server := newTLSBindingTestServerHandle()
	server.authorizations = newAuthorizationStore(10, 2, time.Second)
	defer server.Close()
	route, err := provider.NewResolvedRoute(upstream.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	prov := &provider.Provider{Name: "phalacloud", BaseURL: upstream.URL, StaticRoute: route, UsesTLSBinding: true, E2EE: true, Encryptor: aci.NewE2EE(), Preparer: phalacloud.NewPreparer("test")}
	key, err := route.AuthorizationKey(prov.Name, "model")
	if err != nil {
		t.Fatal(err)
	}
	report := &attestation.VerificationReport{
		Provider: prov.Name, Model: "model", BackendFormat: attestation.FormatACI1, ACIKeysetDigest: "sha256:aa",
		TLSAuthority: route.Authority(), TLSKeyFP: hex.EncodeToString(fingerprint[:]),
		Factors: []attestation.FactorResult{{Name: attestation.FactorTEEReportData, Status: attestation.Pass}, {Name: attestation.FactorE2EEUsable, Status: attestation.Skip}},
	}
	candidate, err := newAuthorization(key, report, gw.PubKeyHex(), true, false)
	if err != nil {
		t.Fatal(err)
	}
	value := loadTestAuthorization(t, server.authorizations, key, candidate)
	input := &authorizedRequest{provider: prov, route: route, key: key, body: []byte(`{"model":"model","stream":true,"messages":[{"role":"user","content":"test"}]}`), stream: true, path: "/v1/chat/completions", contentType: "application/json", endpoint: e2ee.EndpointChat}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	rec := newInferenceRecorder()
	_, err = server.inferAuthorized(ctx, rec, input)
	if (err != nil) != wantErr {
		t.Fatalf("err = %v, want error %v", err, wantErr)
	}
	if relayed := strings.Contains(rec.Body.String(), "Hel") && strings.Contains(rec.Body.String(), "lo"); relayed == wantErr {
		t.Errorf("decrypted content relayed = %v, want %v", relayed, !wantErr)
	}
	current, ok := server.authorizations.acquire(key)
	if gotEnded := !ok || current.generation != value.generation; gotEnded != ended {
		t.Errorf("generation ended = %v, want %v", gotEnded, ended)
	}
}
