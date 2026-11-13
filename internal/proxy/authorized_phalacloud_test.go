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

// authorizedSessionID stands for the attested session that the
// authorization pinned.
const authorizedSessionID = "4d849e211f7078bd8d27a748a7ac0ddfe164d2ef5c0e29e6e30292a371276320"

// A Phala Cloud request on the pinned path is encrypted with E2EE v2 to the
// authorized gateway key, pins the authorized attested sessions, goes to the
// attested TLS key, and its response decrypts. The keyset digest of the
// response decides whether the authorization generation stays: the verified
// digest keeps it, another digest relays the response and ends it, and no
// digest fails the request and ends it. A refusal of the pinned sessions
// (session_not_accepted) fails the attempt and ends the generation, so the
// next attempt verifies the sessions again.
func TestAuthorizedPhalaCloudACIv2(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, tc := range []struct {
			name, served string
			refuse       bool
			wantErr      bool
			ended        bool
		}{
			{"verified digest", "sha256:aa", false, false, false},
			{"other digest", "sha256:bb", false, false, true},
			{"no digest", "", false, true, true},
			{"sessions refused", "sha256:aa", true, true, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				testAuthorizedPhalaCloud(t, authority, tc.served, tc.refuse, tc.wantErr, tc.ended)
			})
		}
	})
}

// A Phala Cloud authorization without a pinned session sends no request.
func TestAuthorizedPhalaCloudRequiresPinnedSessions(t *testing.T) {
	route, err := provider.NewResolvedRoute("https://tee.redpill.ai", "")
	if err != nil {
		t.Fatal(err)
	}
	prov := &provider.Provider{Name: "phalacloud", E2EE: true, Encryptor: aci.NewE2EE(), Preparer: phalacloud.NewPreparer("test")}
	_, _, err = provider.PrepareInference(t.Context(), prov, route, &provider.InferenceInput{Body: []byte(`{"model":"m","messages":[]}`), Path: "/v1/chat/completions", ContentType: "application/json"})
	if err == nil || !strings.Contains(err.Error(), "no verified attested session") {
		t.Fatalf("err = %v, want the missing pin", err)
	}
}

func testAuthorizedPhalaCloud(t *testing.T, authority *testtls.Authority, served string, refuse, wantErr, ended bool) {
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
			Provider struct {
				ACISessionIDs []string `json:"aci_session_ids"`
			} `json:"provider"`
		}
		if err := json.Unmarshal(body, &b); err != nil || len(b.Messages) != 1 {
			t.Errorf("request body: %v", err)
			return
		}
		if len(b.Provider.ACISessionIDs) != 1 || b.Provider.ACISessionIDs[0] != authorizedSessionID {
			t.Errorf("provider.aci_session_ids = %q, want the authorized session", b.Provider.ACISessionIDs)
		}
		if refuse {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = io.WriteString(w, `{"error":{"message":"none of the pinned sessions can serve this request","type":"session_not_accepted","code":null,"param":null}}`)
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
		ACISessionIDs: []string{authorizedSessionID},
		TLSAuthority:  route.Authority(), TLSKeyFP: hex.EncodeToString(fingerprint[:]),
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
