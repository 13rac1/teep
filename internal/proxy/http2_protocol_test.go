package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/provider/tinfoil"
	"github.com/13rac1/teep/internal/tlsct/testtls"
	"golang.org/x/net/http2"
)

// A protocol reset after the complete POST body does not establish whether
// inference ran. Exercise the production encrypted request constructors and
// attempt loop, including net/http's version-dependent internal retry logic.
func TestAuthorizedProtocolErrorNeverReplays(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, name := range []string{"neardirect", "tinfoil_v3_cloud"} {
			t.Run(name, func(t *testing.T) { testConsumedProtocolError(t, authority, name) })
		}
	})
}

func testConsumedProtocolError(t *testing.T, authority *testtls.Authority, name string) {
	t.Helper()
	var consumed atomic.Int32
	upstream := authority.NewTLSServerWithConfig(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("HTTP/1.1 handler used")
	}), func(ts *httptest.Server) {
		ts.TLS.NextProtos = []string{"h2"}
		ts.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){"h2": func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
			resetConsumedHTTP2Posts(t, conn, &consumed)
		}}
	})
	defer upstream.Close()
	server := newTLSBindingTestServerHandle()
	server.authorizations = newAuthorizationStore(10, 2, time.Second)
	defer server.Close()
	route, err := provider.NewResolvedRoute(upstream.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	prov := &provider.Provider{Name: name, BaseURL: upstream.URL, StaticRoute: route, UsesTLSBinding: true, E2EE: true}
	var signingKey string
	if name == "neardirect" {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(private)
		signingKey = hex.EncodeToString(public)
		prov.Encryptor, prov.Preparer = neardirect.NewE2EE(), neardirect.NewPreparer("test")
	} else {
		private := authorizedTestKey(t)
		signingKey = hex.EncodeToString(private.PublicKey().Bytes())
		prov.Encryptor, prov.Preparer = tinfoil.NewE2EE(), tinfoil.NewPreparer("test")
	}
	key, err := route.AuthorizationKey(name, "model")
	if err != nil {
		t.Fatal(err)
	}
	fp := sha256.Sum256(upstream.Certificate().RawSubjectPublicKeyInfo)
	report := &attestation.VerificationReport{Provider: name, Model: "model", TLSAuthority: route.Authority(), TLSKeyFP: hex.EncodeToString(fp[:]), Factors: []attestation.FactorResult{{Name: attestation.FactorTEEReportData, Status: attestation.Pass}}}
	value, err := newAuthorization(key, report, signingKey, true, false, time.Time{}, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	loadTestAuthorization(t, server.authorizations, key, value)
	input := &authorizedRequest{provider: prov, route: route, key: key, body: []byte(`{"model":"model","messages":[{"role":"user","content":"test"}]}`), path: "/v1/chat/completions", contentType: "application/json", endpoint: e2ee.EndpointChat}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	prepared, err := server.prepareAuthorizedRequest(ctx, input, value)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Request.GetBody != nil || prepared.Request.Header.Get("Idempotency-Key") != "" || prepared.Request.Header.Get("X-Idempotency-Key") != "" {
		t.Fatal("encrypted inference enables implicit replay")
	}
	cleanupAuthorized(prepared)
	result, err := server.authorizedRoundtrip(ctx, input)
	if result.upstream != nil {
		cleanupAuthorized(result.upstream)
	}
	if err == nil || consumed.Load() != 1 {
		t.Fatalf("consumed requests=%d error=%v", consumed.Load(), err)
	}
	if _, ok := server.authorizations.acquire(key); !ok {
		t.Fatal("protocol reset invalidated valid keys")
	}
}

func resetConsumedHTTP2Posts(t *testing.T, conn *tls.Conn, consumed *atomic.Int32) {
	t.Helper()
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Error(err)
		return
	}
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		t.Error(err)
		return
	}
	if string(preface) != http2.ClientPreface {
		t.Error("invalid HTTP/2 preface")
		return
	}
	framer := http2.NewFramer(conn, conn)
	framer.SetMaxReadFrameSize(1 << 20)
	if err := framer.WriteSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 32}); err != nil {
		t.Error(err)
		return
	}
	total := 0
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if err := framer.WriteSettingsAck(); err != nil {
					return
				}
			}
		case *http2.DataFrame:
			total += len(f.Data())
			if total > 2<<20 {
				t.Error("request exceeds test bound")
				return
			}
			if f.StreamEnded() {
				if total == 0 {
					t.Error("empty encrypted POST")
				}
				consumed.Add(1)
				if err := framer.WriteRSTStream(f.StreamID, http2.ErrCodeProtocol); err != nil {
					return
				}
			}
		}
	}
}
