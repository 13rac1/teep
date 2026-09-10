package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestStandaloneTLSOnlyConnectionRetry(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, name := range []string{"neardirect", "nearcloud"} {
			for _, failure := range []string{"first_dial", "every_dial", "capacity"} {
				t.Run(name+"/"+failure, func(t *testing.T) { testTLSOnlyConnectionRetry(t, authority, name, failure) })
			}
		}
	})
}

func testTLSOnlyConnectionRetry(t *testing.T, authority *testtls.Authority, name, failure string) {
	t.Helper()
	model, err := e2ee.NewNearCloudSession()
	if err != nil {
		t.Fatal(err)
	}
	defer model.Zero()
	var received, dials atomic.Int32
	upstream := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("X-Encryption-Version") != "" {
			t.Error("invalid TLS-only request")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\ndata: [DONE]\n\n")
	}))
	route, err := provider.NewResolvedRoute(upstream.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	fp := sha256.Sum256(upstream.Certificate().RawSubjectPublicKeyInfo)
	identity, err := tlsct.NewTransportIdentity(route.Authority(), hex.EncodeToString(fp[:]))
	if err != nil {
		t.Fatal(err)
	}
	base := tlsct.NewPooledTransport()
	dial := base.DialContext
	base.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		n := dials.Add(1)
		if failure == "capacity" {
			return nil, tlsct.ErrConnectionCapacity
		}
		if n == 1 || failure == "every_dial" {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
		}
		return dial(ctx, network, address)
	}
	client, err := tlsct.NewSPKIPinnedHTTPClientWithTransport(0, base, identity, true)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	opts := &Options{ProviderName: name, Provider: &config.Provider{BaseURL: upstream.URL, APIKey: "test", E2EE: false}, ModelName: "model"}
	attempts := 0
	probe, err := tlsct.RunInferenceAttempts(t.Context(), func(ctx context.Context) (*standaloneProbe, bool, error) {
		attempts++
		return testStandaloneInference(ctx, opts, route, &attestation.RawAttestation{SigningKey: model.ClientEd25519PubHex()}, standaloneTestModelKey(t, model.ClientEd25519PubHex()), client)
	})
	wantAttempts, wantReceived := 2, int32(0)
	if failure == "capacity" {
		wantAttempts = 1
	}
	if failure == "first_dial" {
		wantReceived = 1
		if err != nil || probe == nil || probe.tlsInference == nil || !probe.tlsInference.Attempted || probe.e2ee != nil {
			t.Fatalf("TLS-only recovery failed: %v", err)
		}
	} else if err == nil {
		t.Fatal("failed connection reported success")
	}
	if attempts != wantAttempts || dials.Load() != int32(wantAttempts) || received.Load() != wantReceived {
		t.Fatalf("attempts=%d dials=%d received=%d", attempts, dials.Load(), received.Load())
	}
}
