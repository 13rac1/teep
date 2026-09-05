package tlsct_test

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestOutboundClientsRejectRedirects(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		var targets atomic.Int32
		target := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			targets.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}))
		source := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/target" {
				targets.Add(1)
			}
			if r.URL.Path == "/ok" || r.URL.Path == "/target" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			location := "/target"
			if r.URL.Query().Get("cross") == "true" {
				location = target.URL
			}
			status, err := strconv.Atoi(r.URL.Query().Get("status"))
			if err != nil {
				t.Error(err)
				return
			}
			w.Header().Set("Location", location)
			w.WriteHeader(status)
		}))
		fp := sha256.Sum256(source.Certificate().RawSubjectPublicKeyInfo)
		pinned, err := tlsct.NewSPKIPinnedHTTPClientWithTransport(time.Second, tlsct.NewPooledTransport(), hex.EncodeToString(fp[:]), true)
		if err != nil {
			t.Fatal(err)
		}
		clients := map[string]*http.Client{
			"discovery_and_online":       tlsct.NewHTTPClient(time.Second),
			"attestation_and_collateral": config.NewAttestationClient(false),
			"inference":                  tlsct.NewHTTPClientWithTransport(time.Second, tlsct.NewPooledTransport()),
			"pinned_inference":           pinned,
		}
		for name, client := range clients {
			t.Run(name, func(t *testing.T) {
				defer client.CloseIdleConnections()
				resp, err := client.Get(source.URL + "/ok")
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusNoContent {
					t.Fatal("direct request failed")
				}
				for _, cross := range []string{"false", "true"} {
					for _, status := range []int{300, 301, 302, 303, 304, 305, 307, 308} {
						resp, err := client.Get(source.URL + "/redirect?cross=" + cross + "&status=" + strconv.Itoa(status))
						if err != nil {
							t.Fatal(err)
						}
						resp.Body.Close()
						if resp.StatusCode != status {
							t.Fatalf("status = %d, want %d", resp.StatusCode, status)
						}
					}
				}
			})
		}
		if targets.Load() != 0 {
			t.Fatalf("redirect targets received %d requests", targets.Load())
		}
	})
}
