package tinfoil

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestTrustedRootVerificationCancellation(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, headers := range []bool{false, true} {
			t.Run(map[bool]string{false: "headers", true: "body"}[headers], func(t *testing.T) {
				started := make(chan struct{})
				var once sync.Once
				ts := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/ready" {
						_, _ = w.Write([]byte("ready"))
						return
					}
					if headers {
						w.WriteHeader(http.StatusOK)
						_ = http.NewResponseController(w).Flush()
					}
					once.Do(func() { close(started) })
					<-r.Context().Done()
				}))
				defer ts.Close()
				client := tlsct.NewHTTPClient(30 * time.Second)
				defer client.CloseIdleConnections()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				fetch := newTrustedRootFetcher(ctx, client)
				finished := make(chan error, 1)
				go func() { _, err := fetch.DownloadFile(ts.URL, 1024, time.Second); finished <- err }()
				select {
				case <-started:
				case <-time.After(5 * time.Second):
					t.Fatal("root download did not start")
				}
				cancel()
				select {
				case err := <-finished:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("cancellation lost: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("root download outlived verification cancellation")
				}
				if _, err := fetch.DownloadFile(ts.URL+"/ready", 1024, time.Second); !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled verification started another download: %v", err)
				}
				other := newTrustedRootFetcher(t.Context(), client)
				if _, err := other.DownloadFile(ts.URL+"/ready", 1024, time.Second); err != nil {
					t.Fatalf("cancellation affected another verification: %v", err)
				}
			})
		}
	})
}
