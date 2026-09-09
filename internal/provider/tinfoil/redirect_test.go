package tinfoil

import (
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestTrustedRootFetcherRejectsRedirectWithoutRetry(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		var requests atomic.Int32
		ts := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			w.Header().Set("Location", "/target")
			w.WriteHeader(http.StatusFound)
		}))
		client := tlsct.NewHTTPClient(time.Second)
		defer client.CloseIdleConnections()
		f := newTrustedRootFetcher(t.Context(), client)
		if _, err := f.DownloadFile(ts.URL, 1024, time.Second); err == nil {
			t.Fatal("trusted-root fetch accepted a redirect")
		}
		if requests.Load() != 1 {
			t.Fatalf("got %d requests, want one", requests.Load())
		}
	})
}
