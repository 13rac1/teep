package proxy

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestInferenceRejectsRedirects(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		var requests atomic.Int32
		ts, fp := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			w.Header().Set("Location", "/target")
			w.WriteHeader(http.StatusTemporaryRedirect)
		}))
		for _, binding := range []bool{false, true} {
			s := newTLSBindingTestServerHandle()
			prov := &provider.Provider{Name: "test", BaseURL: ts.URL, UsesTLSBinding: binding}
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL, http.NoBody)
			if err != nil {
				t.Fatal(err)
			}
			sent, failure := s.sendUpstreamRequest(context.Background(), prov, "model", ts.URL, fp, req)
			if failure == nil || failure.code != http.StatusBadGateway || sent.resp != nil {
				t.Fatalf("redirect returned downstream response or wrong error: %+v, %v", sent, failure)
			}
		}
		if requests.Load() != 2 {
			t.Fatalf("received %d requests, want two source requests", requests.Load())
		}
	})
}
