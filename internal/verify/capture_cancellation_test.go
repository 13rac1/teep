package verify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/provider/tinfoil"
)

type captureDiscoveryTransport struct {
	base   http.RoundTripper
	target *url.URL
}

func (r captureDiscoveryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme, clone.URL.Host = r.target.Scheme, r.target.Host
	return r.base.RoundTrip(clone)
}

func TestCanceledDiscoveryCapture(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	client := server.Client()
	state := &verificationCapture{discovery: capture.WrapRecording(captureDiscoveryTransport{client.Transport, target})}
	client.Transport = state.discovery
	resolver := tinfoil.NewDirectResolver("test", true)
	resolver.SetClient(client)
	ctx, cancel := context.WithCancel(t.Context())
	finished := make(chan struct{})
	go func() { _, _ = resolver.ResolveMapping(ctx, "model"); close(finished) }()
	<-started
	cancel()
	<-finished
	// Capture collection can overlap detached discovery after cancellation.
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 100000 {
			_ = state.entries()
		}
	})
	close(release)
	wg.Wait()
	_, _ = resolver.ResolveMapping(t.Context(), "model")
	if len(state.entries()) == 0 {
		t.Fatal("completed discovery was not recorded")
	}
}
