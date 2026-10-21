package config

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestAttestationClientCloseIdleConnections(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		closed := make(chan struct{}, 1)
		server := authority.NewTLSServerWithConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }), func(server *httptest.Server) {
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateClosed {
					select {
					case closed <- struct{}{}:
					default:
					}
				}
			}
		})
		defer server.Close()
		client := NewAttestationClient(false)
		defer client.CloseIdleConnections()
		client.Transport = capture.WrapRecording(client.Transport)
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, http.NoBody)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		client.CloseIdleConnections()
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Fatal("CloseIdleConnections did not close the idle attestation connection")
		}
	})
}
