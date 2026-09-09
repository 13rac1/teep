package config

import (
	"io"
	"net/http"
	"net/http/httptrace"
	"testing"

	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestAttestationClientCloseIdleConnections(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		server := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
		defer server.Close()
		client := NewAttestationClient(false)
		defer client.CloseIdleConnections()
		client.Transport = capture.WrapRecording(client.Transport)
		for i := range 2 {
			reused := false
			ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }})
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, http.NoBody)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if i == 1 && reused {
				t.Fatal("CloseIdleConnections did not close the idle attestation connection")
			}
			client.CloseIdleConnections()
		}
	})
}
