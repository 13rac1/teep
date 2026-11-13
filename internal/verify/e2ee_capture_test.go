package verify

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee/aciv2test"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// A capturing run records the live E2EE test exchange: the status, the
// response headers and the raw SSE bytes, which receipt verification hashes.
// The API key is not recorded.
func TestE2EETestExchangeIsCaptured(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		gw := aciv2test.New(t)
		var stream string
		ts := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Error(err)
				return
			}
			r := gw.ReadRequest(req.Header, body)
			stream = gw.Stream(r, "chatcmpl-7", []string{"Hel", "lo"}, true)
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("X-Receipt-Id", "receipt-7")
			_, _ = io.WriteString(w, stream)
		}))
		defer ts.Close()

		capture := &verificationCapture{}
		ctx := withE2EERecorder(context.Background(), capture.recordE2EE)
		raw := &attestation.RawAttestation{BackendFormat: attestation.FormatACI1, SigningKey: gw.PubKeyHex()}
		got := testE2EE(ctx, raw, "phalacloud", &config.Provider{APIKey: "secret-api-key", BaseURL: ts.URL}, "TEE/m", false)
		if got == nil || got.Err != nil {
			t.Fatalf("testE2EE = %+v", got)
		}
		entries := capture.entries()
		if len(entries) != 1 {
			t.Fatalf("recorded %d entries, want 1", len(entries))
		}
		e := entries[0]
		if e.Method != http.MethodPost || !strings.HasSuffix(e.URL, "/v1/chat/completions") || e.Status != http.StatusOK {
			t.Errorf("entry %s %s %d", e.Method, e.URL, e.Status)
		}
		if e.Headers.Get("X-Receipt-Id") != "receipt-7" {
			t.Errorf("response headers = %v", e.Headers)
		}
		if string(e.Body) != stream {
			t.Error("recorded body is not the raw SSE stream")
		}
		if strings.Contains(string(e.ReqBody), "secret-api-key") || strings.Contains(e.URL, "secret-api-key") {
			t.Error("the API key was recorded")
		}
	})
}
