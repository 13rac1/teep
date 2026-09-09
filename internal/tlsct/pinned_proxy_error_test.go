package tlsct

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestPinnedProxySelectionPreservesCause(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		upstream := authority.NewTLSServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("proxy selection failure must prevent requests")
		}))
		cause := &url.Error{Op: "parse", URL: "https://user:secret@proxy.invalid", Err: errors.New("invalid proxy")}
		base := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) { return nil, cause }}
		identity := pinnedTestIdentity(t, upstream.URL, certificateSPKI(t, upstream))
		client, err := NewSPKIPinnedHTTPClientWithTransport(0, base, identity, false)
		if client != nil {
			client.CloseIdleConnections()
			t.Fatal("proxy selection failure returned a client")
		}
		if !errors.Is(err, cause) {
			t.Fatal("proxy selection cause was lost")
		}
		var parsed *url.Error
		if !errors.As(err, &parsed) || parsed != cause {
			t.Fatal("proxy selection error type was lost")
		}
		if err.Error() != "select proxy for attested origin" {
			t.Fatal("proxy selection message exposes the underlying error")
		}
	})
}
