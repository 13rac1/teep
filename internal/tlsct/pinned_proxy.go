package tlsct

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
)

// proxySelectionError retains the cause without exposing proxy credentials in logs.
type proxySelectionError struct{ cause error }

func (e *proxySelectionError) Error() string { return "select proxy for attested origin" }
func (e *proxySelectionError) Unwrap() error { return e.cause }

// configurePinnedProxy selects the proxy once for this origin's dedicated
// transport. For an HTTPS proxy, DialContext authenticates the outer TLS
// connection. net/http then performs CONNECT and the pinned origin handshake.
func configurePinnedProxy(base *http.Transport, authority string, ctEnabled bool) error {
	if base.Proxy == nil {
		return nil
	}
	selected, err := base.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: authority}})
	if err != nil {
		return &proxySelectionError{cause: err}
	}
	if selected == nil {
		base.Proxy = nil
		return nil
	}
	proxy := *selected
	if proxy.Scheme == "https" {
		if base.Dial != nil { //nolint:staticcheck // Reject deprecated dialers that cannot honor setup deadlines.
			return errors.New("HTTPS proxy requires a context-aware TCP dialer")
		}
		configureHTTPSProxyDial(base, &proxy, ctEnabled)
	}
	base.Proxy = http.ProxyURL(&proxy)
	return nil
}

func configureHTTPSProxyDial(base *http.Transport, proxy *url.URL, ctEnabled bool) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: proxy.Hostname(),
		NextProtos: []string{"http/1.1"}, // net/http sends CONNECT using HTTP/1.1.
	}
	if ctEnabled {
		addCTVerifyConnection(config, defaultChecker)
	}
	port := proxy.Port()
	if port == "" {
		port = "443"
	}
	proxy.Host = net.JoinHostPort(proxy.Hostname(), port)
	// Only net/http's TLS setup is omitted here: the dialer below has already
	// authenticated and encrypted the proxy connection before CONNECT is sent.
	proxy.Scheme = "http"
	dial := base.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: connectionSetupTimeout}).DialContext
	}
	budget := base.TLSHandshakeTimeout
	if budget <= 0 {
		budget = connectionSetupTimeout
	}
	base.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		bounded, cancel := context.WithTimeout(ctx, budget)
		defer cancel()
		secured := tls.Client(conn, config)
		if err := secured.HandshakeContext(bounded); err != nil {
			_ = secured.Close()
			return nil, err
		}
		return secured, nil
	}
}
