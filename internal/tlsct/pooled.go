package tlsct

import (
	"net"
	"net/http"
	"time"
)

const (
	// MaxConnectionsPerHost bounds active connections in each transport pool.
	MaxConnectionsPerHost  = 16
	connectionSetupTimeout = 5 * time.Minute
)

// NewPooledTransport returns the common attestation and inference transport.
// Request deadlines can end operations before the connection setup budgets.
// TLS and CT configuration is installed by the HTTP client constructor.
func NewPooledTransport() *http.Transport {
	return newPooledTransport(connectionSetupTimeout, connectionSetupTimeout)
}

func newPooledTransport(dialTimeout, handshakeTimeout time.Duration) *http.Transport {
	return &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: handshakeTimeout,
		ForceAttemptHTTP2:   true,
		MaxConnsPerHost:     MaxConnectionsPerHost,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
}
