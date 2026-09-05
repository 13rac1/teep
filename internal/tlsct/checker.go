package tlsct

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/ctutil"
	"github.com/google/certificate-transparency-go/loglist3"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
)

const (
	certCacheTTL    = time.Hour
	logListCacheTTL = 24 * time.Hour
)

const ctEnabledDefault = true

var defaultChecker = NewChecker()

// TLS verification callbacks do not expose a request context. The HTTP
// client's hard timeout bounds log-list retrieval on this context.
var tlsHandshakeContext = context.Background()

type certCacheEntry struct {
	checkedAt time.Time
}

// Checker verifies SCT evidence using Google's CT package and public log list.
// Successful checks are cached briefly to avoid repeated work across new and
// pooled connections presenting the same certificate.
type Checker struct {
	mu      sync.Mutex
	entries map[string]certCacheEntry
	enabled atomic.Bool

	logListMu   sync.RWMutex
	logList     *loglist3.LogList
	logListAt   time.Time
	logListLock sync.Mutex
	logListHTTP *http.Client
}

// NewChecker creates a CT checker with in-memory caches.
func NewChecker() *Checker {
	dt, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		panic("http.DefaultTransport is not *http.Transport")
	}
	base := dt.Clone()
	base.MaxIdleConnsPerHost = 4
	base.IdleConnTimeout = 90 * time.Second
	base.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}

	c := &Checker{
		entries: make(map[string]certCacheEntry),
		logListHTTP: &http.Client{
			CheckRedirect: RejectRedirect,
			Timeout:       20 * time.Second,
			Transport:     WrapLogging(base),
		},
	}
	c.enabled.Store(ctEnabledDefault)
	return c
}

// DefaultChecker returns the shared process-wide CT checker.
func DefaultChecker() *Checker { return defaultChecker }

// SetEnabled controls whether CT verification is enforced by this checker.
func (c *Checker) SetEnabled(enabled bool) {
	if c == nil {
		return
	}
	c.enabled.Store(enabled)
}

// NewHTTPClient returns an HTTP client that enforces CT during public HTTPS
// TLS handshakes, before sending HTTP requests. All outgoing requests are
// logged at DEBUG level via WrapLogging.
func NewHTTPClient(timeout time.Duration, ctEnabled ...bool) *http.Client {
	dt, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		panic("http.DefaultTransport is not *http.Transport")
	}
	client := NewHTTPClientWithTransport(timeout, dt.Clone(), ctEnabled...)
	client.Transport = WrapLogging(client.Transport)
	return client
}

// NewHTTPClientWithTransport returns an HTTP client that enforces CT during
// every public HTTPS TLS handshake, before any HTTP request bytes are sent,
// while using the provided base transport settings.
func NewHTTPClientWithTransport(timeout time.Duration, base *http.Transport, ctEnabled ...bool) *http.Client {
	if base == nil {
		dt, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			panic("http.DefaultTransport is not *http.Transport")
		}
		base = dt.Clone()
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if base.TLSClientConfig != nil {
		tlsConfig = base.TLSClientConfig.Clone()
		if tlsConfig.MinVersion < tls.VersionTLS13 {
			tlsConfig.MinVersion = tls.VersionTLS13
		}
	}
	if ctEnabledFromOpt(ctEnabled...) {
		validateCTTransport(base)
		addCTVerifyConnection(tlsConfig, defaultChecker)
	}
	base.TLSClientConfig = tlsConfig
	return &http.Client{
		CheckRedirect: RejectRedirect,
		Timeout:       timeout,
		Transport:     base,
	}
}

func validateCTTransport(base *http.Transport) {
	if base.DialTLSContext != nil || base.DialTLS != nil { //nolint:staticcheck // deprecated hook must also be rejected
		panic("CT-enforced transport must not provide a custom TLS dialer")
	}
	if config := base.TLSClientConfig; config != nil {
		if config.InsecureSkipVerify {
			panic("CT-enforced transport must not disable WebPKI verification")
		}
		if config.RootCAs != nil {
			panic("CT-enforced transport must use system root CAs")
		}
	}
}

func ctEnabledFromOpt(enabled ...bool) bool {
	if len(enabled) == 0 {
		return ctEnabledDefault
	}
	return enabled[0]
}

func addCTVerifyConnection(config *tls.Config, checker *Checker) {
	previousVerify := config.VerifyConnection
	configuredServerName := config.ServerName
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if previousVerify != nil {
			if err := previousVerify(state); err != nil {
				return err
			}
		}
		host := ctConnectionHost(&state, configuredServerName)
		if err := checker.checkTLSState(host, &state, checker.loadLogListForHandshake); err != nil {
			return &ctVerificationError{err: err}
		}
		return nil
	}
}

func ctConnectionHost(state *tls.ConnectionState, configuredServerName string) string {
	if state.ServerName != "" {
		return state.ServerName
	}
	if configuredServerName != "" {
		return configuredServerName
	}
	if len(state.PeerCertificates) == 0 {
		return ""
	}
	var privateIP string
	for _, ip := range state.PeerCertificates[0].IPAddresses {
		if !isPrivateHost(ip.String()) {
			return ip.String()
		}
		if privateIP == "" {
			privateIP = ip.String()
		}
	}
	return privateIP
}

// CheckTLSState verifies that the peer cert chain provides valid SCT evidence
// anchored to a known CT log in Google's public log list.
func (c *Checker) CheckTLSState(ctx context.Context, host string, state *tls.ConnectionState) error {
	return c.checkTLSState(host, state, func() (*loglist3.LogList, error) {
		return c.loadLogList(ctx)
	})
}

func (c *Checker) checkTLSState(
	host string,
	state *tls.ConnectionState,
	loadLogList func() (*loglist3.LogList, error),
) error {
	if c == nil || !c.enabled.Load() {
		return nil
	}
	if isPrivateHost(host) {
		return nil
	}
	if state == nil || len(state.PeerCertificates) == 0 {
		return errors.New("missing peer certificate")
	}

	leaf := state.PeerCertificates[0]
	cacheKey := certCacheKey(host, leaf)

	c.mu.Lock()
	if e, ok := c.entries[cacheKey]; ok && time.Since(e.checkedAt) <= certCacheTTL {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	ctChain, err := toCTChain(state.PeerCertificates)
	if err != nil {
		return fmt.Errorf("parse certificate chain for CT: %w", err)
	}
	if len(ctChain) == 0 {
		return errors.New("empty certificate chain")
	}

	type sourceSCT struct {
		sct      *ct.SignedCertificateTimestamp
		embedded bool
	}
	var scts []sourceSCT

	embedded, err := x509util.ParseSCTsFromCertificate(leaf.Raw)
	if err == nil {
		for _, s := range embedded {
			scts = append(scts, sourceSCT{sct: s, embedded: true})
		}
	}

	for i := range state.SignedCertificateTimestamps {
		raw := state.SignedCertificateTimestamps[i]
		sct, exErr := x509util.ExtractSCT(&ctx509.SerializedSCT{Val: raw})
		if exErr != nil {
			continue
		}
		scts = append(scts, sourceSCT{sct: sct, embedded: false})
	}

	if len(scts) == 0 {
		return errors.New("no SCTs found in certificate or TLS handshake")
	}

	logList, err := loadLogList()
	if err != nil {
		return fmt.Errorf("load CT log list: %w", err)
	}

	var verifyErrs []string
	for _, candidate := range scts {
		log := logList.FindLogByKeyHash(candidate.sct.LogID.KeyID)
		if log == nil {
			verifyErrs = append(verifyErrs, "SCT log ID not found in trusted log list")
			continue
		}
		pub, pkErr := ctx509.ParsePKIXPublicKey(log.Key)
		if pkErr != nil {
			verifyErrs = append(verifyErrs, "parse log public key: "+pkErr.Error())
			continue
		}
		if err := ctutil.VerifySCT(pub, ctChain, candidate.sct, candidate.embedded); err != nil {
			verifyErrs = append(verifyErrs, err.Error())
			continue
		}

		c.addCacheEntry(cacheKey)
		return nil
	}

	if len(verifyErrs) == 0 {
		return errors.New("no verifiable SCTs")
	}
	return fmt.Errorf("no valid SCTs: %s", strings.Join(verifyErrs, "; "))
}

func (c *Checker) addCacheEntry(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) > 1024 {
		now := time.Now()
		for k, e := range c.entries {
			if now.Sub(e.checkedAt) > certCacheTTL {
				delete(c.entries, k)
			}
		}
		// Hard cap: if still over limit after TTL sweep, evict oldest.
		for len(c.entries) > 1024 {
			var oldestKey string
			var oldestTime time.Time
			for k, e := range c.entries {
				if oldestKey == "" || e.checkedAt.Before(oldestTime) {
					oldestKey = k
					oldestTime = e.checkedAt
				}
			}
			delete(c.entries, oldestKey)
		}
	}
	c.entries[key] = certCacheEntry{checkedAt: time.Now()}
}

func (c *Checker) loadLogList(parentCtx context.Context) (*loglist3.LogList, error) {
	return c.loadLogListWithRequest(func() (*http.Request, func(), error) {
		ctx, cancel := context.WithTimeout(parentCtx, 20*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, loglist3.AllLogListURL, http.NoBody)
		if err != nil {
			cancel()
			return nil, nil, err
		}
		return req, cancel, nil
	})
}

// loadLogListForHandshake is used by tls.Config.VerifyConnection, which does
// not expose a request context. logListHTTP has a hard 20-second client
// timeout, so the handshake remains bounded.
func (c *Checker) loadLogListForHandshake() (*loglist3.LogList, error) {
	return c.loadLogListWithRequest(func() (*http.Request, func(), error) {
		req, err := http.NewRequestWithContext(tlsHandshakeContext, http.MethodGet, loglist3.AllLogListURL, http.NoBody)
		return req, func() {}, err
	})
}

func (c *Checker) loadLogListWithRequest(
	newRequest func() (*http.Request, func(), error),
) (*loglist3.LogList, error) {
	c.logListMu.RLock()
	if c.logList != nil && time.Since(c.logListAt) <= logListCacheTTL {
		ll := c.logList
		c.logListMu.RUnlock()
		return ll, nil
	}
	c.logListMu.RUnlock()

	c.logListLock.Lock()
	defer c.logListLock.Unlock()

	c.logListMu.RLock()
	if c.logList != nil && time.Since(c.logListAt) <= logListCacheTTL {
		ll := c.logList
		c.logListMu.RUnlock()
		return ll, nil
	}
	c.logListMu.RUnlock()

	req, cleanup, err := newRequest()
	if err != nil {
		return nil, err
	}
	defer cleanup()
	SetUserAgent(req)
	resp, err := c.logListHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("HTTP %d while fetching log list: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	ll, err := loglist3.NewFromJSON(body)
	if err != nil {
		return nil, err
	}

	c.logListMu.Lock()
	c.logList = ll
	c.logListAt = time.Now()
	c.logListMu.Unlock()

	return ll, nil
}

func toCTChain(chain []*x509.Certificate) ([]*ctx509.Certificate, error) {
	out := make([]*ctx509.Certificate, 0, len(chain))
	for i := range chain {
		if chain[i] == nil {
			continue
		}
		parsed, err := ctx509.ParseCertificate(chain[i].Raw)
		if err != nil {
			return nil, fmt.Errorf("parse cert %d: %w", i, err)
		}
		out = append(out, parsed)
	}
	return out, nil
}

func certCacheKey(host string, cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return strings.ToLower(host) + "\x00" + hex.EncodeToString(h[:])
}

func isPrivateHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return true
	}
	if hostOnly, _, err := net.SplitHostPort(h); err == nil {
		h = hostOnly
	}
	if h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast()
	}
	return false
}
