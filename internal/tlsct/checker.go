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

var defaultChecker = NewChecker()

type certCacheEntry struct {
	checkedAt time.Time
}

// Checker verifies SCT evidence using Google's CT package and public log list.
// Successful checks are cached briefly to avoid repeated work on pooled
// connections.
type Checker struct {
	mu      sync.Mutex
	entries map[string]certCacheEntry

	logListMu   sync.RWMutex
	logList     *loglist3.LogList
	logListAt   time.Time
	logListLock sync.Mutex
	logListHTTP *http.Client
}

// NewChecker creates a CT checker with in-memory caches.
func NewChecker() *Checker {
	base := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert // Go stdlib default transport type is *http.Transport.
	base.MaxIdleConnsPerHost = 4
	base.IdleConnTimeout = 90 * time.Second

	return &Checker{
		entries: make(map[string]certCacheEntry),
		logListHTTP: &http.Client{
			Timeout:   20 * time.Second,
			Transport: base,
		},
	}
}

// DefaultChecker returns the shared process-wide CT checker.
func DefaultChecker() *Checker { return defaultChecker }

// NewHTTPClient returns an HTTP client that enforces CT for all HTTPS requests.
func NewHTTPClient(timeout time.Duration) *http.Client {
	base := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert // Go stdlib default transport type is *http.Transport.
	return NewHTTPClientWithTransport(timeout, base)
}

// NewHTTPClientWithTransport returns an HTTP client that enforces CT for all
// HTTPS requests while using the provided base transport settings.
func NewHTTPClientWithTransport(timeout time.Duration, base *http.Transport) *http.Client {
	if base == nil {
		base = http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert // Go stdlib default transport type is *http.Transport.
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: WrapTransport(base),
	}
}

// WrapTransport wraps an existing transport with post-handshake CT checks.
func WrapTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &ctRoundTripper{base: base, checker: defaultChecker}
}

type ctRoundTripper struct {
	base    http.RoundTripper
	checker *Checker
}

func (t *ctRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if req.URL == nil || !strings.EqualFold(req.URL.Scheme, "https") {
		return resp, nil
	}
	if resp.TLS == nil {
		_ = resp.Body.Close()
		return nil, errors.New("missing TLS connection state")
	}
	if err := t.checker.CheckTLSState(req.Context(), req.URL.Hostname(), resp.TLS); err != nil {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("certificate transparency check failed: %w", err)
	}
	return resp, nil
}

// CheckTLSState verifies that the peer cert chain provides valid SCT evidence
// anchored to a known CT log in Google's public log list.
func (c *Checker) CheckTLSState(ctx context.Context, host string, state *tls.ConnectionState) error {
	if isPrivateHost(host) {
		return nil
	}
	if state == nil || len(state.PeerCertificates) == 0 {
		return errors.New("missing peer certificate")
	}

	leaf := state.PeerCertificates[0]
	h := sha256.Sum256(leaf.Raw)
	cacheKey := strings.ToLower(host) + "\x00" + hex.EncodeToString(h[:])

	c.mu.Lock()
	if e, ok := c.entries[cacheKey]; ok && time.Since(e.checkedAt) <= certCacheTTL {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	logList, err := c.loadLogList(ctx)
	if err != nil {
		return fmt.Errorf("load CT log list: %w", err)
	}

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

		c.mu.Lock()
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
		c.entries[cacheKey] = certCacheEntry{checkedAt: time.Now()}
		c.mu.Unlock()
		return nil
	}

	if len(verifyErrs) == 0 {
		return errors.New("no verifiable SCTs")
	}
	return fmt.Errorf("no valid SCTs: %s", strings.Join(verifyErrs, "; "))
}

func (c *Checker) loadLogList(parentCtx context.Context) (*loglist3.LogList, error) {
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

	ctx, cancel := context.WithTimeout(parentCtx, 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loglist3.AllLogListURL, http.NoBody)
	if err != nil {
		return nil, err
	}
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

func isPrivateHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return true
	}
	if hostOnly, _, err := net.SplitHostPort(h); err == nil {
		h = hostOnly
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast()
	}
	return false
}
