package tlsct

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
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
	client := NewHTTPClientWithTransport(timeout, NewPooledTransport(), ctEnabled...)
	client.Transport = WrapLogging(client.Transport)
	return client
}

// NewHTTPClientWithTransport returns an HTTP client that enforces CT during
// every public HTTPS TLS handshake, before any HTTP request bytes are sent,
// while using the provided base transport settings.
func NewHTTPClientWithTransport(timeout time.Duration, base *http.Transport, ctEnabled ...bool) *http.Client {
	if base == nil {
		base = NewPooledTransport()
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
		listed, err := findLog(logList, candidate.sct.LogID.KeyID)
		if err != nil {
			verifyErrs = append(verifyErrs, err.Error())
			continue
		}
		sctTime := time.UnixMilli(int64(candidate.sct.Timestamp)) //nolint:gosec // SCT timestamps are milliseconds since 1970 and fit in int64
		if err := checkSCTTime(sctTime, leaf.NotBefore, time.Now()); err != nil {
			verifyErrs = append(verifyErrs, err.Error())
			continue
		}
		if err := listed.acceptsSCT(sctTime, leaf.NotAfter); err != nil {
			verifyErrs = append(verifyErrs, err.Error())
			continue
		}
		pub, pkErr := ctx509.ParsePKIXPublicKey(listed.key)
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

// listedLog holds what the SCT check needs of a log in the CT log list.
type listedLog struct {
	key      []byte
	state    *loglist3.LogStates
	interval *loglist3.TemporalInterval
}

// findLog returns the log in either CT log collection whose ID is id. A log
// ID that is not listed, or that is listed more than once, is an error: with
// two entries, the state and interval of one could hide those of the other.
func findLog(list *loglist3.LogList, id [sha256.Size]byte) (listedLog, error) {
	var found []listedLog
	for _, op := range list.Operators {
		for _, log := range op.Logs {
			if subtle.ConstantTimeCompare(log.LogID, id[:]) == 1 {
				found = append(found, listedLog{key: log.Key, state: log.State, interval: log.TemporalInterval})
			}
		}
		for _, log := range op.TiledLogs {
			if subtle.ConstantTimeCompare(log.LogID, id[:]) == 1 {
				found = append(found, listedLog{key: log.Key, state: log.State, interval: log.TemporalInterval})
			}
		}
	}
	// The SCT signature does not cover the log ID, so a listed key must hash
	// to its ID; otherwise one key could appear under a second, trusted ID.
	for _, l := range found {
		keyHash := sha256.Sum256(l.key)
		if subtle.ConstantTimeCompare(keyHash[:], id[:]) != 1 {
			return listedLog{}, errors.New("SCT log ID does not match the hash of its key in the CT log list")
		}
	}
	switch len(found) {
	case 0:
		return listedLog{}, errors.New("SCT log ID not found in the CT log list")
	case 1:
		return found[0], nil
	default:
		return listedLog{}, errors.New("SCT log ID listed more than once in the CT log list")
	}
}

// stateCount returns the number of states set in ls. The list should set one;
// LogStatus picks the first one set, which could hide a rejected state.
func stateCount(ls *loglist3.LogStates) int {
	n := 0
	for _, set := range []bool{ls.Pending != nil, ls.Qualified != nil, ls.Usable != nil, ls.ReadOnly != nil, ls.Retired != nil, ls.Rejected != nil} {
		if set {
			n++
		}
	}
	return n
}

// sctBeforeNotBefore and sctFutureSkew bound the SCT timestamp. A log issues
// the SCT for a certificate shortly before the CA signs it, and CAs date
// NotBefore at or before signing, so an honest SCT is not more than a day
// older than NotBefore. An SCT dated in the future is refused, with an
// allowance for clock skew.
const (
	sctBeforeNotBefore = 24 * time.Hour
	sctFutureSkew      = time.Hour
)

// checkSCTTime refuses an SCT dated long before the certificate's NotBefore
// or in the future. Without it, the holder of a retired or read-only log's
// key could date an SCT before the state change.
func checkSCTTime(sctTime, notBefore, now time.Time) error {
	if sctTime.Before(notBefore.Add(-sctBeforeNotBefore)) {
		return errors.New("SCT timestamp is more than a day before the certificate's NotBefore")
	}
	if sctTime.After(now.Add(sctFutureSkew)) {
		return errors.New("SCT timestamp is in the future")
	}
	return nil
}

// acceptsSCT reports, as an error, why an SCT that the log issued at sctTime
// for a certificate that expires at notAfter cannot count. The list holds
// every known log, including test, pending and rejected logs, so only a log
// in a trusted state counts: usable or qualified, or read-only or retired for
// an SCT issued before that state began. When the log has a temporal
// interval, notAfter must fall inside it.
func (l listedLog) acceptsSCT(sctTime, notAfter time.Time) error {
	if l.state != nil && stateCount(l.state) > 1 {
		return errors.New("SCT log has more than one state in the CT log list")
	}
	switch l.state.LogStatus() {
	case loglist3.UsableLogStatus, loglist3.QualifiedLogStatus:
	case loglist3.ReadOnlyLogStatus:
		if !sctTime.Before(l.state.ReadOnly.Timestamp) {
			return errors.New("SCT issued after its log became read-only")
		}
	case loglist3.RetiredLogStatus:
		if !sctTime.Before(l.state.Retired.Timestamp) {
			return errors.New("SCT issued after its log was retired")
		}
	case loglist3.PendingLogStatus:
		return errors.New("SCT log is pending, not trusted yet")
	case loglist3.RejectedLogStatus:
		return errors.New("SCT log is rejected")
	default:
		return errors.New("SCT log has no state in the CT log list")
	}
	if l.interval != nil && (notAfter.Before(l.interval.StartInclusive) || !notAfter.Before(l.interval.EndExclusive)) {
		return errors.New("certificate expiry is outside the temporal interval of the SCT log")
	}
	return nil
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
