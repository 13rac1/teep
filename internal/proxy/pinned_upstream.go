package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct"
)

const maxPinnedUpstreamPools = 1000

func newUpstreamTransport() *http.Transport {
	return tlsct.NewPooledTransport()
}

type pinnedUpstreamKey struct {
	provider  string
	authority string
}

type pinnedUpstreamEntry struct {
	fingerprint string
	client      *http.Client
	transport   *http.Transport
	lastUsed    time.Time
}

type pinnedUpstreamPools struct {
	mu      sync.Mutex
	entries map[pinnedUpstreamKey]*pinnedUpstreamEntry
}

func newPinnedUpstreamPools() *pinnedUpstreamPools {
	return &pinnedUpstreamPools{entries: make(map[pinnedUpstreamKey]*pinnedUpstreamEntry)}
}

// pinnedUpstreamClient returns a connection pool whose TLS handshakes are
// authenticated against expectedSPKI before request transmission. A change in
// the attested fingerprint atomically replaces the selectable pool for the
// provider authority; in-flight users of the old pool may finish, but no later
// request can obtain it from this registry.
func (s *Server) pinnedUpstreamClient(prov *provider.Provider, baseURL, expectedSPKI string) (*http.Client, error) {
	if s.pinnedUpstreams == nil {
		return nil, errors.New("TLS-pinned upstream pool is not initialized")
	}
	if s.cfg == nil {
		return nil, errors.New("server config is not initialized")
	}
	authority, err := pinnedUpstreamAuthority(baseURL)
	if err != nil {
		return nil, err
	}
	key := pinnedUpstreamKey{provider: prov.Name, authority: authority}

	s.pinnedUpstreams.mu.Lock()
	if entry := s.pinnedUpstreams.entries[key]; entry != nil &&
		tlsct.SPKIFingerprintsEqual(entry.fingerprint, expectedSPKI) {
		entry.lastUsed = time.Now()
		client := entry.client
		s.pinnedUpstreams.mu.Unlock()
		return client, nil
	}

	base := newUpstreamTransport()
	client, err := tlsct.NewSPKIPinnedHTTPClientWithTransport(0, base, expectedSPKI, !s.cfg.Offline)
	if err != nil {
		s.pinnedUpstreams.mu.Unlock()
		return nil, err
	}
	client.Transport = tlsct.WrapCounting(
		tlsct.WrapLogging(client.Transport),
		func() { s.stats.httpRequests.Add(1) },
		func() { s.stats.httpErrors.Add(1) },
	)

	old := s.pinnedUpstreams.entries[key]
	s.pinnedUpstreams.entries[key] = &pinnedUpstreamEntry{
		fingerprint: expectedSPKI,
		client:      client,
		transport:   base,
		lastUsed:    time.Now(),
	}
	evicted := s.pinnedUpstreams.evictOldestLocked(key)
	s.pinnedUpstreams.mu.Unlock()

	if old != nil {
		old.transport.CloseIdleConnections()
	}
	if evicted != nil {
		evicted.transport.CloseIdleConnections()
	}
	return client, nil
}

func (p *pinnedUpstreamPools) evictOldestLocked(exclude pinnedUpstreamKey) *pinnedUpstreamEntry {
	if len(p.entries) <= maxPinnedUpstreamPools {
		return nil
	}
	var oldestKey pinnedUpstreamKey
	var oldest *pinnedUpstreamEntry
	for key, entry := range p.entries {
		if key == exclude {
			continue
		}
		if oldest == nil || entry.lastUsed.Before(oldest.lastUsed) {
			oldestKey = key
			oldest = entry
		}
	}
	if oldest != nil {
		delete(p.entries, oldestKey)
	}
	return oldest
}

func (s *Server) retirePinnedUpstream(prov *provider.Provider, baseURL string) {
	if s.pinnedUpstreams == nil {
		return
	}
	authority, err := pinnedUpstreamAuthority(baseURL)
	if err != nil {
		return
	}
	key := pinnedUpstreamKey{provider: prov.Name, authority: authority}
	s.pinnedUpstreams.mu.Lock()
	entry := s.pinnedUpstreams.entries[key]
	delete(s.pinnedUpstreams.entries, key)
	s.pinnedUpstreams.mu.Unlock()
	if entry != nil {
		entry.transport.CloseIdleConnections()
	}
}

func pinnedUpstreamAuthority(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse TLS-pinned upstream URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("TLS-pinned upstream URL %q must be an absolute HTTPS URL without userinfo", baseURL)
	}
	return strings.ToLower(u.Host), nil
}
