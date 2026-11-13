package phalacloud

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/aci"
	"github.com/13rac1/teep/internal/tlsct"
)

// maxSessionEvidenceBytes bounds the Chutes session records that one
// verification fetches from the gateway. A Chutes evidence bundle was 3.9 MB
// on 2026-10-31, and the sessions of one model shared 10 bundles; verifying
// every bundle would cost about 39 MB for each full verification. The
// sessions of the Phala model CVM (276 KB) are always fetched and do not
// count against the limit.
const maxSessionEvidenceBytes = 8 << 20

// maxModelCVMBundles bounds the evidence bundles of the Phala model CVM
// that one verification fetches; each is at most aci.MaxSessionBytes. The
// gateway listed one on 2026-11-01 and two on 2026-11-02 (276 KB each).
const maxModelCVMBundles = 4

// sessionSet is the outcome of fetching the attested sessions of a model:
// the full records to audit, and the sessions that teep did not fetch.
type sessionSet struct {
	sessions []*aci.Session
	refused  []attestation.ACISessionRefusal
	err      error
	// listUnknown holds the members of the session list outside its entries
	// that teep does not define.
	listUnknown []string
}

// fetchSessions lists the attested sessions behind model and fetches a
// bounded set of their full records (ACI/1 §8.1). Sessions that the gateway
// established from one evidence fetch share their evidence digest, so one
// GET per digest gives every session of the bundle (aci.RebuildSession).
// The selection takes every bundle of the Phala model CVM, then Chutes
// bundles by the number of sessions they cover, largest first, while the
// fetched Chutes records stay within maxSessionEvidenceBytes. A record's
// size is known only after its GET, and the gateway sends the whole record
// even when teep stops reading, so the next GET starts only while the rest
// of the limit holds the largest Chutes record fetched so far. At most
// maxModelCVMBundles bundles of the Phala model CVM are fetched. Sessions of
// other verifiers are not fetched: teep cannot verify their evidence.
//
// Every request goes over a client pinned to the TLS key that the report
// binds, so the API key is sent only to that key, and each response must
// have come over that key.
func (a *Attester) fetchSessions(ctx context.Context, model string, identity tlsct.TransportIdentity) *sessionSet {
	client, err := a.sessionClient(identity)
	if err != nil {
		return &sessionSet{err: fmt.Errorf("session client: %w", err)}
	}
	defer client.CloseIdleConnections()
	f := &sessionFetcher{client: client, apiKey: a.apiKey, identity: identity}
	listURL := a.baseURL + aci.SessionsPath + "?" + url.Values{"model": {model}}.Encode()
	body, err := f.get(ctx, listURL, aci.MaxSessionListBytes)
	if err != nil {
		return &sessionSet{err: fmt.Errorf("session list: %w", err)}
	}
	entries, listUnknown, err := aci.ParseSessionList(body)
	if err != nil {
		return &sessionSet{err: err}
	}
	set := &sessionSet{listUnknown: listUnknown}
	budget, largest := int64(maxSessionEvidenceBytes), int64(0)
	modelCVM := 0
	for _, bundle := range selectBundles(entries, set) {
		if bundle[0].VerifierID == verifierPhalaDirect {
			if modelCVM == maxModelCVMBundles {
				set.refuseAll(bundle, fmt.Sprintf("not fetched: the limit of %d Phala model CVM bundles of one verification is reached", maxModelCVMBundles))
				continue
			}
			modelCVM++
			f.fetchBundle(ctx, a.baseURL, bundle, aci.MaxSessionBytes, set)
			continue
		}
		if budget <= 0 || budget < largest {
			set.refuseAll(bundle, "not fetched: the session evidence limit of one verification is reached")
			continue
		}
		fetched := f.fetchBundle(ctx, a.baseURL, bundle, min(budget, aci.MaxSessionBytes), set)
		budget -= fetched
		largest = max(largest, fetched)
	}
	return set
}

// selectBundles groups the list entries by evidence digest and orders the
// bundles for fetching. Entries of a verifier that teep does not verify are
// refused at once.
func selectBundles(entries []*aci.Session, set *sessionSet) [][]*aci.Session {
	byDigest := map[string][]*aci.Session{}
	var digests []string
	for _, s := range entries {
		if s.VerifierID != verifierPhalaDirect && s.VerifierID != verifierChutes {
			set.refuse(s, "teep does not verify the evidence of "+s.VerifierID)
			continue
		}
		if _, ok := byDigest[s.EvidenceDigest]; !ok {
			digests = append(digests, s.EvidenceDigest)
		}
		byDigest[s.EvidenceDigest] = append(byDigest[s.EvidenceDigest], s)
	}
	bundles := make([][]*aci.Session, 0, len(digests))
	for _, d := range digests {
		bundles = append(bundles, byDigest[d])
	}
	modelCVM := func(b []*aci.Session) bool { return b[0].VerifierID == verifierPhalaDirect }
	slices.SortStableFunc(bundles, func(x, y []*aci.Session) int {
		if modelCVM(x) != modelCVM(y) {
			if modelCVM(x) {
				return -1
			}
			return 1
		}
		return cmp.Or(cmp.Compare(len(y), len(x)), cmp.Compare(newest(y), newest(x)), cmp.Compare(x[0].EvidenceDigest, y[0].EvidenceDigest))
	})
	return bundles
}

func newest(b []*aci.Session) int64 {
	var t int64
	for _, s := range b {
		t = max(t, s.EstablishedAt)
	}
	return t
}

// sessionFetcher sends the session requests of one verification.
type sessionFetcher struct {
	client   *http.Client
	apiKey   string
	identity tlsct.TransportIdentity
}

// get fetches target, at most limit bytes, and requires that the response came
// over the TLS key of the identity.
func (f *sessionFetcher) get(ctx context.Context, target string, limit int64) ([]byte, error) {
	body, peer, err := provider.FetchAttestationWithTLS(ctx, f.client, target, f.apiKey, limit)
	if err != nil {
		return nil, err
	}
	if err := tlsct.CompareSPKIFingerprints(peer, f.identity.Fingerprint()); err != nil {
		return nil, fmt.Errorf("session TLS binding: %w", err)
	}
	return body, nil
}

// fetchBundle fetches the full record of the first session of bundle, at
// most limit bytes, rebuilds the other sessions of the bundle, and returns
// the bytes that it counts as fetched: limit when the fetch failed, because
// up to limit bytes can have been read. The sessions of the bundle share one
// decoded evidence, and the parsed records are released after the rebuild.
func (f *sessionFetcher) fetchBundle(ctx context.Context, baseURL string, bundle []*aci.Session, limit int64, set *sessionSet) int64 {
	first := bundle[0]
	body, err := f.get(ctx, baseURL+aci.SessionsPath+"/"+first.ID, limit)
	if err != nil {
		set.refuseAll(bundle, fmt.Sprintf("not fetched: %v", err))
		return limit
	}
	full, err := aci.ParseSession(body, first.ID)
	if err != nil {
		set.refuseAll(bundle, err.Error())
		return int64(len(body))
	}
	set.sessions = append(set.sessions, full)
	var rebuiltSessions []*aci.Session
	for _, entry := range bundle[1:] {
		rebuilt, err := aci.RebuildSession(entry, full)
		if err != nil {
			set.refuse(entry, err.Error())
			continue
		}
		rebuiltSessions = append(rebuiltSessions, rebuilt)
	}
	// Every rebuild reads the data URI of full; release it only after the
	// last one.
	for _, rebuilt := range rebuiltSessions {
		rebuilt.ReleaseRecord()
		rebuilt.Evidence = full.Evidence
	}
	full.ReleaseRecord()
	set.sessions = append(set.sessions, rebuiltSessions...)
	return int64(len(body))
}

func (s *sessionSet) refuse(session *aci.Session, reason string) {
	s.refused = append(s.refused, attestation.ACISessionRefusal{ID: session.ID, VerifierID: session.VerifierID, Reason: reason})
}

func (s *sessionSet) refuseAll(bundle []*aci.Session, reason string) {
	for _, session := range bundle {
		s.refuse(session, reason)
	}
}

// AuditSessions audits the sessions that the attester fetched with raw and
// returns the result for the aci_session_verified factor. A session is
// pinned only when every check of auditor passes.
func AuditSessions(ctx context.Context, auditor SessionAuditor, raw *attestation.RawAttestation) *attestation.ACISessionResult {
	set, ok := raw.ACISessions.(*sessionSet)
	if !ok || set == nil {
		return &attestation.ACISessionResult{Err: errors.New("no attested sessions were fetched")}
	}
	if set.err != nil {
		return &attestation.ACISessionResult{Err: set.err}
	}
	result := &attestation.ACISessionResult{Refused: slices.Clone(set.refused)}
	for _, path := range set.listUnknown {
		result.UnknownFields = append(result.UnknownFields, "aci_sessions."+path)
	}
	for _, s := range set.sessions {
		err := auditor.Audit(ctx, s)
		for _, path := range s.Unknown {
			result.UnknownFields = append(result.UnknownFields, fmt.Sprintf("aci_sessions[%s].%s", s.ID[:min(len(s.ID), 12)], path))
		}
		if err != nil {
			result.Refused = append(result.Refused, attestation.ACISessionRefusal{ID: s.ID, VerifierID: s.VerifierID, Reason: err.Error()})
			continue
		}
		result.Pinned = append(result.Pinned, attestation.ACIPinnedSession{ID: s.ID, EstablishedAt: s.EstablishedAt, ExpiresAt: s.ExpiresAt})
	}
	return result
}
