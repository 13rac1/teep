package phalacloud

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/aci"
	"github.com/13rac1/teep/internal/tlsct"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

// The attester lists the sessions of the model, fetches the bundle of the
// Phala model CVM, then the Chutes bundle that covers the most sessions,
// and rebuilds the other sessions of that bundle. Fetching stops at the
// evidence limit. The audit pins the sessions that pass every check.
func TestFetchSessionsSelectsBoundedBundles(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		files := map[string][]byte{}
		for id, name := range map[string]string{phalaDirectSessionID: "session_phala_direct.json", chutesSessionID: "session_chutes.json"} {
			body, err := os.ReadFile("../aci/testdata/" + name)
			if err != nil {
				t.Fatal(err)
			}
			files[id] = body
		}
		list, err := os.ReadFile("../aci/testdata/session_list.json")
		if err != nil {
			t.Fatal(err)
		}
		var mu sync.Mutex
		var requests []string
		ts := authority.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			requests = append(requests, r.URL.RequestURI())
			mu.Unlock()
			if r.Header.Get("Authorization") != "Bearer key" {
				t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
			}
			if r.URL.Path == aci.SessionsPath {
				if r.URL.Query().Get("model") != "qwen/qwen3.8-27b" {
					t.Errorf("list query %q", r.URL.RawQuery)
				}
				_, _ = w.Write(list)
				return
			}
			body, ok := files[strings.TrimPrefix(r.URL.Path, aci.SessionsPath+"/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(body)
		}))
		a := NewAttester(ts.URL, "key")
		a.SetClient(tlsct.NewHTTPClientWithTransport(30*time.Second, tlsct.NewPooledTransport(), false))
		set := a.fetchSessions(context.Background(), "qwen/qwen3.8-27b")
		if set.err != nil {
			t.Fatal(set.err)
		}
		// The list, the Phala model CVM bundle, the Chutes bundle of three
		// sessions, and the next Chutes bundle, which this server does not
		// serve; its failure uses up the rest of the limit.
		if len(requests) != 4 || !strings.HasPrefix(requests[0], aci.SessionsPath+"?") ||
			requests[1] != aci.SessionsPath+"/"+phalaDirectSessionID || requests[2] != aci.SessionsPath+"/"+chutesSessionID {
			t.Fatalf("requests %q", requests)
		}
		if len(set.sessions) != 4 {
			t.Fatalf("fetched %d sessions, want 4 (1 Phala model CVM, 3 Chutes of one bundle)", len(set.sessions))
		}
		if len(set.refused) != 11 {
			t.Errorf("refused %d sessions before the audit, want 11", len(set.refused))
		}
		for _, r := range set.refused {
			if !strings.HasPrefix(r.Reason, "not fetched") {
				t.Errorf("session %s refused: %s", r.ID, r.Reason)
			}
		}

		raw := &attestation.RawAttestation{ACISessions: set}
		auditor := SessionAuditor{TDX: attestation.NewTDXVerifier(true, nil, time.Unix(1793473465, 0)), Offline: true}
		result := AuditSessions(context.Background(), auditor, raw)
		if result.Err != nil {
			t.Fatal(result.Err)
		}
		// The Phala model CVM session and the three Chutes sessions of the
		// fetched bundle pass; the others were not fetched.
		if got := len(result.Pinned); got != 4 || result.Pinned[0] != phalaDirectSessionID {
			t.Errorf("pinned %d sessions (%q), want 4 starting with the Phala model CVM", got, result.Pinned)
		}
		if got := len(result.Refused); got != 11 {
			t.Errorf("refused %d sessions, want 11", got)
		}
	})
}

// A session list that cannot be fetched fails the audit.
func TestAuditSessionsWithoutSessions(t *testing.T) {
	auditor := SessionAuditor{TDX: attestation.NewTDXVerifier(true, nil, time.Now()), Offline: true}
	for _, raw := range []*attestation.RawAttestation{{}, {ACISessions: &sessionSet{err: context.DeadlineExceeded}}} {
		if r := AuditSessions(context.Background(), auditor, raw); r.Err == nil || len(r.Pinned) != 0 {
			t.Errorf("result %+v, want an error", r)
		}
	}
}

// Every bundle of the Phala model CVM comes first, then Chutes bundles by
// the number of sessions they cover; sessions of other verifiers are
// refused.
func TestSelectBundles(t *testing.T) {
	entry := func(id, verifier, digest string, at int64) *aci.Session {
		return &aci.Session{ID: id, VerifierID: verifier, EvidenceDigest: digest, EstablishedAt: at}
	}
	entries := []*aci.Session{
		entry("c1", verifierChutes, "d1", 1),
		entry("c2", verifierChutes, "d2", 2),
		entry("c3", verifierChutes, "d2", 3),
		entry("o1", "private-ai-verifier/other/v1", "d3", 4),
		entry("p1", verifierPhalaDirect, "d4", 5),
		entry("c4", verifierChutes, "d5", 9),
	}
	set := &sessionSet{}
	order := make([]string, 0, 4)
	for _, b := range selectBundles(entries, set) {
		order = append(order, b[0].ID)
	}
	if strings.Join(order, " ") != "p1 c2 c4 c1" {
		t.Errorf("order %q, want p1 c2 c4 c1", order)
	}
	if len(set.refused) != 1 || set.refused[0].ID != "o1" {
		t.Errorf("refused %+v, want the session of the other verifier", set.refused)
	}
}
