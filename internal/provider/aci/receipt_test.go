package aci

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
)

// The live capture of 2026-11-01 whose pinned E2EE test exchange the
// receipt of testdata/receipt.json covers.
const receiptCapture = "../../integration/testdata/current/phalacloud_aci"

// receiptFixture returns the receipt and the check of its exchange.
func receiptFixture(t *testing.T) (*Receipt, *ReceiptCheck) {
	t.Helper()
	body, err := os.ReadFile("testdata/receipt.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseReceipt(body)
	if err != nil {
		t.Fatal(err)
	}
	_, entries, err := capture.Load(filepath.Clean(receiptCapture))
	if err != nil {
		t.Fatal(err)
	}
	var report, response, request, list []byte
	for i := range entries {
		switch {
		case strings.Contains(entries[i].URL, CanonicalPath):
			report = entries[i].Body
		case strings.Contains(entries[i].URL, SessionsPath+"?"):
			list = entries[i].Body
		case strings.HasSuffix(entries[i].URL, "/v1/chat/completions"):
			response, request = entries[i].Body, entries[i].ReqBody
		}
	}
	raw, err := ParseCanonical(context.Background(), report, "phalacloud")
	if err != nil {
		t.Fatal(err)
	}
	// The probe encrypted messages[0].content, "Say hello"; the gateway
	// hashes the restored request in compact form (E2EE v2 §8).
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(request, &wire); err != nil {
		t.Fatal(err)
	}
	restored := strings.Replace(string(request), string(contentOf(t, wire)), `"Say hello"`, 1)
	requestHash, err := RestoredRequestHash([]byte(restored))
	if err != nil || requestHash == nil {
		t.Fatalf("restored request hash: %v, %v", requestHash, err)
	}
	var pinned []string
	var b struct {
		Provider struct {
			ACISessionIDs []string `json:"aci_session_ids"`
		} `json:"provider"`
	}
	if err := json.Unmarshal(request, &b); err != nil {
		t.Fatal(err)
	}
	pinned = b.Provider.ACISessionIDs
	listed, _, err := ParseSessionList(list)
	if err != nil {
		t.Fatal(err)
	}
	var sessions []attestation.ACIPinnedSession
	for _, s := range listed {
		if slices.Contains(pinned, s.ID) {
			sessions = append(sessions, attestation.ACIPinnedSession{ID: s.ID, EstablishedAt: s.EstablishedAt, ExpiresAt: s.ExpiresAt})
		}
	}
	if len(sessions) != len(pinned) {
		t.Fatalf("the session list has %d of the %d pinned sessions", len(sessions), len(pinned))
	}
	return r, &ReceiptCheck{
		Keys: raw.ACIReceiptKeys, KeysetDigest: raw.ACIWorkloadKeysetDigest, NotAfter: raw.ACIKeysetNotAfter,
		Endpoint: "/v1/chat/completions", Method: "POST", Model: "qwen/qwen3.8-27b",
		ResponseHash: sha256.Sum256(response), RequestHash: requestHash, Sessions: sessions,
	}
}

// contentOf returns the encoded ciphertext of messages[0].content.
func contentOf(t *testing.T, wire map[string]json.RawMessage) json.RawMessage {
	t.Helper()
	var messages []map[string]json.RawMessage
	if err := json.Unmarshal(wire["messages"], &messages); err != nil || len(messages) != 1 {
		t.Fatalf("messages: %v", err)
	}
	return messages[0]["content"]
}

// citedSession is the session that the live receipt cites.
const citedSession = "f82e2a6b603a3d0b1abe395f979440f0da44a425b238cfcb5354f20906f43cc7"

func cited(c *ReceiptCheck) *attestation.ACIPinnedSession {
	for i := range c.Sessions {
		if c.Sessions[i].ID == citedSession {
			return &c.Sessions[i]
		}
	}
	panic("the fixture does not pin the cited session")
}

func withoutCited(sessions []attestation.ACIPinnedSession) []attestation.ACIPinnedSession {
	return slices.DeleteFunc(slices.Clone(sessions), func(s attestation.ACIPinnedSession) bool { return s.ID == citedSession })
}

// The live receipt verifies: signature, keyset digest, endpoint, model,
// response and restored request hashes, and a pinned verified session.
func TestVerifyReceiptLive(t *testing.T) {
	r, c := receiptFixture(t)
	if err := VerifyReceipt(r, c); err != nil {
		t.Fatal(err)
	}
	if got, want := r.Upstream[0].SessionID, citedSession; got != want {
		t.Errorf("cited session %s, want %s", got, want)
	}
}

// Each checked statement fails when it differs from the request.
func TestVerifyReceiptRefuses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Receipt, *ReceiptCheck)
		want   string
	}{
		{"other signature", func(r *Receipt, _ *ReceiptCheck) { r.Signature = strings.Repeat("00", 64) }, "signature does not verify"},
		{"signed content changed", func(r *Receipt, _ *ReceiptCheck) { r.signed = append([]byte(nil), r.signed[1:]...) }, "signature does not verify"},
		{"unknown key", func(r *Receipt, _ *ReceiptCheck) { r.KeyID = "other" }, "no receipt key"},
		{"other keyset", func(_ *Receipt, c *ReceiptCheck) { c.KeysetDigest = "sha256:" + strings.Repeat("ab", 32) }, "another workload keyset"},
		{"other model", func(_ *Receipt, c *ReceiptCheck) { c.Model = "other" }, "model"},
		{"other endpoint", func(_ *Receipt, c *ReceiptCheck) { c.Endpoint = "/v1/completions" }, "not POST"},
		{"other response", func(_ *Receipt, c *ReceiptCheck) { c.ResponseHash[0] ^= 1 }, "response.returned"},
		{"other request", func(_ *Receipt, c *ReceiptCheck) { c.RequestHash[0] ^= 1 }, "request.received"},
		{"session not pinned", func(_ *Receipt, c *ReceiptCheck) { c.Sessions = withoutCited(c.Sessions) }, "no required, verified"},
		{"served before the session", func(r *Receipt, c *ReceiptCheck) { cited(c).EstablishedAt = r.ServedAt + 1 }, "outside the period"},
		{"served after the session", func(r *Receipt, c *ReceiptCheck) { cited(c).ExpiresAt = r.ServedAt - 1 }, "outside the period"},
		{"past not_after", func(r *Receipt, c *ReceiptCheck) { c.NotAfter = r.ServedAt - 1 }, "not_after"},
		{"at not_after", func(r *Receipt, c *ReceiptCheck) { c.NotAfter = r.ServedAt }, "not earlier than the keyset not_after"},
		{"no not_after", func(_ *Receipt, c *ReceiptCheck) { c.NotAfter = 0 }, "no keyset not_after"},
		{"served at expires_at", func(r *Receipt, c *ReceiptCheck) { cited(c).ExpiresAt = r.ServedAt }, "outside the period"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, c := receiptFixture(t)
			tc.change(r, c)
			err := VerifyReceipt(r, c)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			// Only the request hash marks a failure that keeps the shared
			// authorization; endpoint, method and model are a route
			// mismatch.
			if want := tc.name == "other request"; errors.Is(err, ErrReceiptRequestMismatch) != want {
				t.Errorf("request mismatch = %v, want %v", errors.Is(err, ErrReceiptRequestMismatch), want)
			}
			if want := tc.name == "other model" || tc.name == "other endpoint"; errors.Is(err, ErrReceiptRouteMismatch) != want {
				t.Errorf("route mismatch = %v, want %v", errors.Is(err, ErrReceiptRouteMismatch), want)
			}
		})
	}
}

// A receipt for another request does not stop the check before the
// service's own statements: with another model and another response, or
// another model and a session that the request did not pin, the response or
// session failure is returned, which ends the authorization, not the route
// mismatch.
func TestVerifyReceiptChecksServiceStatementsFirst(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Receipt, *ReceiptCheck)
		want   string
	}{
		{"other model and other response", func(_ *Receipt, c *ReceiptCheck) { c.Model, c.ResponseHash[0] = "other", c.ResponseHash[0]^1 }, "response.returned"},
		{"other model and session not pinned", func(_ *Receipt, c *ReceiptCheck) { c.Model, c.Sessions = "other", withoutCited(c.Sessions) }, "no required, verified"},
		{"other request and other response", func(_ *Receipt, c *ReceiptCheck) { c.RequestHash[0] ^= 1; c.ResponseHash[0] ^= 1 }, "response.returned"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, c := receiptFixture(t)
			tc.change(r, c)
			err := VerifyReceipt(r, c)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if errors.Is(err, ErrReceiptRouteMismatch) || errors.Is(err, ErrReceiptRequestMismatch) {
				t.Errorf("err = %v is a request statement mismatch", err)
			}
		})
	}
}

// served_at at established_at is inside the period of the cited session,
// and one second before not_after and expires_at is inside both bounds.
func TestVerifyReceiptBoundaries(t *testing.T) {
	r, c := receiptFixture(t)
	cited(c).EstablishedAt = r.ServedAt
	if err := VerifyReceipt(r, c); err != nil {
		t.Errorf("served at established_at: %v", err)
	}
	r, c = receiptFixture(t)
	c.NotAfter, cited(c).ExpiresAt = r.ServedAt+1, r.ServedAt+1
	if err := VerifyReceipt(r, c); err != nil {
		t.Errorf("served one second before not_after and expires_at: %v", err)
	}
}

// A receipt without a request hash check states only what it can: the
// request is not checked, every other statement is.
func TestVerifyReceiptWithoutRequestHash(t *testing.T) {
	r, c := receiptFixture(t)
	c.RequestHash = nil
	if err := VerifyReceipt(r, c); err != nil {
		t.Fatal(err)
	}
}

func TestParseReceiptRefusesMalformed(t *testing.T) {
	body, err := os.ReadFile("testdata/receipt.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"no signature", func(d map[string]any) { delete(d, "signature") }},
		{"other api_version", func(d map[string]any) { d["api_version"] = "aci/2" }},
		{"first event not request.received", func(d map[string]any) {
			events := d["event_log"].([]any)
			d["event_log"] = append(events[1:], events[0])
		}},
		{"no response.returned", func(d map[string]any) {
			events := d["event_log"].([]any)
			d["event_log"] = events[:len(events)-1]
		}},
		{"verified upstream without session", func(d map[string]any) {
			delete(upstreamEvent(d), "session_id")
		}},
		{"verified upstream with a reason", func(d map[string]any) { upstreamEvent(d)["reason"] = "x" }},
		{"required null", func(d map[string]any) { upstreamEvent(d)["required"] = nil }},
		{"failed upstream with a session", func(d map[string]any) {
			upstreamEvent(d)["result"] = "failed"
			upstreamEvent(d)["reason"] = "x"
		}},
		{"other result", func(d map[string]any) { upstreamEvent(d)["result"] = "skipped" }},
		{"event not an object", func(d map[string]any) {
			d["event_log"] = append(d["event_log"].([]any), "x")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var d map[string]any
			if err := json.Unmarshal(body, &d); err != nil {
				t.Fatal(err)
			}
			tc.change(d)
			changed, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseReceipt(changed); err == nil {
				t.Fatal("malformed receipt accepted")
			}
		})
	}
}

// upstreamEvent returns the upstream.verified event of a decoded receipt.
func upstreamEvent(d map[string]any) map[string]any {
	for _, e := range d["event_log"].([]any) {
		if m, ok := e.(map[string]any); ok && m["type"] == "upstream.verified" {
			return m
		}
	}
	panic("the receipt has no upstream.verified event")
}

// A failed upstream event has a reason and may name the upstream; the
// receipt parses, and the check finds no verified session.
func TestParseReceiptFailedUpstream(t *testing.T) {
	r, c := receiptFixture(t)
	var d map[string]any
	live, err := os.ReadFile("testdata/receipt.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(live, &d); err != nil {
		t.Fatal(err)
	}
	m := upstreamEvent(d)
	delete(m, "session_id")
	m["result"], m["reason"], m["upstream_name"] = "failed", "no TEE", "upstream-1"
	body, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := ParseReceipt(body)
	if err != nil {
		t.Fatal(err)
	}
	if u := failed.Upstream[0]; u.Result != "failed" || u.Reason != "no TEE" || u.SessionID != "" {
		t.Errorf("upstream event %+v", u)
	}
	failed.signed, failed.Signature = r.signed, r.Signature
	if err := VerifyReceipt(failed, c); err == nil || !strings.Contains(err.Error(), "no required, verified") {
		t.Errorf("err = %v, want no verified session", err)
	}
}
