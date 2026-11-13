package aci

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/jsonstrict"
)

// ReceiptsPath is the ACI/1 receipt route (§7.1).
const ReceiptsPath = "/v1/aci/receipts"

// MaxReceiptBytes bounds one receipt document (1340 bytes on 2026-11-01).
const MaxReceiptBytes = 64 << 10

// Receipt is a signed ACI/1 inference receipt (§7.3).
type Receipt struct {
	ID           string
	ChatID       string // "" when null
	Model        string // "" when null
	KeysetDigest string
	Endpoint     string
	Method       string
	ServedAt     int64
	KeyID        string
	Signature    string
	// RequestReceived, RequestForwarded and ResponseReturned are the
	// body_hash values of the required events ("" when absent).
	RequestReceived  string
	RequestForwarded string
	ResponseReturned string
	// Upstream lists the upstream.verified events in order.
	Upstream []UpstreamVerified

	// signed is the canonical form of the document without signature.
	signed []byte
}

// UpstreamVerified is one upstream.verified event (§7.5).
type UpstreamVerified struct {
	Result    string // "verified" or "failed"
	Required  bool
	ModelID   string
	SessionID string // set when Result is "verified"
	Reason    string // set when Result is "failed"
}

type receiptJSON struct {
	APIVersion           string            `json:"api_version"`
	ReceiptID            string            `json:"receipt_id"`
	ChatID               *string           `json:"chat_id"`
	Model                *string           `json:"model"`
	WorkloadKeysetDigest string            `json:"workload_keyset_digest"`
	Endpoint             string            `json:"endpoint"`
	Method               string            `json:"method"`
	ServedAt             int64             `json:"served_at"`
	EventLog             []json.RawMessage `json:"event_log"`
	KeyID                string            `json:"key_id"`
	Signature            string            `json:"signature"`
}

// ParseReceipt parses a receipt document. The document must have every
// member of §7.3 and no other; events are objects, the first one is
// request.received, and the events of §7.4 and §7.5 must have exactly
// their defined members. Events of other types are ignored (§7.4).
func ParseReceipt(body []byte) (*Receipt, error) {
	if len(body) > MaxReceiptBytes {
		return nil, fmt.Errorf("receipt exceeds %d bytes", MaxReceiptBytes)
	}
	var doc receiptJSON
	unknown, missing, err := jsonstrict.Unmarshal(body, &doc)
	if err != nil {
		return nil, fmt.Errorf("receipt: %w", err)
	}
	if len(unknown) > 0 || len(missing) > 0 {
		return nil, fmt.Errorf("receipt: undefined members %q, missing members %q", unknown, missing)
	}
	if doc.APIVersion != "aci/1" {
		return nil, fmt.Errorf("receipt api_version is %q, want aci/1", doc.APIVersion)
	}
	if !isSHA256Digest(doc.WorkloadKeysetDigest) || doc.ReceiptID == "" || doc.KeyID == "" {
		return nil, errors.New("receipt needs a receipt_id, a key_id and a sha256 workload_keyset_digest")
	}
	r := &Receipt{
		ID: doc.ReceiptID, KeysetDigest: doc.WorkloadKeysetDigest, Endpoint: doc.Endpoint,
		Method: doc.Method, ServedAt: doc.ServedAt, KeyID: doc.KeyID, Signature: doc.Signature,
	}
	if doc.ChatID != nil {
		r.ChatID = *doc.ChatID
	}
	if doc.Model != nil {
		r.Model = *doc.Model
	}
	if err := r.parseEvents(doc.EventLog); err != nil {
		return nil, err
	}
	value, err := sessionValue(body)
	if err != nil {
		return nil, fmt.Errorf("receipt: %w", err)
	}
	delete(value, "signature")
	if r.signed, err = canonicalize(value); err != nil {
		return nil, fmt.Errorf("receipt: canonical form: %w", err)
	}
	return r, nil
}

func (r *Receipt) parseEvents(events []json.RawMessage) error {
	if len(events) == 0 {
		return errors.New("receipt has no events")
	}
	for i, e := range events {
		// The type selects the form; an event of another type may have
		// members of its own (§7.4).
		var head struct {
			Type string `json:"type"`
		}
		if _, _, err := jsonstrict.Unmarshal(e, &head); err != nil || head.Type == "" {
			return fmt.Errorf("receipt event %d: not an object with a string type", i)
		}
		if i == 0 && head.Type != "request.received" {
			return fmt.Errorf("receipt event 0 is %q, want request.received", head.Type)
		}
		switch head.Type {
		case "request.received", "request.forwarded", "response.returned":
			hash, err := eventBodyHash(e, head.Type)
			if err != nil {
				return fmt.Errorf("receipt event %d: %w", i, err)
			}
			if err := r.setBodyHash(head.Type, hash); err != nil {
				return fmt.Errorf("receipt event %d: %w", i, err)
			}
		case "upstream.verified":
			u, err := parseUpstreamVerified(e)
			if err != nil {
				return fmt.Errorf("receipt event %d: %w", i, err)
			}
			r.Upstream = append(r.Upstream, u)
		}
	}
	if r.ResponseReturned == "" {
		return errors.New("receipt has no response.returned event")
	}
	return nil
}

func (r *Receipt) setBodyHash(kind, hash string) error {
	var target *string
	switch kind {
	case "request.received":
		target = &r.RequestReceived
	case "request.forwarded":
		target = &r.RequestForwarded
	case "response.returned":
		target = &r.ResponseReturned
	default:
		return fmt.Errorf("%s is not a body hash event", kind)
	}
	if *target != "" {
		return fmt.Errorf("%s appears twice", kind)
	}
	*target = hash
	return nil
}

func eventBodyHash(e json.RawMessage, kind string) (string, error) {
	var ev struct {
		Type     string `json:"type"`
		BodyHash string `json:"body_hash"`
	}
	if err := decodeExact(e, &ev); err != nil {
		return "", fmt.Errorf("%s: %w", kind, err)
	}
	if !isSHA256Digest(ev.BodyHash) {
		return "", fmt.Errorf("%s: body_hash is not sha256:<64 lowercase hex>", kind)
	}
	return ev.BodyHash, nil
}

// verifiedEvent and failedEvent are the two forms of upstream.verified
// (§7.5). Required is a pointer so that null fails.
type verifiedEvent struct {
	Type      string `json:"type"`
	Result    string `json:"result"`
	Required  *bool  `json:"required"`
	ModelID   string `json:"model_id"`
	SessionID string `json:"session_id"`
}

type failedEvent struct {
	Type         string  `json:"type"`
	Result       string  `json:"result"`
	Required     *bool   `json:"required"`
	ModelID      string  `json:"model_id"`
	Reason       string  `json:"reason"`
	UpstreamName *string `json:"upstream_name,omitempty"`
}

// parseUpstreamVerified parses one upstream.verified event in the form of
// its result: a verified event has a session_id, a failed event a reason
// and an optional upstream_name, and no other member.
func parseUpstreamVerified(e json.RawMessage) (UpstreamVerified, error) {
	var head struct {
		Result string `json:"result"`
	}
	if _, _, err := jsonstrict.Unmarshal(e, &head); err != nil {
		return UpstreamVerified{}, fmt.Errorf("upstream.verified: %w", err)
	}
	switch head.Result {
	case "verified":
		var v verifiedEvent
		if err := decodeExact(e, &v); err != nil {
			return UpstreamVerified{}, fmt.Errorf("upstream.verified: %w", err)
		}
		if v.Required == nil {
			return UpstreamVerified{}, errors.New("upstream.verified: required is null")
		}
		if !isLowerHex64(v.SessionID) {
			return UpstreamVerified{}, errors.New("upstream.verified: session_id is not 64 lowercase hex characters")
		}
		return UpstreamVerified{Result: v.Result, Required: *v.Required, ModelID: v.ModelID, SessionID: v.SessionID}, nil
	case "failed":
		var f failedEvent
		if err := decodeExact(e, &f); err != nil {
			return UpstreamVerified{}, fmt.Errorf("upstream.verified: %w", err)
		}
		if f.Required == nil {
			return UpstreamVerified{}, errors.New("upstream.verified: required is null")
		}
		return UpstreamVerified{Result: f.Result, Required: *f.Required, ModelID: f.ModelID, Reason: f.Reason}, nil
	default:
		return UpstreamVerified{}, fmt.Errorf("upstream.verified: result %q is not verified or failed", head.Result)
	}
}

// decodeExact decodes e into v and requires exactly the members of v; a
// member tagged omitempty may be absent.
func decodeExact(e json.RawMessage, v any) error {
	unknown, missing, err := jsonstrict.Unmarshal(e, v)
	if err != nil {
		return err
	}
	if len(unknown) > 0 || len(missing) > 0 {
		return fmt.Errorf("undefined members %q, missing members %q", unknown, missing)
	}
	return nil
}

// ErrReceiptRequestMismatch marks a receipt whose statement about the
// request (endpoint, method, model or request hash) differs from the
// request that teep sent. Those statements depend on the client's request,
// so the caller fails the request without ending the authorization that
// other clients share; a failure of the service's own statements
// (signature, keyset, response hash, session, served_at) ends it.
var ErrReceiptRequestMismatch = errors.New("receipt does not describe the request that teep sent")

// ReceiptCheck is what a receipt must state for one request.
type ReceiptCheck struct {
	// Keys and KeysetDigest are the receipt keys and the digest of the
	// verified keyset; NotAfter is its not_after.
	Keys         []attestation.ACIReceiptKey
	KeysetDigest string
	NotAfter     int64
	Endpoint     string
	Method       string
	Model        string
	// ResponseHash is the sha256 of the response bytes that teep received.
	ResponseHash [32]byte
	// RequestHash is the sha256 of the restored request, or nil when teep
	// cannot reproduce the gateway's form; the request is then not checked.
	RequestHash *[32]byte
	// Sessions lists the sessions that the request pinned, with their
	// periods.
	Sessions []attestation.ACIPinnedSession
}

// VerifyReceipt checks r for one request (ACI/1 §9.3): the ed25519
// signature over the JCS form without signature under the keyset key that
// key_id names, the keyset digest, endpoint, method, model, the response
// hash, the request hash when teep has it, and a verified upstream event
// that is required and cites a pinned session whose period holds served_at.
// served_at must be earlier than the keyset's not_after, which must be set.
func VerifyReceipt(r *Receipt, c *ReceiptCheck) error {
	if err := verifyReceiptSignature(r, c.Keys); err != nil {
		return err
	}
	switch {
	case subtle.ConstantTimeCompare([]byte(r.KeysetDigest), []byte(c.KeysetDigest)) != 1:
		return errors.New("receipt names another workload keyset")
	case r.Endpoint != c.Endpoint || r.Method != c.Method:
		return fmt.Errorf("%w: receipt is for %s %s, not %s %s", ErrReceiptRequestMismatch, r.Method, r.Endpoint, c.Method, c.Endpoint)
	case r.Model != c.Model:
		return fmt.Errorf("%w: receipt model is %q, not %q", ErrReceiptRequestMismatch, r.Model, c.Model)
	case c.NotAfter <= 0:
		return errors.New("receipt check has no keyset not_after")
	case r.ServedAt >= c.NotAfter:
		// §3.1: a keyset verifies a receipt whose served_at is earlier
		// than its not_after.
		return errors.New("receipt served_at is not earlier than the keyset not_after")
	}
	if !hashEquals(r.ResponseReturned, c.ResponseHash) {
		return errors.New("response.returned does not hash the response that teep received")
	}
	if c.RequestHash != nil && !hashEquals(r.RequestReceived, *c.RequestHash) {
		return fmt.Errorf("%w: request.received does not hash it", ErrReceiptRequestMismatch)
	}
	return checkUpstreamVerified(r.Upstream, c.Sessions, r.ServedAt)
}

func verifyReceiptSignature(r *Receipt, keys []attestation.ACIReceiptKey) error {
	var key *attestation.ACIReceiptKey
	for i := range keys {
		if keys[i].KeyID == r.KeyID {
			if key != nil {
				return fmt.Errorf("keyset lists receipt key %s twice", r.KeyID)
			}
			key = &keys[i]
		}
	}
	if key == nil {
		return fmt.Errorf("keyset has no receipt key %s", r.KeyID)
	}
	if key.Algo != "ed25519" {
		return fmt.Errorf("receipt key %s is %s, not ed25519", r.KeyID, key.Algo)
	}
	pub, err := hex.DecodeString(key.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("receipt key %s is not a 32-byte ed25519 key", r.KeyID)
	}
	sig, err := hex.DecodeString(r.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("receipt signature is not 64 bytes of hex")
	}
	if !ed25519.Verify(pub, r.signed, sig) {
		return errors.New("receipt signature does not verify")
	}
	return nil
}

// checkUpstreamVerified accepts the receipt when a required, verified
// upstream event cites a pinned session whose period holds servedAt
// (§9.3 step 6).
func checkUpstreamVerified(events []UpstreamVerified, pinned []attestation.ACIPinnedSession, servedAt int64) error {
	if len(events) == 0 {
		return errors.New("receipt has no upstream.verified event")
	}
	var outside error
	for _, u := range events {
		if u.Result != "verified" || !u.Required {
			continue
		}
		for i := range pinned {
			s := &pinned[i]
			if subtle.ConstantTimeCompare([]byte(s.ID), []byte(u.SessionID)) != 1 {
				continue
			}
			// §9.3 step 6: established_at <= served_at < expires_at.
			if servedAt < s.EstablishedAt || servedAt >= s.ExpiresAt {
				outside = fmt.Errorf("receipt served_at %d is outside the period %d to %d of cited session %s", servedAt, s.EstablishedAt, s.ExpiresAt, s.ID)
				continue
			}
			return nil
		}
	}
	if outside != nil {
		return outside
	}
	return errors.New("receipt cites no required, verified upstream session that the request pinned")
}

func hashEquals(digest string, sum [32]byte) bool {
	return subtle.ConstantTimeCompare([]byte(digest), []byte("sha256:"+hex.EncodeToString(sum[:]))) == 1
}
