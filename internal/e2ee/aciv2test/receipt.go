package aciv2test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// ReceiptKeyID is the key_id of the gateway's receipt signing key.
const ReceiptKeyID = "test-receipt-ed25519"

// Receipt holds the statements of one ACI/1 receipt (§7.3).
type Receipt struct {
	ID, Model, KeysetDigest string
	// SessionID is the session that the upstream.verified event cites.
	SessionID string
	// Request is the restored request and Response the wire response bytes
	// that the receipt hashes.
	Request, Response []byte
	ServedAt          int64
}

// ReceiptPublicKeyHex returns the receipt signing public key as hex.
func (g *Gateway) ReceiptPublicKeyHex() string {
	return hex.EncodeToString(g.receiptKey[ed25519.SeedSize:])
}

// SignReceipt returns the receipt document of r, signed with ed25519 over
// the JCS form of the document without signature (§7.3).
func (g *Gateway) SignReceipt(r *Receipt) []byte {
	g.t.Helper()
	doc := map[string]any{
		"api_version":            "aci/1",
		"receipt_id":             r.ID,
		"chat_id":                nil,
		"model":                  r.Model,
		"workload_keyset_digest": r.KeysetDigest,
		"endpoint":               "/v1/chat/completions",
		"method":                 "POST",
		"served_at":              r.ServedAt,
		"event_log": []map[string]any{
			{"type": "request.received", "body_hash": bodyHash(r.Request)},
			{"type": "upstream.verified", "result": "verified", "required": true, "model_id": r.Model, "session_id": r.SessionID},
			{"type": "response.returned", "body_hash": bodyHash(r.Response)},
		},
		"key_id": ReceiptKeyID,
	}
	unsigned, err := json.Marshal(doc)
	if err != nil {
		g.t.Fatal(err)
	}
	canonical, err := jsoncanonicalizer.Transform(unsigned)
	if err != nil {
		g.t.Fatal(err)
	}
	doc["signature"] = hex.EncodeToString(ed25519.Sign(g.receiptKey, canonical))
	out, err := json.Marshal(doc)
	if err != nil {
		g.t.Fatal(err)
	}
	return out
}

func bodyHash(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
