package attestation

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// DstackRuntimeEventType marks a dstack runtime event, whose RTMR digest is
// computed from its semantic fields rather than trusted as a declared value.
// SEE: dstack_event_digest in
// https://github.com/Dstack-TEE/private-ai-gateway src/aci/verifier/dstack.rs.
const DstackRuntimeEventType = 0x08000001

// ReplayEventLog replays event log entries to recompute the four RTMR values.
// Each entry extends the RTMR at its IMR index: RTMR_new = SHA384(RTMR_old || digest).
// RTMRs start as 48 zero bytes.
//
// For dstack runtime events the digest is recomputed from (event_type, event,
// event_payload) — the event and event_payload strings would otherwise be free
// text that survives the replay, letting a caller read attacker-chosen values
// (such as the app-id) out of a log that still matched the quote. SEE:
// appIDFromEventLog in internal/provider/venice/keyset.go, which reads those
// fields.
//
// Based on github.com/Dstack-TEE/dstack/sdk/go/dstack (Apache-2.0).
func ReplayEventLog(entries []EventLogEntry) ([4][48]byte, error) {
	var rtmrs [4][48]byte // zero-initialized

	for i, e := range entries {
		if e.IMR < 0 || e.IMR > 3 {
			return rtmrs, fmt.Errorf("event %d: IMR index %d out of range [0,3]", i, e.IMR)
		}

		digest, err := eventDigest(e)
		if err != nil {
			return rtmrs, fmt.Errorf("event %d: %w", i, err)
		}

		if len(digest) < 48 {
			padded := make([]byte, 48)
			copy(padded, digest)
			digest = padded
		}

		h := sha512.New384()
		h.Write(rtmrs[e.IMR][:])
		h.Write(digest)
		copy(rtmrs[e.IMR][:], h.Sum(nil))
	}

	return rtmrs, nil
}

// eventDigest returns the digest extended into an RTMR. dstack runtime events
// authenticate their name and payload instead of supplying a stored digest.
func eventDigest(e EventLogEntry) ([]byte, error) {
	if e.EventType != DstackRuntimeEventType {
		digest, err := hex.DecodeString(e.Digest)
		if err != nil {
			return nil, fmt.Errorf("invalid hex digest: %w", err)
		}
		return digest, nil
	}

	payload, err := hex.DecodeString(e.EventPayload)
	if err != nil {
		return nil, fmt.Errorf("runtime event %q has invalid hex payload: %w", e.Event, err)
	}

	h := sha512.New384()
	var eventType [4]byte
	binary.LittleEndian.PutUint32(eventType[:], uint32(e.EventType))
	h.Write(eventType[:])
	h.Write([]byte(":"))
	h.Write([]byte(e.Event))
	h.Write([]byte(":"))
	h.Write(payload)
	digest := h.Sum(nil)

	if e.Digest == "" {
		return digest, nil
	}
	stored, err := hex.DecodeString(e.Digest)
	if err != nil {
		return nil, fmt.Errorf("runtime event %q has invalid hex digest: %w", e.Event, err)
	}
	if len(stored) != len(digest) || subtle.ConstantTimeCompare(stored, digest) != 1 {
		return nil, fmt.Errorf("runtime event %q digest does not match its payload", e.Event)
	}
	return digest, nil
}
