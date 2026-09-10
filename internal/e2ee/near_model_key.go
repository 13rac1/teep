package e2ee

import (
	"crypto/ecdh"
	"encoding/hex"
	"fmt"
)

// NearModelKey is an immutable validated Ed25519 key and its X25519 conversion.
// Validation does not authenticate the key; the caller must verify its attestation binding.
// The zero value is invalid and cannot supply a routing header.
type NearModelKey struct {
	hexadecimal string
	x25519      *ecdh.PublicKey
}

// ParseNearModelKey validates and canonicalizes a model key in one operation.
func ParseNearModelKey(value string) (NearModelKey, error) {
	if len(value) != 64 {
		return NearModelKey{}, fmt.Errorf("expected 64 hex chars, got %d", len(value))
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return NearModelKey{}, fmt.Errorf("not valid hex: %w", err)
	}
	converted, err := Ed25519PubToX25519(decoded)
	if err != nil {
		return NearModelKey{}, fmt.Errorf("not a valid ed25519 point: %w", err)
	}
	return NearModelKey{hexadecimal: hex.EncodeToString(decoded), x25519: converted}, nil
}

// Hex returns the canonical key, or an empty string for the invalid zero value.
func (k NearModelKey) Hex() string { return k.hexadecimal }
