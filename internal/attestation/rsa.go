package attestation

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

// decodeBase64URL decodes a base64url-encoded string (no padding required).
func decodeBase64URL(s string) ([]byte, error) {
	// Add padding if necessary.
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64url decode: %w", err)
	}
	return b, nil
}

// buildRSAPublicKey constructs an *rsa.PublicKey from the raw modulus (n) and
// exponent (e) bytes, both in big-endian byte order.
func buildRSAPublicKey(nBytes, eBytes []byte) (*rsa.PublicKey, error) {
	if len(nBytes) == 0 {
		return nil, fmt.Errorf("RSA modulus is empty")
	}
	if len(eBytes) == 0 {
		return nil, fmt.Errorf("RSA exponent is empty")
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	if !e.IsInt64() {
		return nil, fmt.Errorf("RSA exponent too large")
	}
	exp := int(e.Int64())
	if exp < 3 {
		return nil, fmt.Errorf("RSA exponent too small: %d", exp)
	}

	return &rsa.PublicKey{N: n, E: exp}, nil
}
