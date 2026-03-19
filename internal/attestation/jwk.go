package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"
)

// decodeBase64URL decodes a base64url-encoded string (no padding required).
func decodeBase64URL(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64url decode: %w", err)
	}
	return b, nil
}

// ecPublicKeyFromJWK builds an *ecdsa.PublicKey from JWK EC fields.
func ecPublicKeyFromJWK(crv, xB64, yB64 string) (*ecdsa.PublicKey, error) {
	curve, err := curveFromName(crv)
	if err != nil {
		return nil, err
	}

	xBytes, err := decodeBase64URL(xB64)
	if err != nil {
		return nil, fmt.Errorf("decode EC x: %w", err)
	}
	yBytes, err := decodeBase64URL(yB64)
	if err != nil {
		return nil, fmt.Errorf("decode EC y: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("EC point is not on curve %s", crv)
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// curveFromName returns the elliptic.Curve for the given JWK crv name.
func curveFromName(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported EC curve: %q", crv)
	}
}
