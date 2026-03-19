package attestation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// nvidiaJWKSURL is NVIDIA's public JWKS endpoint for attestation JWT verification.
const nvidiaJWKSURL = "https://nras.attestation.nvidia.com/.well-known/jwks.json"

// nvidiaJWKSTTL is how long to cache the NVIDIA JWKS before re-fetching.
const nvidiaJWKSTTL = time.Hour

// NvidiaVerifyResult holds the structured outcome of NVIDIA payload verification.
// Fields are populated even on partial failure. Supports both EAT (local SPDM
// verification) and JWT (NRAS cloud verification) formats.
type NvidiaVerifyResult struct {
	// SignatureErr is non-nil if signature verification failed.
	// For EAT: cert chain or SPDM ECDSA signature failure.
	// For JWT: JWT signature verification failure.
	SignatureErr error

	// ClaimsErr is non-nil if claims/metadata are invalid.
	// For EAT: nonce mismatch or missing fields.
	// For JWT: expired, wrong issuer, etc.
	ClaimsErr error

	// Format is "EAT" or "JWT" depending on the payload type.
	Format string

	// Algorithm is the signature algorithm (e.g. "RS256" for JWT, "ECDSA-P384" for EAT).
	Algorithm string

	// OverallResult is the x-nvidia-overall-att-result claim value (JWT only).
	OverallResult string

	// Nonce is the nonce from the payload.
	Nonce string

	// Issuer is the iss claim from the JWT payload (JWT only).
	Issuer string

	// ExpiresAt is the exp claim from the JWT payload (JWT only).
	ExpiresAt time.Time

	// Arch is the GPU architecture family (e.g. "HOPPER") (EAT only).
	Arch string

	// GPUCount is the number of GPUs in the evidence list (EAT only).
	GPUCount int
}

// nvidiaClaims extends jwt.RegisteredClaims with NVIDIA-specific fields.
type nvidiaClaims struct {
	jwt.RegisteredClaims
	OverallResult string `json:"x-nvidia-overall-att-result"`
	Nonce         string `json:"nonce"`
}

// jwksCache is a package-level singleton for caching NVIDIA's JWKS.
var jwksCache = &nvidiaJWKSCache{}

// nvidiaJWKSCache caches the fetched JWKS keyset with a TTL.
type nvidiaJWKSCache struct {
	mu        sync.RWMutex
	keys      []cachedJWKSKey
	fetchedAt time.Time
}

// cachedJWKSKey pairs a kid with a usable RSA public key.
// The key field holds an *rsa.PublicKey (or other crypto.PublicKey).
type cachedJWKSKey struct {
	kid string
	key any
}

// keyfunc returns the jwt.Keyfunc that resolves signing keys from the cached JWKS.
// It re-fetches the JWKS if the cache is empty or expired.
func (c *nvidiaJWKSCache) keyfunc(ctx context.Context, client *http.Client) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		c.mu.RLock()
		expired := time.Since(c.fetchedAt) > nvidiaJWKSTTL || len(c.keys) == 0
		keys := c.keys
		c.mu.RUnlock()

		if expired {
			fresh, err := fetchAndParseJWKS(ctx, client)
			if err != nil {
				return nil, fmt.Errorf("fetch NVIDIA JWKS: %w", err)
			}
			c.mu.Lock()
			c.keys = fresh
			c.fetchedAt = time.Now()
			c.mu.Unlock()
			keys = fresh
		}

		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			// No kid in JWT: accept only if JWKS has exactly one key.
			if len(keys) == 1 {
				return keys[0].key, nil
			}
			return nil, fmt.Errorf("JWT missing kid header and JWKS has %d keys; cannot determine signing key", len(keys))
		}
		for _, k := range keys {
			if k.kid == kid {
				return k.key, nil
			}
		}
		return nil, fmt.Errorf("no matching key found in NVIDIA JWKS (kid=%q)", kid)
	}
}

// jwksJSON is the minimal JSON structure of a JWKS endpoint response.
type jwksJSON struct {
	Keys []jwkKeyJSON `json:"keys"`
}

// jwkKeyJSON represents one key entry in a JWKS document.
type jwkKeyJSON struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// fetchAndParseJWKS fetches the NVIDIA JWKS and returns usable key entries.
func fetchAndParseJWKS(ctx context.Context, client *http.Client) ([]cachedJWKSKey, error) {
	return fetchFromURL(ctx, client, nvidiaJWKSURL)
}

// fetchFromURL fetches a JWKS from the given URL and returns usable key entries.
// This is separated from fetchAndParseJWKS so tests can point at a local server.
func fetchFromURL(ctx context.Context, client *http.Client, url string) ([]cachedJWKSKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build JWKS request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB max
	if err != nil {
		return nil, fmt.Errorf("read JWKS body: %w", err)
	}

	return parseJWKS(body)
}

// parseJWKS converts raw JWKS JSON bytes into a slice of cachedJWKSKey.
// Only RSA keys are supported (the type NVIDIA uses for attestation JWTs).
func parseJWKS(data []byte) ([]cachedJWKSKey, error) {
	var raw jwksJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal JWKS JSON: %w", err)
	}

	var keys []cachedJWKSKey
	for _, k := range raw.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := rsaPublicKeyFromJWK(k.N, k.E)
		if err != nil {
			// Skip malformed keys; do not fail the entire keyset.
			continue
		}
		keys = append(keys, cachedJWKSKey{kid: k.Kid, key: pub})
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("JWKS contains no usable RSA keys")
	}
	return keys, nil
}

// rsaPublicKeyFromJWK builds an *rsa.PublicKey from the base64url-encoded
// modulus and exponent strings used in JWK format.
func rsaPublicKeyFromJWK(nB64, eB64 string) (any, error) {
	nBytes, err := decodeBase64URL(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := decodeBase64URL(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	return buildRSAPublicKey(nBytes, eBytes)
}

// VerifyNVIDIAPayload detects the NVIDIA attestation payload format and
// dispatches to the appropriate verifier:
//   - JSON starting with '{' containing evidence_list → EAT (local SPDM verification)
//   - JWT string starting with "ey" → NRAS JWT (cloud signature verification)
//
// ctx controls HTTP requests (JWKS fetching for JWT path). client is the HTTP
// client; pass nil for a default 30s timeout client. expectedNonce is required
// for EAT verification; it may be zero for the JWT path (nonce checked in report).
func VerifyNVIDIAPayload(ctx context.Context, payload string, expectedNonce Nonce, client *http.Client) *NvidiaVerifyResult {
	if len(payload) == 0 {
		return &NvidiaVerifyResult{SignatureErr: fmt.Errorf("empty NVIDIA payload")}
	}

	prefix := payload
	if len(prefix) > 200 {
		prefix = prefix[:200]
	}
	slog.Debug("NVIDIA payload received", "length", len(payload), "prefix", prefix)

	if payload[0] == '{' {
		slog.Debug("NVIDIA payload is EAT JSON, using local SPDM verification")
		return verifyNVIDIAEAT(payload, expectedNonce)
	}

	slog.Debug("NVIDIA payload appears to be JWT, using NRAS verification")
	return verifyNVIDIAJWT(ctx, payload, client)
}

// verifyNVIDIAJWT verifies an NVIDIA NRAS attestation JWT. It fetches (and
// caches) the NVIDIA JWKS, verifies the JWT signature, and extracts claims.
func verifyNVIDIAJWT(ctx context.Context, jwtPayload string, client *http.Client) *NvidiaVerifyResult {
	result := &NvidiaVerifyResult{Format: "JWT"}

	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	keyFunc := jwksCache.keyfunc(ctx, client)

	claims := &nvidiaClaims{}
	token, err := jwt.ParseWithClaims(jwtPayload, claims, keyFunc,
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		if isSignatureError(err) {
			result.SignatureErr = fmt.Errorf("JWT signature verification failed: %w", err)
		} else {
			result.ClaimsErr = fmt.Errorf("JWT claims validation failed: %w", err)
		}
		if token != nil {
			result.Algorithm = token.Method.Alg()
		}
		extractPartialClaims(claims, result)
		return result
	}

	if !token.Valid {
		result.ClaimsErr = fmt.Errorf("JWT is not valid after parsing")
		return result
	}

	result.Algorithm = token.Method.Alg()
	extractPartialClaims(claims, result)

	if result.OverallResult == "" {
		result.ClaimsErr = fmt.Errorf("x-nvidia-overall-att-result claim is missing")
	}

	return result
}

// extractPartialClaims copies fields from nvidiaClaims into the result.
func extractPartialClaims(claims *nvidiaClaims, result *NvidiaVerifyResult) {
	result.OverallResult = claims.OverallResult
	result.Nonce = claims.Nonce
	result.Issuer = claims.Issuer
	if claims.ExpiresAt != nil {
		result.ExpiresAt = claims.ExpiresAt.Time
	}
}

// isSignatureError returns true when err indicates a key or signature failure
// rather than a claims failure. In jwt/v5, use errors.Is for categorisation.
func isSignatureError(err error) bool {
	return errors.Is(err, jwt.ErrTokenSignatureInvalid) ||
		errors.Is(err, jwt.ErrTokenUnverifiable) ||
		errors.Is(err, jwt.ErrTokenMalformed)
}
