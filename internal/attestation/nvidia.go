package attestation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// nvidiaJWKSURL is NVIDIA's public JWKS endpoint for attestation JWT verification.
const nvidiaJWKSURL = "https://nras.attestation.nvidia.com/.well-known/jwks.json"

// nvidiaJWKSTTL is how long to cache the NVIDIA JWKS before re-fetching.
const nvidiaJWKSTTL = time.Hour

// NvidiaVerifyResult holds the structured outcome of NVIDIA JWT parsing and
// verification. Fields are populated even on partial failure.
type NvidiaVerifyResult struct {
	// SignatureErr is non-nil if the JWT signature could not be verified.
	SignatureErr error

	// ClaimsErr is non-nil if the JWT claims are invalid (expired, wrong issuer, etc.).
	ClaimsErr error

	// Algorithm is the JWT signature algorithm (e.g. "RS256").
	Algorithm string

	// OverallResult is the x-nvidia-overall-att-result claim value.
	OverallResult string

	// Nonce is the nonce claim from the JWT payload (may be empty if absent).
	Nonce string

	// Issuer is the iss claim from the JWT payload.
	Issuer string

	// ExpiresAt is the exp claim from the JWT payload.
	ExpiresAt time.Time
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
		for _, k := range keys {
			if kid == "" || k.kid == kid {
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

	body, err := io.ReadAll(resp.Body)
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

// VerifyNVIDIAJWT verifies the NVIDIA attestation JWT payload string. It
// fetches (and caches) the NVIDIA JWKS, verifies the JWT signature, and
// extracts the claims.
//
// ctx controls the HTTP request for JWKS fetching. client is the HTTP client
// to use; pass nil to use a default client with a 30s timeout.
func VerifyNVIDIAJWT(ctx context.Context, jwtPayload string, client *http.Client) *NvidiaVerifyResult {
	result := &NvidiaVerifyResult{}

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
		// Categorise the error: signature/key problems vs claims problems.
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

	// Validate NVIDIA-specific claims.
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
