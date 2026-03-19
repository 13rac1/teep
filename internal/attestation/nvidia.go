package attestation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// nvidiaJWKSURL is NVIDIA's public JWKS endpoint for attestation JWT verification.
const nvidiaJWKSURL = "https://nras.attestation.nvidia.com/.well-known/jwks.json"

// nrasAttestURL is NVIDIA's Remote Attestation Service endpoint for GPU
// attestation. POST raw EAT JSON to receive a signed JWT with measurement
// comparison results against NVIDIA's Reference Integrity Manifest (RIM).
const nrasAttestURL = "https://nras.attestation.nvidia.com/v3/attest/gpu"

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
	OverallResult bool

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
	OverallResult bool   `json:"x-nvidia-overall-att-result"`
	Nonce         string `json:"nonce"`
}

// jwksCache is a package-level singleton for caching NVIDIA's JWKS.
var jwksCache = &nvidiaJWKSCache{}

// nvidiaJWKSCache caches the fetched JWKS keyset with a TTL.
type nvidiaJWKSCache struct {
	mu        sync.Mutex
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
		c.mu.Lock()
		if time.Since(c.fetchedAt) > nvidiaJWKSTTL || len(c.keys) == 0 {
			fresh, err := fetchAndParseJWKS(ctx, client)
			if err != nil {
				c.mu.Unlock()
				return nil, fmt.Errorf("fetch NVIDIA JWKS: %w", err)
			}
			c.keys = fresh
			c.fetchedAt = time.Now()
		}
		keys := c.keys
		c.mu.Unlock()

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
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
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
// Only EC keys are supported (NVIDIA NRAS uses ES384).
func parseJWKS(data []byte) ([]cachedJWKSKey, error) {
	var raw jwksJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal JWKS JSON: %w", err)
	}

	var keys []cachedJWKSKey
	for _, k := range raw.Keys {
		if k.Kty != "EC" {
			continue
		}
		pub, err := ecPublicKeyFromJWK(k.Crv, k.X, k.Y)
		if err != nil {
			slog.Debug("JWKS: skipping malformed EC key", "kid", k.Kid, "err", err)
			continue
		}
		keys = append(keys, cachedJWKSKey{kid: k.Kid, key: pub})
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("JWKS contains no usable EC keys")
	}
	return keys, nil
}

// VerifyNVIDIAPayload verifies the NVIDIA attestation payload via local SPDM
// certificate chain and signature verification. The payload must be EAT JSON
// (starting with '{'). NRAS cloud verification is handled separately by
// VerifyNVIDIANRAS.
func VerifyNVIDIAPayload(payload string, expectedNonce Nonce) *NvidiaVerifyResult {
	if len(payload) == 0 {
		return &NvidiaVerifyResult{SignatureErr: fmt.Errorf("empty NVIDIA payload")}
	}

	prefix := payload
	if len(prefix) > 200 {
		prefix = prefix[:200]
	}
	slog.Debug("NVIDIA payload received", "length", len(payload), "prefix", prefix)

	if payload[0] != '{' {
		return &NvidiaVerifyResult{
			SignatureErr: fmt.Errorf("NVIDIA payload is not EAT JSON (starts with %q)", payload[:min(10, len(payload))]),
		}
	}

	return verifyNVIDIAEAT(payload, expectedNonce)
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
		jwt.WithValidMethods([]string{"ES256", "ES384", "ES512"}),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		if isSignatureError(err) {
			result.SignatureErr = fmt.Errorf("JWT signature verification failed: %w", err)
		} else {
			result.ClaimsErr = fmt.Errorf("JWT claims validation failed: %w", err)
		}
		if token != nil && token.Method != nil {
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

// VerifyNVIDIANRAS posts the raw EAT payload to NVIDIA's Remote Attestation
// Service for RIM-based measurement comparison and verifies the returned JWT.
// This provides defense-in-depth: local SPDM verification proves evidence is
// well-formed; NRAS compares GPU firmware measurements against NVIDIA's golden
// Reference Integrity Manifest values.
func VerifyNVIDIANRAS(ctx context.Context, eatPayload string, client *http.Client) *NvidiaVerifyResult {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nrasAttestURL, strings.NewReader(eatPayload))
	if err != nil {
		return &NvidiaVerifyResult{
			Format:       "JWT",
			SignatureErr: fmt.Errorf("build NRAS request: %w", err),
		}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return &NvidiaVerifyResult{
			Format:       "JWT",
			SignatureErr: fmt.Errorf("NRAS POST: %w", err),
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB max
	if err != nil {
		return &NvidiaVerifyResult{
			Format:       "JWT",
			SignatureErr: fmt.Errorf("read NRAS response: %w", err),
		}
	}

	if resp.StatusCode != http.StatusOK {
		return &NvidiaVerifyResult{
			Format:    "JWT",
			ClaimsErr: fmt.Errorf("NRAS returned HTTP %d: %s", resp.StatusCode, truncate(string(body), 200)),
		}
	}

	jwtStr := strings.TrimSpace(string(body))
	if jwtStr == "" {
		return &NvidiaVerifyResult{
			Format:       "JWT",
			SignatureErr: fmt.Errorf("NRAS returned empty response"),
		}
	}

	slog.Debug("NRAS response", "status", resp.StatusCode,
		"content_type", resp.Header.Get("Content-Type"),
		"body_len", len(jwtStr),
		"body_prefix", truncate(jwtStr, 200))

	// NRAS returns a JSON array of [type, token] pairs: [["JWT","eyJ..."]].
	// Extract the first JWT from this structure.
	extracted, err := extractNRASJWT(jwtStr)
	if err != nil {
		return &NvidiaVerifyResult{
			Format:       "JWT",
			SignatureErr: fmt.Errorf("parse NRAS response: %w", err),
		}
	}

	return verifyNVIDIAJWT(ctx, extracted, client)
}

// extractNRASJWT parses the NRAS response body. NRAS returns a JSON array
// whose elements may be [type, token] pairs or other structures. This extracts
// the first JWT from any ["JWT","eyJ..."] pair.
func extractNRASJWT(body string) (string, error) {
	var elements []json.RawMessage
	if err := json.Unmarshal([]byte(body), &elements); err != nil {
		return "", fmt.Errorf("NRAS response is not a JSON array: %w (prefix: %s)", err, truncate(body, 100))
	}
	for _, elem := range elements {
		var pair []string
		if err := json.Unmarshal(elem, &pair); err != nil {
			continue // skip non-array elements
		}
		if len(pair) == 2 && pair[0] == "JWT" {
			return strings.TrimSpace(pair[1]), nil
		}
	}
	return "", fmt.Errorf("no JWT entry found in NRAS response (%d elements)", len(elements))
}

// truncate returns s truncated to maxLen characters with "..." appended if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
