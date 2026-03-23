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

	"github.com/13rac1/teep/internal/tlsct"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// NvidiaJWKSURL is NVIDIA's public JWKS endpoint for attestation JWT verification.
//
//nolint:gochecknoglobals // var instead of const to allow test overrides
var NvidiaJWKSURL = "https://nras.attestation.nvidia.com/.well-known/jwks.json"

// NRASAttestURL is NVIDIA's Remote Attestation Service endpoint for GPU
// attestation. POST raw EAT JSON to receive a signed JWT with measurement
// comparison results against NVIDIA's Reference Integrity Manifest (RIM).
//
//nolint:gochecknoglobals // var instead of const to allow test overrides
var NRASAttestURL = "https://nras.attestation.nvidia.com/v3/attest/gpu"

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

// jwksEntry pairs a keyfunc.Keyfunc with its cancel function for cleanup.
type jwksEntry struct {
	kf        keyfunc.Keyfunc
	cancel    context.CancelFunc
	createdAt time.Time
}

// jwksInstances caches keyfunc instances by JWKS URL. Production uses
// NvidiaJWKSURL; tests use httptest server URLs. The keyfunc/v3 library handles
// background refresh, rate-limited unknown-kid refresh, and alg/use validation.
var jwksInstances sync.Map // URL string → *jwksEntry

var (
	// jwksCacheTTL bounds in-process JWKS cache lifetime.
	// keyfunc still performs background refresh; this adds a hard max age.
	jwksCacheTTL = time.Hour
	jwksMu       sync.Mutex
)

// getOrCreateKeyfunc returns a keyfunc.Keyfunc for the given JWKS URL.
// Instances are created once per URL and cached for the process lifetime.
func getOrCreateKeyfunc(_ context.Context, jwksURL string) (keyfunc.Keyfunc, error) {
	if v, ok := jwksInstances.Load(jwksURL); ok {
		entry := v.(*jwksEntry) //nolint:forcetypeassert // sync.Map value is always *jwksEntry
		if time.Since(entry.createdAt) < jwksCacheTTL {
			return entry.kf, nil
		}
	}

	jwksMu.Lock()
	defer jwksMu.Unlock()

	if v, ok := jwksInstances.Load(jwksURL); ok {
		entry := v.(*jwksEntry) //nolint:forcetypeassert // sync.Map value is always *jwksEntry
		if time.Since(entry.createdAt) < jwksCacheTTL {
			return entry.kf, nil
		}
	}

	kfCtx, cancel := context.WithCancel(context.Background())
	k, err := keyfunc.NewDefaultCtx(kfCtx, []string{jwksURL}) //nolint:contextcheck // keyfunc manages its own context lifecycle

	if err != nil {
		cancel()
		return nil, fmt.Errorf("initialize JWKS for %s: %w", jwksURL, err)
	}
	entry := &jwksEntry{kf: k, cancel: cancel, createdAt: time.Now()}
	if old, ok := jwksInstances.Load(jwksURL); ok {
		prev := old.(*jwksEntry) //nolint:forcetypeassert // sync.Map value is always *jwksEntry
		prev.cancel()
	}
	jwksInstances.Store(jwksURL, entry)
	return k, nil
}

// resetJWKS shuts down and removes all cached JWKS instances. Used by tests.
func resetJWKS() {
	jwksInstances.Range(func(key, value any) bool {
		entry := value.(*jwksEntry) //nolint:forcetypeassert // sync.Map value is always *jwksEntry
		entry.cancel()
		jwksInstances.Delete(key)
		return true
	})
}

// VerifyNVIDIAPayload verifies the NVIDIA attestation payload via local SPDM
// certificate chain and signature verification. The payload must be EAT JSON
// (starting with '{'). NRAS cloud verification is handled separately by
// VerifyNVIDIANRAS.
func VerifyNVIDIAPayload(payload string, expectedNonce Nonce) *NvidiaVerifyResult {
	if payload == "" {
		return &NvidiaVerifyResult{SignatureErr: errors.New("empty NVIDIA payload")}
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
// caches) the NVIDIA JWKS via keyfunc/v3, verifies the JWT signature, and
// extracts claims. Nonce freshness is verified separately via the EAT layer
// (factor 14: nvidia_nonce_match).
func verifyNVIDIAJWT(ctx context.Context, jwtPayload, jwksURL string, opts ...jwt.ParserOption) *NvidiaVerifyResult {
	result := &NvidiaVerifyResult{Format: "JWT"}

	kf, err := getOrCreateKeyfunc(ctx, jwksURL)
	if err != nil {
		result.SignatureErr = fmt.Errorf("JWKS initialization: %w", err)
		return result
	}

	claims := &nvidiaClaims{}
	parserOpts := append([]jwt.ParserOption{
		jwt.WithValidMethods([]string{"ES256", "ES384", "ES512"}),
		jwt.WithExpirationRequired(),
	}, opts...)
	token, err := jwt.ParseWithClaims(jwtPayload, claims, kf.Keyfunc, parserOpts...)

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
		result.ClaimsErr = errors.New("JWT is not valid after parsing")
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
func VerifyNVIDIANRAS(ctx context.Context, eatPayload string, client *http.Client, opts ...jwt.ParserOption) *NvidiaVerifyResult {
	if client == nil {
		client = tlsct.NewHTTPClient(30 * time.Second)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, NRASAttestURL, strings.NewReader(eatPayload))
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
			SignatureErr: errors.New("NRAS returned empty response"),
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

	return verifyNVIDIAJWT(ctx, extracted, NvidiaJWKSURL, opts...)
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
