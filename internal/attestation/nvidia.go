package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/13rac1/teep/internal/tlsct"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// NvidiaJWKSURL is NVIDIA's public JWKS endpoint for attestation JWT verification.
var NvidiaJWKSURL = "https://nras.attestation.nvidia.com/.well-known/jwks.json"

// NRASAttestURL is NVIDIA's Remote Attestation Service endpoint for GPU
// attestation. POST raw EAT JSON to receive a signed JWT with measurement
// comparison results against NVIDIA's Reference Integrity Manifest (RIM).
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

	// GPUDiags holds per-GPU diagnostic claims from the NRAS response (JWT only).
	GPUDiags []NRASGPUDiag
}

// NRASGPUDiag holds diagnostic claims extracted from a single per-GPU NRAS JWT.
// When attestation succeeds, NRAS returns full claims (MeasRes, DriverVersion, etc.).
// When attestation fails, NRAS returns only x-nvidia-error-details.
type NRASGPUDiag struct {
	GPUID         string // e.g. "GPU-0"
	MeasRes       string // "success" or "fail" (empty on error)
	DriverVersion string
	VBIOSVersion  string
	HWModel       string
	NonceMatch    bool
	SecBoot       bool
	DbgStat       string // "disabled" or "enabled"
	ErrorDetails  string // x-nvidia-error-details (set on failure)
}

// nvidiaClaims extends jwt.RegisteredClaims with NVIDIA-specific fields.
type nvidiaClaims struct {
	jwt.RegisteredClaims
	OverallResult bool   `json:"x-nvidia-overall-att-result"`
	Nonce         string `json:"eat_nonce"`
}

// jwksEntry pairs a keyfunc.Keyfunc with its cancel function for cleanup.
type jwksEntry struct {
	kf        keyfunc.Keyfunc
	cancel    context.CancelFunc
	createdAt time.Time
}

var (
	// jwksCacheTTL bounds in-process JWKS cache lifetime.
	// keyfunc still performs background refresh; this adds a hard max age.
	jwksCacheTTL = time.Hour
	jwksMu       sync.Mutex
	// jwksInstances caches keyfunc instances by JWKS URL. Production uses
	// NvidiaJWKSURL; tests use httptest server URLs. Protected by jwksMu.
	jwksInstances = make(map[string]*jwksEntry)
)

// getOrCreateKeyfunc returns a keyfunc.Keyfunc for the given JWKS URL.
// Instances are created once per URL and cached for the process lifetime.
func getOrCreateKeyfunc(jwksURL string) (keyfunc.Keyfunc, error) {
	jwksMu.Lock()
	defer jwksMu.Unlock()

	if entry, ok := jwksInstances[jwksURL]; ok {
		if time.Since(entry.createdAt) < jwksCacheTTL {
			return entry.kf, nil
		}
	}

	kfCtx, cancel := context.WithCancel(context.Background())
	k, err := keyfunc.NewDefaultCtx(kfCtx, []string{jwksURL})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("initialize JWKS for %s: %w", jwksURL, err)
	}
	if prev, ok := jwksInstances[jwksURL]; ok {
		prev.cancel()
	}
	entry := &jwksEntry{kf: k, cancel: cancel, createdAt: time.Now()}
	jwksInstances[jwksURL] = entry
	return k, nil
}

// resetJWKS shuts down and removes all cached JWKS instances. Used by tests.
func resetJWKS() {
	jwksMu.Lock()
	defer jwksMu.Unlock()
	for url, entry := range jwksInstances {
		entry.cancel()
		delete(jwksInstances, url)
	}
}

// ShutdownJWKS cancels all background JWKS refresh goroutines and removes
// all cached instances. Call this during graceful shutdown to prevent goroutine
// leaks from the background keyfunc refresh loops (F-35).
func ShutdownJWKS() {
	resetJWKS()
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
// (factor: nvidia_nonce_client_bound).
func verifyNVIDIAJWT(jwtPayload, jwksURL string, opts ...jwt.ParserOption) *NvidiaVerifyResult {
	result := &NvidiaVerifyResult{Format: "JWT"}

	kf, err := getOrCreateKeyfunc(jwksURL)
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

	// NRAS v3 returns [["JWT","<overall>"], {"GPU-0":"<jwt>", ...}].
	overallJWT, perGPU, err := extractNRASJWT(jwtStr)
	if err != nil {
		return &NvidiaVerifyResult{
			Format:       "JWT",
			SignatureErr: fmt.Errorf("parse NRAS response: %w", err),
		}
	}

	result := verifyNVIDIAJWT(overallJWT, NvidiaJWKSURL, opts...) //nolint:contextcheck // keyfunc manages its own background context for JWKS refresh
	result.GPUDiags = extractGPUDiags(perGPU)
	return result
}

// extractGPUDiags decodes per-GPU JWT payloads (without signature verification)
// and extracts diagnostic claims. The per-GPU JWTs share the same JWKS as the
// overall JWT and their digests are checked via the submods claim, so
// re-verifying signatures is unnecessary.
func extractGPUDiags(perGPU map[string]string) []NRASGPUDiag {
	if len(perGPU) == 0 {
		return nil
	}

	// Sort GPU IDs for deterministic output.
	ids := make([]string, 0, len(perGPU))
	for id := range perGPU {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	diags := make([]NRASGPUDiag, 0, len(ids))
	for _, id := range ids {
		jwtStr := perGPU[id]
		claims, err := decodeJWTPayload(jwtStr)
		if err != nil {
			slog.Warn("failed to decode per-GPU JWT payload", "gpu", id, "err", err)
			diags = append(diags, NRASGPUDiag{GPUID: id, MeasRes: fmt.Sprintf("decode error: %v", err)})
			continue
		}
		slog.Debug("per-GPU JWT decoded", "gpu", id, "claim_count", len(claims),
			"measres", claims["measres"], "error_details", claims["x-nvidia-error-details"])
		diags = append(diags, NRASGPUDiag{
			GPUID:         id,
			MeasRes:       jsonString(claims, "measres"),
			DriverVersion: jsonString(claims, "x-nvidia-gpu-driver-version"),
			VBIOSVersion:  jsonString(claims, "x-nvidia-gpu-vbios-version"),
			HWModel:       jsonString(claims, "hwmodel"),
			NonceMatch:    jsonBool(claims, "x-nvidia-gpu-attestation-report-nonce-match"),
			SecBoot:       jsonBool(claims, "secboot"),
			DbgStat:       jsonString(claims, "dbgstat"),
			ErrorDetails:  nvidiaErrorMessage(claims),
		})
	}
	return diags
}

// decodeJWTPayload extracts and JSON-decodes the payload segment of a JWT
// without verifying the signature.
func decodeJWTPayload(jwtStr string) (map[string]any, error) {
	parts := strings.SplitN(jwtStr, ".", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("JWT has %d parts, want at least 2", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("base64url decode payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal payload JSON: %w", err)
	}
	return claims, nil
}

func jsonString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}

func jsonBool(m map[string]any, key string) bool {
	v, ok := m[key]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	if !ok {
		return false
	}
	return b
}

// nvidiaErrorMessage extracts the message from x-nvidia-error-details, which is
// a nested object like {"code":4010, "message":"NONCE_NOT_MATCHING", ...}.
func nvidiaErrorMessage(claims map[string]any) string {
	v, ok := claims["x-nvidia-error-details"]
	if !ok {
		return ""
	}
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	msg := jsonString(m, "message")
	if msg == "" {
		msg = jsonString(m, "description")
	}
	return msg
}

// extractNRASJWT parses the NRAS response body. NRAS v3 returns a JSON array:
//
//	[["JWT","<overall-jwt>"], {"GPU-0":"<jwt>", "GPU-1":"<jwt>", ...}]
//
// The first element is a [type, token] pair with the overall summary JWT.
// The second element (if present) is an object mapping GPU IDs to per-GPU JWTs
// containing detailed attestation claims.
func extractNRASJWT(body string) (overallJWT string, perGPU map[string]string, err error) {
	var elements []json.RawMessage
	if err := json.Unmarshal([]byte(body), &elements); err != nil {
		return "", nil, fmt.Errorf("NRAS response is not a JSON array: %w (prefix: %s)", err, truncate(body, 100))
	}
	for _, elem := range elements {
		// Try ["JWT","eyJ..."] pair.
		var pair []string
		if json.Unmarshal(elem, &pair) == nil && len(pair) == 2 && pair[0] == "JWT" {
			overallJWT = strings.TrimSpace(pair[1])
			continue
		}
		// Try {"GPU-0":"eyJ...", ...} object.
		var gpuMap map[string]string
		if json.Unmarshal(elem, &gpuMap) == nil && len(gpuMap) > 0 {
			perGPU = gpuMap
		}
	}
	if overallJWT == "" {
		return "", nil, fmt.Errorf("no JWT entry found in NRAS response (%d elements)", len(elements))
	}
	slog.Debug("NRAS JWT extracted", "overall_len", len(overallJWT), "per_gpu_count", len(perGPU))
	return overallJWT, perGPU, nil
}

// truncate returns s truncated to maxLen characters with "..." appended if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
