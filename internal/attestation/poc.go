package attestation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// PoCPeers lists the Proof of Cloud trust-server endpoints operated by
// alliance members. These are the three known signers for the threshold
// multisig. Source: https://github.com/proofofcloud/trust-server/blob/main/public_info/peers_list.txt
var PoCPeers = []string{
	"https://trust-server.scrtlabs.com",
	"https://trust-server.nillion.network",
	"https://trust-server.iex.ec",
}

const (
	// PoCQuorum is the number of signers required for the multisig threshold.
	PoCQuorum = 3
)

// PoCResult holds the result of a Proof of Cloud registry lookup.
type PoCResult struct {
	Registered bool
	MachineID  string
	Label      string
	JWT        string // the signed EdDSA JWT from the final signer
	Err        error  // network/parse error (distinct from "not registered")
}

// PoCClient queries Proof of Cloud trust-servers using threshold multisig.
type PoCClient struct {
	peers  []string // trust-server base URLs
	quorum int
	client *http.Client
	// signingKey is the EdDSA public key for JWT signature verification
	// (GW-M-11). When set, the final JWT is cryptographically verified
	// using this key. When nil, only claims are validated.
	signingKey ed25519.PublicKey
	// jwtVerifyFn validates the final JWT from the trust server. When nil,
	// verifyPoCJWTClaims is used (validates expiry and machine ID consistency).
	// Override for testing or when custom signature verification is desired.
	jwtVerifyFn func(jwtStr, machineID string) error
}

// NewPoCClient creates a PoCClient with the given trust-server peer URLs.
func NewPoCClient(peers []string, quorum int, client *http.Client) *PoCClient {
	return &PoCClient{peers: peers, quorum: quorum, client: client}
}

// NewPoCClientWithSigningKey creates a PoCClient that verifies EdDSA signatures
// on PoC JWTs using the provided ed25519 public key (GW-M-11). When the key is
// nil, behaviour is identical to NewPoCClient (claims-only validation).
func NewPoCClientWithSigningKey(peers []string, quorum int, client *http.Client, key ed25519.PublicKey) *PoCClient {
	return &PoCClient{peers: peers, quorum: quorum, client: client, signingKey: key}
}

// NewPoCClientWithCertPins creates a PoCClient with TLS certificate pinning.
// pins maps each trust-server hostname (e.g. "trust-server.scrtlabs.com") to
// one or more allowed SHA-256 DER certificate fingerprints (hex-encoded).
// Every HTTPS connection to a pinned host must present a certificate whose
// SHA-256 DER fingerprint matches at least one listed value (F-40).
// An empty map disables pinning and uses the provided client as-is.
func NewPoCClientWithCertPins(peers []string, quorum int, client *http.Client, pins map[string][]string) *PoCClient {
	pc := NewPoCClient(peers, quorum, client)
	if len(pins) > 0 {
		base := http.DefaultTransport
		if client != nil && client.Transport != nil {
			base = client.Transport
		}
		pinnedClient := &http.Client{
			Timeout:       client.Timeout,
			CheckRedirect: client.CheckRedirect,
			Jar:           client.Jar,
			Transport:     &pocCertPinTransport{base: base, pins: pins},
		}
		pc.client = pinnedClient
	}
	return pc
}

// pocCertPinTransport is an http.RoundTripper that enforces TLS certificate
// fingerprint pinning for configured hosts after each successful HTTPS request.
type pocCertPinTransport struct {
	base http.RoundTripper
	pins map[string][]string // hostname → allowed SHA-256 DER fingerprints (hex)
}

func (t *pocCertPinTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	hostPins, ok := t.pins[req.URL.Hostname()]
	if !ok || len(hostPins) == 0 {
		return resp, nil // no pins configured for this host
	}

	if resp.TLS == nil {
		// Enforce TLS when pins are configured.
		resp.Body.Close()
		return nil, fmt.Errorf("poc cert pin: HTTPS required for pinned host %s but connection is not TLS", req.URL.Hostname())
	}

	for _, cert := range resp.TLS.PeerCertificates {
		fp := sha256.Sum256(cert.Raw)
		fpHex := hex.EncodeToString(fp[:])
		for _, pin := range hostPins {
			if subtle.ConstantTimeCompare([]byte(fpHex), []byte(pin)) == 1 {
				return resp, nil // matched
			}
		}
	}

	resp.Body.Close()
	return nil, fmt.Errorf("poc cert pin: no certificate for %s matches a pinned fingerprint", req.URL.Hostname())
}

// Ensure pocCertPinTransport satisfies http.RoundTripper at compile time.
var _ http.RoundTripper = (*pocCertPinTransport)(nil)

// Reference tls.ConnectionState to confirm resp.TLS is *tls.ConnectionState.
var _ *tls.ConnectionState = (*tls.ConnectionState)(nil)

// pocJWTClaims holds the subset of JWT claims used by PoC trust-server tokens.
type pocJWTClaims struct {
	ExpiresAt int64  `json:"exp"`
	MachineID string `json:"machineId"`
}

// verifyPoCJWTClaims decodes the JWT payload (without verifying the
// cryptographic signature) and validates:
//   - The JWT is structurally valid (three base64url-encoded parts).
//   - The exp claim is present and the token is not expired.
//   - When expectedMachineID is non-empty, the machineId claim matches.
//
// SECURITY NOTE (F-39): This validates claims but does NOT verify the EdDSA
// signature. When a signing key is configured, PoCClient.verifyPoCJWT is used
// instead, providing full cryptographic verification (GW-M-11). The TLS
// transport (with CT checks) provides the primary channel integrity guarantee
// when no signing key is available.
func verifyPoCJWTClaims(jwtStr, expectedMachineID string) error {
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		return fmt.Errorf("malformed JWT: expected 3 dot-separated parts, got %d", len(parts))
	}

	// Decode the payload part (index 1).
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("decode JWT payload: %w", err)
	}

	var claims pocJWTClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("parse JWT claims: %w", err)
	}

	if claims.ExpiresAt == 0 {
		return errors.New("JWT is missing exp claim")
	}
	if time.Now().Unix() > claims.ExpiresAt {
		return fmt.Errorf("JWT has expired (exp=%d)", claims.ExpiresAt)
	}

	if expectedMachineID != "" && claims.MachineID != "" {
		if claims.MachineID != expectedMachineID {
			return fmt.Errorf("JWT machineId %q does not match stage-1 machineId %q",
				claims.MachineID, expectedMachineID)
		}
	}

	return nil
}

// stage1Response is the nonce response from a trust-server in multisig mode.
type stage1Response struct {
	MachineID string `json:"machineId"`
	Moniker   string `json:"moniker"`
	Nonce     string `json:"nonce"`
}

// stage2Response is a partial signature response or the final JWT response.
type stage2Response struct {
	// If the final signer returns a JWT, these fields are populated:
	MachineID string `json:"machineId,omitempty"`
	Label     string `json:"label,omitempty"`
	JWT       string `json:"jwt,omitempty"`
}

// CheckQuote runs the full multisig protocol against the trust-server
// peers and returns the registration result.
//
// Stage 1 nonces are collected in parallel from all peers (F-41); quorum is
// confirmed before proceeding to the sequential Stage 2 signature chain.
func (c *PoCClient) CheckQuote(ctx context.Context, hexQuote string) *PoCResult {
	// Stage 1: Collect nonces from quorum peers IN PARALLEL (F-41).
	// All configured peers are contacted concurrently; we proceed once quorum
	// have responded. A cancellable child context stops remaining goroutines.
	type nonceEntry struct {
		peerURL   string
		moniker   string
		nonce     string
		machineID string // from stage1Response; used for JWT cross-check (F-39)
	}

	type collectResult struct {
		n         nonceEntry
		err       error
		forbidden bool
	}

	ctx1, cancel1 := context.WithCancel(ctx)
	defer cancel1()

	collectCh := make(chan collectResult, len(c.peers))
	for _, peer := range c.peers {
		peerURL := peer
		go func() {
			body := map[string]string{"quote": hexQuote}
			resp, err := c.postJSON(ctx1, peerURL, "/get_jwt", body)
			if err != nil {
				collectCh <- collectResult{err: fmt.Errorf("stage 1 POST to %s: %w", peerURL, err)}
				return
			}
			if resp.statusCode == 403 {
				slog.Debug("PoC: peer returned 403 (not whitelisted)", "peer", peerURL)
				collectCh <- collectResult{forbidden: true}
				return
			}
			if resp.statusCode != 200 {
				collectCh <- collectResult{err: fmt.Errorf("stage 1: %s returned HTTP %d: %s",
					peerURL, resp.statusCode, truncateStr(string(resp.body), 256))}
				return
			}
			var s1 stage1Response
			if err := json.Unmarshal(resp.body, &s1); err != nil {
				collectCh <- collectResult{err: fmt.Errorf("stage 1: parse response from %s: %w", peerURL, err)}
				return
			}
			if s1.Moniker == "" || s1.Nonce == "" {
				collectCh <- collectResult{err: fmt.Errorf("stage 1: missing moniker/nonce from %s", peerURL)}
				return
			}
			slog.Debug("PoC: nonce collected", "peer", peerURL, "moniker", s1.Moniker)
			collectCh <- collectResult{n: nonceEntry{
				peerURL:   peerURL,
				moniker:   s1.Moniker,
				nonce:     s1.Nonce,
				machineID: s1.MachineID,
			}}
		}()
	}

	// Collect results; return on first 403 or once quorum is reached.
	var nonces []nonceEntry
	var lastErr error
	for range len(c.peers) {
		r := <-collectCh
		if r.forbidden {
			cancel1()
			return &PoCResult{Registered: false}
		}
		if r.err != nil {
			lastErr = r.err
			continue
		}
		nonces = append(nonces, r.n)
		if len(nonces) >= c.quorum {
			cancel1()
			break
		}
	}

	if len(nonces) < c.quorum {
		if lastErr != nil {
			return &PoCResult{Err: lastErr}
		}
		return &PoCResult{Err: fmt.Errorf("collected %d nonces, need %d", len(nonces), c.quorum)}
	}

	// Use the machine ID from the first stage-1 responder for JWT consistency.
	expectedMachineID := nonces[0].machineID

	// Build the nonces map: moniker → nonce_pub.
	noncesMap := make(map[string]string, len(nonces))
	for _, n := range nonces {
		noncesMap[n.moniker] = n.nonce
	}

	// Stage 2: Chain partial signatures through each peer (sequential by design).
	partialSigs := map[string]string{}

	for i, n := range nonces {
		reqBody := map[string]any{
			"quote":  hexQuote,
			"nonces": noncesMap,
		}
		if len(partialSigs) > 0 {
			reqBody["partial_sigs"] = partialSigs
		}

		resp, err := c.postJSON(ctx, n.peerURL, "/get_jwt", reqBody)
		if err != nil {
			return &PoCResult{Err: fmt.Errorf("stage 2 POST to %s: %w", n.peerURL, err)}
		}
		if resp.statusCode == 403 {
			return &PoCResult{Registered: false}
		}
		if resp.statusCode != 200 {
			return &PoCResult{Err: fmt.Errorf("stage 2: %s returned HTTP %d: %s", n.peerURL, resp.statusCode, resp.body)}
		}

		// Check if this is the final response (has jwt field).
		var s2 stage2Response
		if err := json.Unmarshal(resp.body, &s2); err != nil {
			return &PoCResult{Err: fmt.Errorf("stage 2: parse response from %s: %w", n.peerURL, err)}
		}

		if s2.JWT != "" {
			slog.Debug("PoC: final JWT received", "peer", n.peerURL, "label", s2.Label)

			// Validate JWT claims (F-39): expiry + machine ID consistency.
			// When a signing key is configured, also verify the EdDSA
			// signature (GW-M-11). jwtVerifyFn can be overridden for testing.
			verifyFn := c.jwtVerifyFn
			if verifyFn == nil {
				if c.signingKey != nil {
					verifyFn = c.verifyPoCJWT
				} else {
					verifyFn = verifyPoCJWTClaims
				}
			}
			if err := verifyFn(s2.JWT, expectedMachineID); err != nil {
				slog.Warn("PoC JWT claims validation failed", "peer", n.peerURL, "err", err)
				return &PoCResult{Err: fmt.Errorf("PoC JWT validation: %w", err)}
			}

			return &PoCResult{
				Registered: true,
				MachineID:  s2.MachineID,
				Label:      s2.Label,
				JWT:        s2.JWT,
			}
		}

		// Not the final signer — accumulate partial signatures.
		// The response is a map of moniker → partial_sig.
		var sigs map[string]string
		if err := json.Unmarshal(resp.body, &sigs); err != nil {
			return &PoCResult{Err: fmt.Errorf("stage 2: parse partial sigs from %s: %w", n.peerURL, err)}
		}
		partialSigs = sigs
		slog.Debug("PoC: partial sig collected", "peer", n.peerURL, "signer", i+1, "of", c.quorum)
	}

	return &PoCResult{Err: errors.New("stage 2 completed without final JWT")}
}

// verifyPoCJWT cryptographically verifies the EdDSA signature on a PoC JWT
// and validates claims (exp, machineId). This is used when PoCClient.signingKey
// is configured, providing a cryptographic guarantee beyond TLS channel integrity.
func (c *PoCClient) verifyPoCJWT(jwtStr, expectedMachineID string) error {
	token, err := jwt.Parse(jwtStr, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodEdDSA {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return c.signingKey, nil
	}, jwt.WithExpirationRequired())
	if err != nil {
		return fmt.Errorf("JWT EdDSA verification failed: %w", err)
	}
	if !token.Valid {
		return errors.New("JWT is not valid")
	}

	// Cross-check machineId claim against stage-1 response.
	if expectedMachineID != "" {
		if mid, _ := token.Claims.GetSubject(); mid == "" {
			// machineId is a custom claim — extract from map.
			if mc, ok := token.Claims.(jwt.MapClaims); ok {
				if mid, _ := mc["machineId"].(string); mid != "" && mid != expectedMachineID {
					return fmt.Errorf("JWT machineId %q does not match stage-1 machineId %q",
						mid, expectedMachineID)
				}
			}
		}
	}

	return nil
}

type httpResult struct {
	statusCode int
	body       []byte
}

func (c *PoCClient) postJSON(ctx context.Context, baseURL, path string, payload any) (*httpResult, error) {
	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	url := strings.TrimRight(baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB max
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return &httpResult{statusCode: resp.StatusCode, body: body}, nil
}
