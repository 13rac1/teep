package attestation

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"
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
}

// NewPoCClient creates a PoCClient with the given trust-server peer URLs.
func NewPoCClient(peers []string, quorum int, client *http.Client) *PoCClient {
	return &PoCClient{peers: peers, quorum: quorum, client: client}
}

// pocJWTClaims holds the subset of JWT claims used by PoC trust-server tokens.
type pocJWTClaims struct {
	ExpiresAt *int64 `json:"exp"`
	MachineID string `json:"machine_id"`
}

// verifyPoCJWTClaims decodes the JWT payload (without verifying the
// cryptographic signature) and validates:
//   - The JWT is structurally valid (three base64url-encoded parts).
//   - If the exp claim is present, the token is not expired (absent exp is logged at INFO).
//   - When expectedMachineID is non-empty, the machine_id claim matches.
//
// Channel integrity is provided by TLS (with CT checks). This is the sole JWT
// validation path.
func verifyPoCJWTClaims(ctx context.Context, jwtStr, expectedMachineID string) error {
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

	if claims.ExpiresAt == nil {
		slog.InfoContext(ctx, "PoC JWT missing exp claim; accepting without expiry check (replay protection not enforced)")
	} else if time.Now().Unix() > *claims.ExpiresAt {
		return fmt.Errorf("JWT has expired (exp=%d)", *claims.ExpiresAt)
	}

	if expectedMachineID != "" {
		if claims.MachineID == "" {
			return fmt.Errorf("JWT missing machine_id claim, expected %q", expectedMachineID)
		}
		if subtle.ConstantTimeCompare([]byte(claims.MachineID), []byte(expectedMachineID)) != 1 {
			return fmt.Errorf("JWT machine_id %q does not match stage-1 machineId %q",
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
				slog.DebugContext(ctx1, "PoC: peer returned 403 (not whitelisted)", "peer", peerURL)
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
			slog.DebugContext(ctx1, "PoC: nonce collected", "peer", peerURL, "moniker", s1.Moniker)
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

	// Deterministic peer order for stage 2: goroutine scheduling is
	// non-deterministic, so the nonces slice arrives in random order.
	// Sorting ensures stage 2 POST bodies (which include partial_sigs
	// from prior peers) are identical across runs — required for
	// capture/replay round-tripping.
	sort.Slice(nonces, func(i, j int) bool {
		return nonces[i].peerURL < nonces[j].peerURL
	})

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
			slog.DebugContext(ctx, "PoC: final JWT received", "peer", n.peerURL, "label", s2.Label)

			// Validate JWT claims (F-39): expiry + machine ID consistency.
			if err := verifyPoCJWTClaims(ctx, s2.JWT, expectedMachineID); err != nil {
				slog.WarnContext(ctx, "PoC JWT claims validation failed", "peer", n.peerURL, "err", err)
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
		slog.DebugContext(ctx, "PoC: partial sig collected", "peer", n.peerURL, "signer", i+1, "of", c.quorum)
	}

	return &PoCResult{Err: errors.New("stage 2 completed without final JWT")}
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
