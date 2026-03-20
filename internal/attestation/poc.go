package attestation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
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
func (c *PoCClient) CheckQuote(ctx context.Context, hexQuote string) *PoCResult {
	// Stage 1: Collect nonces from quorum peers.
	type nonceEntry struct {
		peerURL string
		moniker string
		nonce   string
	}

	var nonces []nonceEntry
	for _, peer := range c.peers {
		if len(nonces) >= c.quorum {
			break
		}

		body := map[string]string{"quote": hexQuote}
		resp, err := c.postJSON(ctx, peer, "/get_jwt", body)
		if err != nil {
			return &PoCResult{Err: fmt.Errorf("stage 1 POST to %s: %w", peer, err)}
		}

		// 403 = not whitelisted.
		if resp.statusCode == 403 {
			slog.Debug("PoC: peer returned 403 (not whitelisted)", "peer", peer)
			return &PoCResult{Registered: false}
		}
		if resp.statusCode != 200 {
			return &PoCResult{Err: fmt.Errorf("stage 1: %s returned HTTP %d: %s", peer, resp.statusCode, resp.body)}
		}

		var s1 stage1Response
		if err := json.Unmarshal(resp.body, &s1); err != nil {
			return &PoCResult{Err: fmt.Errorf("stage 1: parse response from %s: %w", peer, err)}
		}
		if s1.Moniker == "" || s1.Nonce == "" {
			return &PoCResult{Err: fmt.Errorf("stage 1: missing moniker/nonce from %s", peer)}
		}

		slog.Debug("PoC: nonce collected", "peer", peer, "moniker", s1.Moniker)
		nonces = append(nonces, nonceEntry{peerURL: peer, moniker: s1.Moniker, nonce: s1.Nonce})
	}

	if len(nonces) < c.quorum {
		return &PoCResult{Err: fmt.Errorf("collected %d nonces, need %d", len(nonces), c.quorum)}
	}

	// Build the nonces map: moniker → nonce_pub.
	noncesMap := make(map[string]string, len(nonces))
	for _, n := range nonces {
		noncesMap[n.moniker] = n.nonce
	}

	// Stage 2: Chain partial signatures through each peer.
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
