// capture_venice fetches a Venice attestation response and all related
// external service responses needed for the fixture-based integration test.
//
// It saves everything to internal/integration/testdata/venice_YYYYMMDD_HHMMSS/.
//
// Usage:
//
//	VENICE_API_KEY=... go run ./cmd/capture_venice [--model MODEL]
//
// Requires VENICE_API_KEY. Run manually when fixtures need refreshing.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	tdxabi "github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	tdxverify "github.com/google/go-tdx-guest/verify"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/tlsct"
)

const (
	defaultModel    = "e2ee-qwen3-5-122b-a10b"
	defaultBaseURL  = "https://api.venice.ai"
	attestationPath = "/api/v1/tee/attestation"
	nrasURL         = "https://nras.attestation.nvidia.com/v3/attest/gpu"
	jwksURL         = "https://nras.attestation.nvidia.com/.well-known/jwks.json"
	testdataDir     = "internal/integration/testdata"
	httpTimeout     = 60 * time.Second
)

// outDir is set in main() to the timestamped save directory.
var outDir string

func main() {
	model := flag.String("model", defaultModel, "model name for attestation")
	flag.Parse()

	apiKey := os.Getenv("VENICE_API_KEY")
	if apiKey == "" {
		fatal("VENICE_API_KEY not set")
	}

	captureTime := time.Now().UTC()
	saveDir := filepath.Join(testdataDir, captureTime.Format("venice_20060102_150405"))
	if err := os.MkdirAll(saveDir, 0o750); err != nil {
		fatalf("mkdir %s: %v", saveDir, err)
	}
	outDir = saveDir
	fmt.Printf("save directory: %s\n", saveDir)
	fmt.Printf("capture time: %s\n", captureTime.Format(time.RFC3339))

	ctx := context.Background()
	client := tlsct.NewHTTPClient(httpTimeout)

	// 1. Generate nonce.
	var nonceBytes [32]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		fatalf("generate nonce: %v", err)
	}
	nonceHex := hex.EncodeToString(nonceBytes[:])
	fmt.Printf("nonce: %s\n", nonceHex)

	// 2. Fetch Venice attestation.
	fmt.Println("--- fetching Venice attestation ---")
	attestBody := fetchAttestation(ctx, client, defaultBaseURL, apiKey, *model, nonceHex)
	writeFile("venice_attestation.json", attestBody)
	writeFile("venice_fixture_nonce.txt", []byte(nonceHex+"\n"))
	fmt.Printf("attestation response: %d bytes\n", len(attestBody))

	// 3. Extract intel_quote and nvidia_payload.
	intelQuote, nvidiaPayload := extractQuoteAndPayload(attestBody)
	fmt.Printf("intel_quote: %d hex chars\n", len(intelQuote))
	fmt.Printf("nvidia_payload: %d bytes\n", len(nvidiaPayload))

	fmspc, ca := extractFMSPC(intelQuote)
	fmt.Printf("FMSPC: %s, CA: %s\n", fmspc, ca)

	// 4. Fetch Intel PCS collateral.
	fmt.Println("--- fetching Intel PCS collateral ---")
	fetchAndSavePCS(ctx, client, fmspc, ca)

	// 5. Fetch NVIDIA NRAS response.
	fmt.Println("--- fetching NVIDIA NRAS ---")
	if nvidiaPayload != "" && nvidiaPayload[0] == '{' {
		nrasReq, err := http.NewRequestWithContext(ctx, http.MethodPost, nrasURL, strings.NewReader(nvidiaPayload))
		if err != nil {
			fatalf("build NRAS request: %v", err)
		}
		nrasReq.Header.Set("Content-Type", "application/json")
		nrasReq.Header.Set("Accept", "application/json")
		nrasBody := doRequest(client, nrasReq).body
		writeFile("venice_nras_response.json", nrasBody)
		fmt.Printf("NRAS response: %d bytes\n", len(nrasBody))
	} else {
		fmt.Println("skipping NRAS: nvidia_payload is not EAT JSON")
	}

	// 6. Fetch NVIDIA JWKS.
	fmt.Println("--- fetching NVIDIA JWKS ---")
	jwksBody := doGet(ctx, client, jwksURL)
	writeFile("venice_nras_jwks.json", jwksBody)
	fmt.Printf("JWKS response: %d bytes\n", len(jwksBody))

	// 7. Fetch PoC responses.
	fmt.Println("--- fetching PoC responses ---")
	fetchPoC(ctx, client, intelQuote)

	fmt.Println("--- done ---")
	fmt.Printf("Fixtures saved to %s/\n", saveDir)
	fmt.Println("Run integration test with:")
	fmt.Println("  go test -v -race -run TestIntegration_Venice_Fixture ./internal/integration/")
	fmt.Println("(auto-discovers latest fixture dir; or override with VENICE_FIXTURE_DIR=<absolute-path>)")
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

type httpResult struct {
	statusCode int
	header     http.Header
	body       []byte
}

func doRequest(client *http.Client, req *http.Request) httpResult {
	res := doRequestRaw(client, req)
	if res.statusCode != http.StatusOK {
		fatalf("%s %s: HTTP %d: %s", req.Method, req.URL, res.statusCode, truncate(string(res.body)))
	}
	return res
}

func doRequestRaw(client *http.Client, req *http.Request) httpResult {
	fmt.Printf("  > %s %s\n", req.Method, req.URL)
	resp, err := client.Do(req)
	if err != nil {
		fatalf("%s %s: %v", req.Method, req.URL, err)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	resp.Body.Close()
	if err != nil {
		fatalf("%s %s: read body: %v", req.Method, req.URL, err)
	}
	return httpResult{statusCode: resp.StatusCode, header: resp.Header, body: body}
}

func doGet(ctx context.Context, client *http.Client, u string) []byte {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		fatalf("build GET %s: %v", u, err)
	}
	return doRequest(client, req).body
}

func doPostJSON(ctx context.Context, client *http.Client, u string, payload any) httpResult {
	jsonBody, err := json.Marshal(payload)
	if err != nil {
		fatalf("marshal POST body for %s: %v", u, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(jsonBody))
	if err != nil {
		fatalf("build POST %s: %v", u, err)
	}
	req.Header.Set("Content-Type", "application/json")
	return doRequestRaw(client, req)
}

// ---------------------------------------------------------------------------
// Venice attestation
// ---------------------------------------------------------------------------

func fetchAttestation(ctx context.Context, client *http.Client, baseURL, apiKey, model, nonce string) []byte {
	endpoint, err := url.Parse(baseURL + attestationPath)
	if err != nil {
		fatalf("parse URL: %v", err)
	}
	q := endpoint.Query()
	q.Set("model", model)
	q.Set("nonce", nonce)
	endpoint.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		fatalf("build attestation request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	return doRequest(client, req).body
}

// Venice attestation response has intel_quote and nvidia_payload at the top level.
func extractQuoteAndPayload(body []byte) (intelQuote, nvidiaPayload string) {
	var ar struct {
		IntelQuote    string `json:"intel_quote"`
		NvidiaPayload string `json:"nvidia_payload"`
	}
	if err := json.Unmarshal(body, &ar); err != nil {
		fatalf("parse attestation JSON: %v", err)
	}
	if ar.IntelQuote == "" {
		fatal("intel_quote is empty in attestation response")
	}
	return ar.IntelQuote, ar.NvidiaPayload
}

// ---------------------------------------------------------------------------
// TDX / PCS
// ---------------------------------------------------------------------------

func extractFMSPC(hexQuote string) (fmspc, ca string) {
	raw, err := hex.DecodeString(hexQuote)
	if err != nil {
		fatalf("decode intel_quote hex: %v", err)
	}

	quoteAny, err := tdxabi.QuoteToProto(raw)
	if err != nil {
		fatalf("parse TDX quote: %v", err)
	}

	chain, err := tdxverify.ExtractChainFromQuote(quoteAny)
	if err != nil {
		fatalf("extract PCK chain from quote: %v", err)
	}

	ext, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		fatalf("extract PCK extensions: %v", err)
	}

	return ext.FMSPC, "platform"
}

func fetchAndSavePCS(ctx context.Context, client *http.Client, fmspc, ca string) {
	type endpoint struct {
		name       string
		url        string
		bodyFile   string
		headerFile string
		headerKey  string
	}

	endpoints := []endpoint{
		{
			name:       "TCB Info",
			url:        pcs.TcbInfoURL(fmspc),
			bodyFile:   "venice_pcs_tcbinfo.json",
			headerFile: "venice_pcs_tcbinfo_headers.json",
			headerKey:  pcs.TcbInfoIssuerChainPhrase,
		},
		{
			name:       "QE Identity",
			url:        pcs.QeIdentityURL(),
			bodyFile:   "venice_pcs_qeidentity.json",
			headerFile: "venice_pcs_qeidentity_headers.json",
			headerKey:  pcs.SgxQeIdentityIssuerChainPhrase,
		},
		{
			name:       "PCK CRL",
			url:        pcs.PckCrlURL(ca),
			bodyFile:   "venice_pcs_pckcrl.der",
			headerFile: "venice_pcs_pckcrl_headers.json",
			headerKey:  pcs.SgxPckCrlIssuerChainPhrase,
		},
		{
			name:     "Root CRL",
			url:      "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der",
			bodyFile: "venice_pcs_rootcrl.der",
		},
	}

	for _, ep := range endpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.url, http.NoBody)
		if err != nil {
			fatalf("build %s request: %v", ep.name, err)
		}
		res := doRequest(client, req)
		writeFile(ep.bodyFile, res.body)
		fmt.Printf("  %s: %d bytes\n", ep.name, len(res.body))

		if ep.headerFile != "" && ep.headerKey != "" {
			headerVal := res.header.Values(ep.headerKey)
			headerMap := map[string][]string{ep.headerKey: headerVal}
			headerJSON, err := json.MarshalIndent(headerMap, "", "  ")
			if err != nil {
				fatalf("marshal %s headers: %v", ep.name, err)
			}
			writeFile(ep.headerFile, headerJSON)
			fmt.Printf("  %s headers: %s=%d values\n", ep.name, ep.headerKey, len(headerVal))
		}
	}
}

// ---------------------------------------------------------------------------
// PoC
// ---------------------------------------------------------------------------

type pocStage1Response struct {
	MachineID string `json:"machineId"`
	Moniker   string `json:"moniker"`
	Nonce     string `json:"nonce"`
}

type nonceEntry struct {
	peerURL string
	moniker string
	nonce   string
}

// fetchPoCStage1 sends nonce requests to each peer and returns the collected
// nonce entries. Returns nil if a peer returns 403 (not whitelisted), after
// writing stub fixtures for the remaining peers.
func fetchPoCStage1(ctx context.Context, client *http.Client, peers []string, hexQuote string) []nonceEntry {
	nonces := make([]nonceEntry, 0, len(peers))
	for i, peer := range peers {
		u := strings.TrimRight(peer, "/") + "/get_jwt"
		res := doPostJSON(ctx, client, u, map[string]string{"quote": hexQuote})

		writeFile(fmt.Sprintf("venice_poc_stage1_%d.json", i), res.body)
		fmt.Printf("  stage1 peer %d: %d bytes (HTTP %d)\n", i, len(res.body), res.statusCode)

		if res.statusCode == http.StatusForbidden {
			fmt.Println("  PoC peers returned 403 — machine not whitelisted, skipping stage 2")
			for j := i + 1; j < len(peers); j++ {
				writeFile(fmt.Sprintf("venice_poc_stage1_%d.json", j), res.body)
			}
			for j := range peers {
				writeFile(fmt.Sprintf("venice_poc_stage2_%d.json", j), []byte(`{"error":"not whitelisted"}`))
			}
			return nil
		}
		if res.statusCode != http.StatusOK {
			fatalf("PoC stage1 peer %d HTTP %d: %s", i, res.statusCode, truncate(string(res.body)))
		}

		var s1 pocStage1Response
		if err := json.Unmarshal(res.body, &s1); err != nil {
			fatalf("parse PoC stage1 from %s: %v", peer, err)
		}
		if s1.Moniker == "" || s1.Nonce == "" {
			fatalf("PoC stage1 from %s: missing moniker/nonce: %s", peer, string(res.body))
		}
		fmt.Printf("  stage1 peer %d: moniker=%s\n", i, s1.Moniker)
		nonces = append(nonces, nonceEntry{peerURL: peer, moniker: s1.Moniker, nonce: s1.Nonce})
	}
	return nonces
}

// fetchPoCStage2 sends partial-signature requests to each peer, accumulating
// signatures until a final JWT is received.
func fetchPoCStage2(ctx context.Context, client *http.Client, nonces []nonceEntry, hexQuote string) {
	noncesMap := make(map[string]string, len(nonces))
	for _, n := range nonces {
		noncesMap[n.moniker] = n.nonce
	}

	partialSigs := map[string]string{}
	for i, n := range nonces {
		reqBody := map[string]any{
			"quote":  hexQuote,
			"nonces": noncesMap,
		}
		if len(partialSigs) > 0 {
			reqBody["partial_sigs"] = partialSigs
		}

		u := strings.TrimRight(n.peerURL, "/") + "/get_jwt"
		res := doPostJSON(ctx, client, u, reqBody)

		writeFile(fmt.Sprintf("venice_poc_stage2_%d.json", i), res.body)
		fmt.Printf("  stage2 peer %d: %d bytes\n", i, len(res.body))

		if res.statusCode != http.StatusOK {
			fatalf("PoC stage2 peer %d HTTP %d: %s", i, res.statusCode, truncate(string(res.body)))
		}

		var s2 struct {
			JWT string `json:"jwt"`
		}
		if err := json.Unmarshal(res.body, &s2); err == nil && s2.JWT != "" {
			fmt.Printf("  stage2 peer %d: final JWT received (%d chars)\n", i, len(s2.JWT))
			return
		}

		var sigs map[string]string
		if err := json.Unmarshal(res.body, &sigs); err != nil {
			fatalf("parse PoC stage2 partial sigs from %s: %v", n.peerURL, err)
		}
		partialSigs = sigs
		fmt.Printf("  stage2 peer %d: partial sig collected\n", i)
	}
}

func fetchPoC(ctx context.Context, client *http.Client, hexQuote string) {
	peers := attestation.PoCPeers
	nonces := fetchPoCStage1(ctx, client, peers, hexQuote)
	if nonces == nil {
		return
	}
	fetchPoCStage2(ctx, client, nonces, hexQuote)
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

func writeFile(name string, data []byte) {
	path := filepath.Join(outDir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		fatalf("write %s: %v", path, err)
	}
}

func truncate(s string) string {
	const maxLen = 500
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func fatal(args ...any) {
	fmt.Fprintln(os.Stderr, args...)
	os.Exit(1)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
