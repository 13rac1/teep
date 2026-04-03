// capture_nanogpt fetches attestation responses from all NanoGPT TEE models
// and saves the raw JSON to fixture files for analysis and testing.
//
// It saves everything to internal/integration/testdata/nanogpt_YYYYMMDD_HHMMSS/.
//
// Usage:
//
//	NANOGPT_API_KEY=... go run ./cmd/capture_nanogpt
//
// Requires NANOGPT_API_KEY. Run manually when fixtures need refreshing.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/13rac1/teep/internal/tlsct"
)

const (
	baseURL         = "https://nano-gpt.com/api"
	modelsPath      = "/v1/models"
	attestationPath = "/v1/tee/attestation"
	teeModelPrefix  = "TEE/"
	testdataDir     = "internal/integration/testdata"
	httpTimeout     = 60 * time.Second
)

var outDir string

func main() {
	apiKey := os.Getenv("NANOGPT_API_KEY")
	if apiKey == "" {
		fatal("NANOGPT_API_KEY not set")
	}

	captureTime := time.Now().UTC()
	saveDir := filepath.Join(testdataDir, captureTime.Format("nanogpt_20060102_150405"))
	if err := os.MkdirAll(saveDir, 0o750); err != nil {
		fatalf("mkdir %s: %v", saveDir, err)
	}
	outDir = saveDir
	fmt.Printf("save directory: %s\n", saveDir)
	fmt.Printf("capture time:   %s\n", captureTime.Format(time.RFC3339))

	ctx := context.Background()
	client := tlsct.NewHTTPClient(httpTimeout)

	// 1. Fetch model list.
	fmt.Println("\n--- fetching model list ---")
	models := fetchModels(ctx, client, apiKey)

	var teeModels []string
	for _, m := range models {
		if strings.HasPrefix(m, teeModelPrefix) {
			teeModels = append(teeModels, m)
		}
	}
	sort.Strings(teeModels)
	fmt.Printf("found %d TEE models (of %d total)\n", len(teeModels), len(models))

	if len(teeModels) == 0 {
		fatal("no TEE models found")
	}

	// Save model list.
	modelsJSON, err := json.MarshalIndent(teeModels, "", "  ")
	if err != nil {
		fatalf("marshal models: %v", err)
	}
	writeFile("models.json", modelsJSON)

	// 2. Fetch attestation for each TEE model.
	fmt.Println("\n--- fetching attestations ---")
	fmt.Printf("%-45s %-12s %-8s %s\n", "MODEL", "FORMAT", "STATUS", "SIZE")
	fmt.Printf("%-45s %-12s %-8s %s\n",
		strings.Repeat("-", 45),
		strings.Repeat("-", 12),
		strings.Repeat("-", 8),
		strings.Repeat("-", 10))

	var ok, skip int
	for _, model := range teeModels {
		slug := modelSlug(model)
		nonce := randomHexNonce()

		res, err := fetchAttestation(ctx, client, apiKey, model, nonce)
		if err != nil {
			fmt.Printf("%-45s %-12s %-8s %v\n", model, "", "ERROR", err)
			skip++
			continue
		}

		writeFile(slug+"_attestation.json", res.body)
		writeFile(slug+"_nonce.txt", []byte(nonce+"\n"))

		headersJSON, err := json.MarshalIndent(res.headers, "", "  ")
		if err != nil {
			fatalf("marshal headers for %s: %v", model, err)
		}
		writeFile(slug+"_headers.json", headersJSON)

		format := detectFormat(res.body)
		fmt.Printf("%-45s %-12s %-8s %d bytes\n", model, format, "ok", len(res.body))
		ok++

		time.Sleep(500 * time.Millisecond)
	}

	// 3. Summary.
	fmt.Printf("\n--- done ---\n")
	fmt.Printf("captured: %d, skipped: %d\n", ok, skip)
	fmt.Printf("fixtures saved to %s/\n", saveDir)
}

// ---------------------------------------------------------------------------
// Model list
// ---------------------------------------------------------------------------

func fetchModels(ctx context.Context, client *http.Client, apiKey string) []string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+modelsPath, http.NoBody)
	if err != nil {
		fatalf("build models request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	fmt.Printf("  > GET %s\n", req.URL)
	resp, err := client.Do(req)
	if err != nil {
		fatalf("GET %s: %v", req.URL, err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err != nil {
		fatalf("read models response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		fatalf("models endpoint HTTP %d: %s", resp.StatusCode, truncate(string(body)))
	}
	fmt.Printf("  models response: %d bytes\n", len(body))

	var openAIResp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &openAIResp); err != nil {
		fatalf("parse models response: %v", err)
	}
	ids := make([]string, len(openAIResp.Data))
	for i, m := range openAIResp.Data {
		ids[i] = m.ID
	}
	return ids
}

// ---------------------------------------------------------------------------
// Attestation
// ---------------------------------------------------------------------------

type attestationResult struct {
	body    []byte
	headers http.Header
}

func fetchAttestation(ctx context.Context, client *http.Client, apiKey, model, nonce string) (*attestationResult, error) {
	endpoint, err := url.Parse(baseURL + attestationPath)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}
	q := endpoint.Query()
	q.Set("model", model)
	q.Set("nonce", nonce)
	endpoint.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body)))
	}

	return &attestationResult{body: body, headers: resp.Header}, nil
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------

func detectFormat(body []byte) string {
	var obj map[string]json.RawMessage
	if json.Unmarshal(body, &obj) != nil {
		return "invalid-json"
	}

	if _, ok := obj["format"]; ok {
		var fmtStr string
		if json.Unmarshal(obj["format"], &fmtStr) == nil {
			if strings.Contains(fmtStr, "/v2") {
				return "tinfoil-v2"
			}
			return "tinfoil"
		}
		return "tinfoil-?"
	}

	if _, ok := obj["intel_quote"]; ok {
		return "dstack"
	}

	if _, ok := obj["gateway_attestation"]; ok {
		return "gateway"
	}

	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return "unknown(" + strings.Join(keys, ",") + ")"
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

func modelSlug(model string) string {
	s := strings.TrimPrefix(model, teeModelPrefix)
	return strings.ReplaceAll(s, "/", "-")
}

func randomHexNonce() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		fatalf("generate nonce: %v", err)
	}
	return hex.EncodeToString(b)
}

func writeFile(name string, data []byte) {
	path := filepath.Join(outDir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		fatalf("write %s: %v", path, err)
	}
}

func truncate(s string) string {
	const maxLen = 200
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
