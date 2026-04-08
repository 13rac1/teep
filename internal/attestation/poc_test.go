package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// makePoCJWT returns a minimal structurally-valid JWT whose payload contains
// the given machineID and an exp far in the future.
func makePoCJWT(machineID string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA"}`))
	payload := base64.RawURLEncoding.EncodeToString(
		fmt.Appendf(nil, `{"exp":9999999999,"machine_id":%q}`, machineID),
	)
	return header + "." + payload + ".fakesig"
}

// TestCheckQuoteMultisigFullFlow exercises the complete 3-peer multisig flow:
// Stage 1: collect nonces from 3 peers, Stage 2: chain partial sigs, final JWT.
func TestCheckQuoteMultisigFullFlow(t *testing.T) {
	hexQuote := "aabbccdd"

	// Track calls per peer to serve correct stage responses.
	var peerCalls [3]atomic.Int32

	monikers := []string{"alice", "bob", "carol"}
	nonces := []string{"nonce_alice", "nonce_bob", "nonce_carol"}
	testJWT := makePoCJWT("deadbeef")

	makePeer := func(idx int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}

			call := peerCalls[idx].Add(1)

			// Call 1 = stage 1 (nonce request), Call 2 = stage 2 (signing).
			if call == 1 {
				// Stage 1: return nonce.
				json.NewEncoder(w).Encode(map[string]string{
					"machineId": "deadbeef",
					"moniker":   monikers[idx],
					"nonce":     nonces[idx],
				})
				return
			}

			// Stage 2: signing.
			if idx < 2 {
				// Non-final signers return partial sigs.
				sigs := map[string]string{}
				for j := 0; j <= idx; j++ {
					sigs[monikers[j]] = "partialsig_" + monikers[j]
				}
				json.NewEncoder(w).Encode(sigs)
			} else {
				// Final signer returns the JWT.
				json.NewEncoder(w).Encode(map[string]string{
					"machineId": "deadbeef",
					"label":     "test-machine",
					"jwt":       testJWT,
				})
			}
		}))
	}

	servers := make([]*httptest.Server, 3)
	peers := make([]string, 3)
	for i := range 3 {
		servers[i] = makePeer(i)
		peers[i] = servers[i].URL
	}
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()

	poc := NewPoCClient(peers, PoCQuorum, &http.Client{})
	result := poc.CheckQuote(context.Background(), hexQuote)

	if result.Err != nil {
		t.Fatalf("CheckQuote: unexpected error: %v", result.Err)
	}
	if !result.Registered {
		t.Error("expected Registered=true")
	}
	if result.MachineID != "deadbeef" {
		t.Errorf("MachineID: got %q, want %q", result.MachineID, "deadbeef")
	}
	if result.Label != "test-machine" {
		t.Errorf("Label: got %q, want %q", result.Label, "test-machine")
	}
	if result.JWT != testJWT {
		t.Errorf("JWT: got %q, want %q", result.JWT, testJWT)
	}
}

// TestCheckQuote_DeterministicStage2Order verifies that stage 2 visits peers
// in sorted URL order regardless of goroutine scheduling in stage 1. Without
// this invariant, capture/replay round-tripping breaks because stage 2 POST
// bodies (which include partial_sigs from prior peers) differ across runs.
func TestCheckQuote_DeterministicStage2Order(t *testing.T) {
	hexQuote := "aabbccdd"
	monikers := []string{"alice", "bob", "carol"}
	nonceVals := []string{"nonce_alice", "nonce_bob", "nonce_carol"}

	// stage2Order records the URL of each peer as it receives its stage 2 POST.
	var mu sync.Mutex
	var stage2Order []string

	// finalIdx is the creation index of the peer that should return the final
	// JWT. Set after all servers are created (once we know sorted URL order).
	var finalIdx atomic.Int32

	makePeer := func(idx int) *httptest.Server {
		var calls atomic.Int32
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}

			call := calls.Add(1)
			if call == 1 {
				// Stage 1: return nonce.
				json.NewEncoder(w).Encode(map[string]string{
					"machineId": "deadbeef",
					"moniker":   monikers[idx],
					"nonce":     nonceVals[idx],
				})
				return
			}

			// Stage 2: record visit order.
			mu.Lock()
			stage2Order = append(stage2Order, r.Host)
			mu.Unlock()

			// Last peer in sorted URL order returns JWT; others return partial sigs.
			if int32(idx) == finalIdx.Load() {
				json.NewEncoder(w).Encode(map[string]string{
					"machineId": "deadbeef",
					"label":     "test-machine",
					"jwt":       makePoCJWT("deadbeef"),
				})
			} else {
				json.NewEncoder(w).Encode(map[string]string{
					monikers[idx]: "partialsig_" + monikers[idx],
				})
			}
		}))
	}

	servers := make([]*httptest.Server, 3)
	peers := make([]string, 3)
	for i := range 3 {
		servers[i] = makePeer(i)
		peers[i] = servers[i].URL
	}
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()

	// Determine which idx is last in sorted URL order. httptest.NewServer
	// assigns random ports, so we can't assume idx 2 is last.
	type urlIdx struct {
		url string
		idx int
	}
	sortedByURL := make([]urlIdx, len(peers))
	for i, p := range peers {
		sortedByURL[i] = urlIdx{url: p, idx: i}
	}
	sort.Slice(sortedByURL, func(i, j int) bool {
		return sortedByURL[i].url < sortedByURL[j].url
	})
	finalIdx.Store(int32(sortedByURL[len(sortedByURL)-1].idx))

	expectedHosts := make([]string, len(sortedByURL))
	for i, s := range sortedByURL {
		expectedHosts[i] = strings.TrimPrefix(s.url, "http://")
	}

	poc := NewPoCClient(peers, PoCQuorum, &http.Client{})
	result := poc.CheckQuote(context.Background(), hexQuote)

	if result.Err != nil {
		t.Fatalf("CheckQuote: %v", result.Err)
	}

	// Verify stage 2 visit order matches sorted peer URLs.
	if len(stage2Order) != len(expectedHosts) {
		t.Fatalf("stage 2 visited %d peers, want %d", len(stage2Order), len(expectedHosts))
	}
	for i := range stage2Order {
		if stage2Order[i] != expectedHosts[i] {
			t.Errorf("stage 2 visit[%d]: got %s, want %s", i, stage2Order[i], expectedHosts[i])
		}
	}
	t.Logf("stage 2 order: %v", stage2Order)
}

// TestCheckQuoteNotWhitelisted verifies 403 handling.
func TestCheckQuoteNotWhitelisted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Machine is not whitelisted."})
	}))
	defer server.Close()

	poc := NewPoCClient([]string{server.URL}, 1, &http.Client{})
	result := poc.CheckQuote(context.Background(), "aabbccdd")

	if result.Err != nil {
		t.Fatalf("expected no error for 403, got: %v", result.Err)
	}
	if result.Registered {
		t.Error("expected Registered=false for 403")
	}
}

// TestCheckQuoteNetworkError verifies network error handling.
func TestCheckQuoteNetworkError(t *testing.T) {
	poc := NewPoCClient([]string{"http://127.0.0.1:1"}, 1, &http.Client{})
	result := poc.CheckQuote(context.Background(), "aabbccdd")

	if result.Err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

// TestPoCPeers verifies the hardcoded peer list meets quorum requirements.
func TestPoCPeers(t *testing.T) {
	if len(PoCPeers) < PoCQuorum {
		t.Errorf("PoCPeers has %d entries, need at least %d for quorum", len(PoCPeers), PoCQuorum)
	}
	for _, p := range PoCPeers {
		if !strings.HasPrefix(p, "https://") {
			t.Errorf("peer %q does not use HTTPS", p)
		}
		if strings.HasSuffix(p, "/") {
			t.Errorf("peer %q has trailing slash", p)
		}
	}
}

// --------------------------------------------------------------------------
// verifyPoCJWTClaims tests
// --------------------------------------------------------------------------

// buildTestJWT constructs a minimal JWT (unsigned) with the given claims payload.
func buildTestJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sig := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	return header + "." + payloadB64 + "." + sig
}

func TestVerifyPoCJWTClaims_Valid(t *testing.T) {
	token := buildTestJWT(t, map[string]any{
		"exp":        time.Now().Add(time.Hour).Unix(),
		"machine_id": "deadbeef",
	})
	err := verifyPoCJWTClaims(context.Background(), token, "deadbeef")
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestVerifyPoCJWTClaims_ValidNoMachineIDCheck(t *testing.T) {
	token := buildTestJWT(t, map[string]any{
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	// Empty expected machineID skips the check.
	err := verifyPoCJWTClaims(context.Background(), token, "")
	if err != nil {
		t.Errorf("expected no error with empty machineID, got: %v", err)
	}
}

func TestVerifyPoCJWTClaims_Expired(t *testing.T) {
	token := buildTestJWT(t, map[string]any{
		"exp":        time.Now().Add(-time.Hour).Unix(),
		"machine_id": "deadbeef",
	})
	err := verifyPoCJWTClaims(context.Background(), token, "deadbeef")
	if err == nil {
		t.Fatal("expected error for expired JWT")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should mention expired: %v", err)
	}
}

func TestVerifyPoCJWTClaims_ExpZero(t *testing.T) {
	// exp: 0 (Unix epoch 1970) must be treated as expired, not as "missing".
	token := buildTestJWT(t, map[string]any{
		"exp":        0,
		"machine_id": "deadbeef",
	})
	err := verifyPoCJWTClaims(context.Background(), token, "deadbeef")
	if err == nil {
		t.Fatal("expected error for exp=0 (Unix epoch), got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should mention expired: %v", err)
	}
}

func TestVerifyPoCJWTClaims_MissingExp(t *testing.T) {
	token := buildTestJWT(t, map[string]any{
		"machine_id": "deadbeef",
	})
	// Missing exp is accepted with a warning (PoC JWTs don't include exp yet).
	err := verifyPoCJWTClaims(context.Background(), token, "deadbeef")
	if err != nil {
		t.Errorf("expected no error for missing exp (warn-only), got: %v", err)
	}
}

func TestVerifyPoCJWTClaims_MachineIDMismatch(t *testing.T) {
	token := buildTestJWT(t, map[string]any{
		"exp":        time.Now().Add(time.Hour).Unix(),
		"machine_id": "aaaaaaaa",
	})
	err := verifyPoCJWTClaims(context.Background(), token, "bbbbbbbb")
	if err == nil {
		t.Fatal("expected error for machine_id mismatch")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error should mention mismatch: %v", err)
	}
}

func TestVerifyPoCJWTClaims_MissingMachineID(t *testing.T) {
	token := buildTestJWT(t, map[string]any{
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	err := verifyPoCJWTClaims(context.Background(), token, "expected-id")
	if err == nil {
		t.Fatal("expected error for missing machine_id")
	}
	if !strings.Contains(err.Error(), "missing machine_id") {
		t.Errorf("error should mention missing machine_id: %v", err)
	}
}

func TestVerifyPoCJWTClaims_MalformedJWT(t *testing.T) {
	err := verifyPoCJWTClaims(context.Background(), "not.a.valid.jwt.token", "")
	if err == nil {
		t.Fatal("expected error for malformed JWT")
	}
	if !strings.Contains(err.Error(), "malformed") {
		t.Errorf("error should mention malformed: %v", err)
	}
}

func TestVerifyPoCJWTClaims_BadBase64(t *testing.T) {
	err := verifyPoCJWTClaims(context.Background(), "header.!!!invalid!!!.sig", "")
	if err == nil {
		t.Fatal("expected error for bad base64")
	}
}

func TestVerifyPoCJWTClaims_BadJSON(t *testing.T) {
	badPayload := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	err := verifyPoCJWTClaims(context.Background(), "header."+badPayload+".sig", "")
	if err == nil {
		t.Fatal("expected error for bad JSON payload")
	}
}

// TestBuildReportWithPoCRegistered verifies cpu_id_registry Pass with PoC result.
func TestBuildReportWithPoCRegistered(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	pocResult := &PoCResult{Registered: true, Label: "test-machine"}

	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, PoC: pocResult, AllowFail: DefaultAllowFail})
	f := findFactor(t, report, "cpu_id_registry")
	if f.Status != Pass {
		t.Errorf("cpu_id_registry with PoC registered: got %s, want PASS; detail: %s", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "test-machine") {
		t.Errorf("detail should contain label: %s", f.Detail)
	}
}

// TestBuildReportWithPoCNotRegistered verifies cpu_id_registry Fail.
func TestBuildReportWithPoCNotRegistered(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	pocResult := &PoCResult{Registered: false}

	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, PoC: pocResult, AllowFail: DefaultAllowFail})
	f := findFactor(t, report, "cpu_id_registry")
	if f.Status != Fail {
		t.Errorf("cpu_id_registry with PoC not registered: got %s, want FAIL", f.Status)
	}
}

// TestBuildReportWithPoCError verifies cpu_id_registry Skip on error.
func TestBuildReportWithPoCError(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	pocResult := &PoCResult{Err: http.ErrHandlerTimeout}

	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, PoC: pocResult, AllowFail: DefaultAllowFail})
	f := findFactor(t, report, "cpu_id_registry")
	if f.Status != Skip {
		t.Errorf("cpu_id_registry with PoC error: got %s, want SKIP", f.Status)
	}
}

// TestBuildReportWithPPIDOffline verifies cpu_id_registry Skip with PPID.
func TestBuildReportWithPPIDOffline(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	tdxResult := &TDXVerifyResult{
		PPID:      "aabbccddee112233aabbccddee112233",
		TeeTCBSVN: make([]byte, 16),
	}

	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, TDX: tdxResult, AllowFail: DefaultAllowFail})
	f := findFactor(t, report, "cpu_id_registry")
	if f.Status != Skip {
		t.Errorf("cpu_id_registry with PPID offline: got %s, want SKIP", f.Status)
	}
	if !strings.Contains(f.Detail, "aabbccdd") {
		t.Errorf("detail should contain PPID prefix: %s", f.Detail)
	}
}
