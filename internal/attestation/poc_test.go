package attestation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

// testHexQuote is the canonical hex-encoded quote used by unit tests.
const testHexQuote = "aabbccdd"

// testQuoteHash returns the PoC-protocol quote_hash for a hex-encoded quote:
// hex(sha256(hex.DecodeString(hexQuote))).
func testQuoteHash(hexQuote string) string {
	b, err := hex.DecodeString(hexQuote)
	if err != nil {
		panic(fmt.Sprintf("testQuoteHash: invalid hex %q: %v", hexQuote, err))
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// makePoCJWT returns a minimal structurally-valid JWT whose payload contains
// the given machineID, label, quote_hash, timestamp, and an exp far in the future.
func makePoCJWT(machineID, label, hexQuote string) string {
	claims := map[string]any{
		"exp":        int64(9999999999),
		"machine_id": machineID,
		"label":      label,
		"quote_hash": testQuoteHash(hexQuote),
		"timestamp":  time.Now().Unix(),
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		panic(fmt.Sprintf("makePoCJWT: marshal: %v", err))
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA"}`))
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
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
	testJWT := makePoCJWT("deadbeef", "test-machine", hexQuote)

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
				// Final signer returns the JWT with consistent wrapper values.
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
					"jwt":       makePoCJWT("deadbeef", "test-machine", hexQuote),
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
		"quote_hash": testQuoteHash(testHexQuote),
		"timestamp":  time.Now().Unix(),
	})
	_, err := verifyPoCJWTClaims(context.Background(), token, testHexQuote, "deadbeef")
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestVerifyPoCJWTClaims_ValidNoMachineIDCheck(t *testing.T) {
	token := buildTestJWT(t, map[string]any{
		"exp":        time.Now().Add(time.Hour).Unix(),
		"quote_hash": testQuoteHash(testHexQuote),
		"timestamp":  time.Now().Unix(),
	})
	// Empty expected machineID skips the check.
	_, err := verifyPoCJWTClaims(context.Background(), token, testHexQuote, "")
	if err != nil {
		t.Errorf("expected no error with empty machineID, got: %v", err)
	}
}

func TestVerifyPoCJWTClaims_Expired(t *testing.T) {
	token := buildTestJWT(t, map[string]any{
		"exp":        time.Now().Add(-time.Hour).Unix(),
		"machine_id": "deadbeef",
		"quote_hash": testQuoteHash(testHexQuote),
		"timestamp":  time.Now().Unix(),
	})
	_, err := verifyPoCJWTClaims(context.Background(), token, testHexQuote, "deadbeef")
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
		"quote_hash": testQuoteHash(testHexQuote),
		"timestamp":  time.Now().Unix(),
	})
	_, err := verifyPoCJWTClaims(context.Background(), token, testHexQuote, "deadbeef")
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
		"quote_hash": testQuoteHash(testHexQuote),
		"timestamp":  time.Now().Unix(),
	})
	// Missing exp is accepted with a warning (PoC JWTs don't include exp yet).
	_, err := verifyPoCJWTClaims(context.Background(), token, testHexQuote, "deadbeef")
	if err != nil {
		t.Errorf("expected no error for missing exp (warn-only), got: %v", err)
	}
}

func TestVerifyPoCJWTClaims_MachineIDMismatch(t *testing.T) {
	token := buildTestJWT(t, map[string]any{
		"exp":        time.Now().Add(time.Hour).Unix(),
		"machine_id": "aaaaaaaa",
		"quote_hash": testQuoteHash(testHexQuote),
		"timestamp":  time.Now().Unix(),
	})
	_, err := verifyPoCJWTClaims(context.Background(), token, testHexQuote, "bbbbbbbb")
	if err == nil {
		t.Fatal("expected error for machine_id mismatch")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error should mention mismatch: %v", err)
	}
}

func TestVerifyPoCJWTClaims_MissingMachineID(t *testing.T) {
	token := buildTestJWT(t, map[string]any{
		"exp":        time.Now().Add(time.Hour).Unix(),
		"quote_hash": testQuoteHash(testHexQuote),
		"timestamp":  time.Now().Unix(),
	})
	_, err := verifyPoCJWTClaims(context.Background(), token, testHexQuote, "expected-id")
	if err == nil {
		t.Fatal("expected error for missing machine_id")
	}
	if !strings.Contains(err.Error(), "missing machine_id") {
		t.Errorf("error should mention missing machine_id: %v", err)
	}
}

func TestVerifyPoCJWTClaims_MalformedJWT(t *testing.T) {
	_, err := verifyPoCJWTClaims(context.Background(), "not.a.valid.jwt.token", testHexQuote, "")
	if err == nil {
		t.Fatal("expected error for malformed JWT")
	}
	if !strings.Contains(err.Error(), "malformed") {
		t.Errorf("error should mention malformed: %v", err)
	}
}

func TestVerifyPoCJWTClaims_BadBase64(t *testing.T) {
	_, err := verifyPoCJWTClaims(context.Background(), "header.!!!invalid!!!.sig", testHexQuote, "")
	if err == nil {
		t.Fatal("expected error for bad base64")
	}
}

func TestVerifyPoCJWTClaims_BadJSON(t *testing.T) {
	badPayload := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	_, err := verifyPoCJWTClaims(context.Background(), "header."+badPayload+".sig", testHexQuote, "")
	if err == nil {
		t.Fatal("expected error for bad JSON payload")
	}
}

// --------------------------------------------------------------------------
// Regression tests for audit findings (AGENTS.md: one test per finding)
// --------------------------------------------------------------------------

func TestVerifyPoCJWTClaims_QuoteHashAbsent(t *testing.T) {
	token := buildTestJWT(t, map[string]any{
		"exp":        time.Now().Add(time.Hour).Unix(),
		"machine_id": "deadbeef",
		"timestamp":  time.Now().Unix(),
		// no "quote_hash"
	})
	_, err := verifyPoCJWTClaims(context.Background(), token, testHexQuote, "deadbeef")
	if err == nil {
		t.Fatal("expected error for absent quote_hash")
	}
	if !strings.Contains(err.Error(), "quote_hash") {
		t.Errorf("error should mention quote_hash: %v", err)
	}
}

func TestVerifyPoCJWTClaims_QuoteHashMismatch(t *testing.T) {
	token := buildTestJWT(t, map[string]any{
		"exp":        time.Now().Add(time.Hour).Unix(),
		"machine_id": "deadbeef",
		"quote_hash": testQuoteHash("ffffffff"), // hash of a different quote
		"timestamp":  time.Now().Unix(),
	})
	_, err := verifyPoCJWTClaims(context.Background(), token, testHexQuote, "deadbeef")
	if err == nil {
		t.Fatal("expected error for quote_hash mismatch")
	}
	if !strings.Contains(err.Error(), "quote_hash") {
		t.Errorf("error should mention quote_hash: %v", err)
	}
}

func TestVerifyPoCJWTClaims_TimestampAbsent(t *testing.T) {
	token := buildTestJWT(t, map[string]any{
		"exp":        time.Now().Add(time.Hour).Unix(),
		"machine_id": "deadbeef",
		"quote_hash": testQuoteHash(testHexQuote),
		// no "timestamp"
	})
	_, err := verifyPoCJWTClaims(context.Background(), token, testHexQuote, "deadbeef")
	if err == nil {
		t.Fatal("expected error for absent timestamp")
	}
	if !strings.Contains(err.Error(), "timestamp") {
		t.Errorf("error should mention timestamp: %v", err)
	}
}

func TestVerifyPoCJWTClaims_TimestampStale(t *testing.T) {
	stale := time.Now().Add(-11 * time.Minute).Unix()
	token := buildTestJWT(t, map[string]any{
		"exp":        time.Now().Add(time.Hour).Unix(),
		"machine_id": "deadbeef",
		"quote_hash": testQuoteHash(testHexQuote),
		"timestamp":  stale,
	})
	_, err := verifyPoCJWTClaims(context.Background(), token, testHexQuote, "deadbeef")
	if err == nil {
		t.Fatal("expected error for stale timestamp")
	}
	if !strings.Contains(err.Error(), "timestamp") {
		t.Errorf("error should mention timestamp: %v", err)
	}
}

func TestVerifyPoCJWTClaims_TimestampFuture(t *testing.T) {
	future := time.Now().Add(11 * time.Minute).Unix()
	token := buildTestJWT(t, map[string]any{
		"exp":        time.Now().Add(time.Hour).Unix(),
		"machine_id": "deadbeef",
		"quote_hash": testQuoteHash(testHexQuote),
		"timestamp":  future,
	})
	_, err := verifyPoCJWTClaims(context.Background(), token, testHexQuote, "deadbeef")
	if err == nil {
		t.Fatal("expected error for future timestamp")
	}
	if !strings.Contains(err.Error(), "timestamp") {
		t.Errorf("error should mention timestamp: %v", err)
	}
}

func TestVerifyPoCJWTClaims_TimestampJustInsideBoundary(t *testing.T) {
	// Timestamp exactly at the boundary (10min ago) is within the window (exclusive).
	ts := time.Now().Add(-10*time.Minute + time.Second).Unix()
	token := buildTestJWT(t, map[string]any{
		"exp":        time.Now().Add(time.Hour).Unix(),
		"machine_id": "deadbeef",
		"quote_hash": testQuoteHash(testHexQuote),
		"timestamp":  ts,
	})
	_, err := verifyPoCJWTClaims(context.Background(), token, testHexQuote, "deadbeef")
	if err != nil {
		t.Errorf("timestamp just inside boundary should pass: %v", err)
	}
}

func TestVerifyPoCJWTClaims_TimestampJustOutsideBoundary(t *testing.T) {
	// Timestamp one second beyond the window must be rejected.
	ts := time.Now().Add(-10*time.Minute - time.Second).Unix()
	token := buildTestJWT(t, map[string]any{
		"exp":        time.Now().Add(time.Hour).Unix(),
		"machine_id": "deadbeef",
		"quote_hash": testQuoteHash(testHexQuote),
		"timestamp":  ts,
	})
	_, err := verifyPoCJWTClaims(context.Background(), token, testHexQuote, "deadbeef")
	if err == nil {
		t.Fatal("expected error for timestamp just outside boundary")
	}
	if !strings.Contains(err.Error(), "timestamp") {
		t.Errorf("error should mention timestamp: %v", err)
	}
}

func TestVerifyPoCJWTClaims_EmptyHexQuote(t *testing.T) {
	// An empty hexQuote is a valid (if unusual) input: sha256 of empty bytes
	// must match quote_hash for the token to be accepted.
	emptyHash := testQuoteHash("")
	token := buildTestJWT(t, map[string]any{
		"exp":        time.Now().Add(time.Hour).Unix(),
		"machine_id": "deadbeef",
		"quote_hash": emptyHash,
		"timestamp":  time.Now().Unix(),
	})
	_, err := verifyPoCJWTClaims(context.Background(), token, "", "deadbeef")
	if err != nil {
		t.Errorf("empty hexQuote with matching hash should pass: %v", err)
	}
}

func TestVerifyPoCJWTClaims_UnknownField(t *testing.T) {
	// Unknown fields must produce a warning but NOT an error (jsonstrict warns, not rejects).
	token := buildTestJWT(t, map[string]any{
		"exp":           time.Now().Add(time.Hour).Unix(),
		"machine_id":    "deadbeef",
		"quote_hash":    testQuoteHash(testHexQuote),
		"timestamp":     time.Now().Unix(),
		"extra_unknown": "future-field",
	})
	_, err := verifyPoCJWTClaims(context.Background(), token, testHexQuote, "deadbeef")
	if err != nil {
		t.Errorf("unknown fields should not cause an error (jsonstrict warns only), got: %v", err)
	}
}

func TestCheckQuote_CrossPeerMachineIDMismatch(t *testing.T) {
	machineIDs := []string{"machine-aaa", "machine-bbb"}
	servers := make([]*httptest.Server, 2)
	for i := range 2 {
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{
				"machineId": machineIDs[i],
				"moniker":   fmt.Sprintf("peer%d", i),
				"nonce":     fmt.Sprintf("nonce%d", i),
			})
		}))
	}
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()

	poc := NewPoCClient([]string{servers[0].URL, servers[1].URL}, 2, &http.Client{})
	result := poc.CheckQuote(context.Background(), testHexQuote)

	if result.Err == nil {
		t.Fatal("expected error for cross-peer machineId mismatch")
	}
	if !strings.Contains(result.Err.Error(), "machineId") {
		t.Errorf("error should mention machineId: %v", result.Err)
	}
}

func TestCheckQuote_CrossPeerMachineIDEmpty(t *testing.T) {
	servers := []*httptest.Server{
		httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{
				"machineId": "machine-aaa",
				"moniker":   "peer0",
				"nonce":     "nonce0",
			})
		})),
		httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{
				"machineId": "", // empty
				"moniker":   "peer1",
				"nonce":     "nonce1",
			})
		})),
	}
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()

	poc := NewPoCClient([]string{servers[0].URL, servers[1].URL}, 2, &http.Client{})
	result := poc.CheckQuote(context.Background(), testHexQuote)

	if result.Err == nil {
		t.Fatal("expected error for empty machineId from stage-1 peer")
	}
	if !strings.Contains(result.Err.Error(), "machineId") {
		t.Errorf("error should mention machineId: %v", result.Err)
	}
}

func TestCheckQuote_ResultFromJWT(t *testing.T) {
	// Verifies that PoCResult.MachineID and PoCResult.Label come from the
	// validated JWT payload, not from the stage-2 response wrapper.
	hexQuote := testHexQuote
	jwtMachineID := "from-jwt-id"
	jwtLabel := "from-jwt-label"

	testJWT := buildTestJWT(t, map[string]any{
		"exp":        int64(9999999999),
		"machine_id": jwtMachineID,
		"quote_hash": testQuoteHash(hexQuote),
		"label":      jwtLabel,
		"timestamp":  time.Now().Unix(),
	})

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		if call == 1 {
			json.NewEncoder(w).Encode(map[string]string{
				"machineId": jwtMachineID,
				"moniker":   "alice",
				"nonce":     "nonce1",
			})
			return
		}
		// Final signer: wrapper values match JWT (required by cross-check).
		json.NewEncoder(w).Encode(map[string]string{
			"machineId": jwtMachineID,
			"label":     jwtLabel,
			"jwt":       testJWT,
		})
	}))
	defer server.Close()

	poc := NewPoCClient([]string{server.URL}, 1, &http.Client{})
	result := poc.CheckQuote(context.Background(), hexQuote)

	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if result.MachineID != jwtMachineID {
		t.Errorf("MachineID: got %q, want %q (from JWT, not wrapper)", result.MachineID, jwtMachineID)
	}
	if result.Label != jwtLabel {
		t.Errorf("Label: got %q, want %q (from JWT, not wrapper)", result.Label, jwtLabel)
	}
}

func TestCheckQuote_Stage2WrapperMachineIDMismatch(t *testing.T) {
	// Verifies that a wrapper machineId disagreeing with the JWT claim is rejected.
	hexQuote := testHexQuote
	jwtMachineID := "from-jwt-id"
	testJWT := buildTestJWT(t, map[string]any{
		"exp":        int64(9999999999),
		"machine_id": jwtMachineID,
		"quote_hash": testQuoteHash(hexQuote),
		"label":      "some-label",
		"timestamp":  time.Now().Unix(),
	})

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		if call == 1 {
			json.NewEncoder(w).Encode(map[string]string{
				"machineId": jwtMachineID,
				"moniker":   "alice",
				"nonce":     "nonce1",
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"machineId": "different-machine", // disagrees with JWT
			"label":     "some-label",
			"jwt":       testJWT,
		})
	}))
	defer server.Close()

	poc := NewPoCClient([]string{server.URL}, 1, &http.Client{})
	result := poc.CheckQuote(context.Background(), hexQuote)

	if result.Err == nil {
		t.Fatal("expected error for wrapper machineId mismatch")
	}
	if !strings.Contains(result.Err.Error(), "machineId") {
		t.Errorf("error should mention machineId: %v", result.Err)
	}
}

func TestCheckQuote_Stage2WrapperLabelMismatch(t *testing.T) {
	// Verifies that a wrapper label disagreeing with the JWT claim is rejected.
	hexQuote := testHexQuote
	jwtMachineID := "from-jwt-id"
	testJWT := buildTestJWT(t, map[string]any{
		"exp":        int64(9999999999),
		"machine_id": jwtMachineID,
		"quote_hash": testQuoteHash(hexQuote),
		"label":      "jwt-label",
		"timestamp":  time.Now().Unix(),
	})

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		if call == 1 {
			json.NewEncoder(w).Encode(map[string]string{
				"machineId": jwtMachineID,
				"moniker":   "alice",
				"nonce":     "nonce1",
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"machineId": jwtMachineID,
			"label":     "different-label", // disagrees with JWT
			"jwt":       testJWT,
		})
	}))
	defer server.Close()

	poc := NewPoCClient([]string{server.URL}, 1, &http.Client{})
	result := poc.CheckQuote(context.Background(), hexQuote)

	if result.Err == nil {
		t.Fatal("expected error for wrapper label mismatch")
	}
	if !strings.Contains(result.Err.Error(), "label") {
		t.Errorf("error should mention label: %v", result.Err)
	}
}

func TestCheckQuote_MonikerCollision(t *testing.T) {
	// Verifies that two stage-1 peers returning the same moniker is rejected.
	servers := []*httptest.Server{
		httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{
				"machineId": "machine-aaa",
				"moniker":   "alice", // same moniker as peer 1
				"nonce":     "nonce0",
			})
		})),
		httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{
				"machineId": "machine-aaa",
				"moniker":   "alice", // duplicate
				"nonce":     "nonce1",
			})
		})),
	}
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()

	poc := NewPoCClient([]string{servers[0].URL, servers[1].URL}, 2, &http.Client{})
	result := poc.CheckQuote(context.Background(), testHexQuote)

	if result.Err == nil {
		t.Fatal("expected error for duplicate moniker")
	}
	if !strings.Contains(result.Err.Error(), "moniker") {
		t.Errorf("error should mention moniker: %v", result.Err)
	}
}

func TestCheckQuote_Stage2IntermediateError(t *testing.T) {
	// Verifies that an HTTP error from a non-final stage-2 peer propagates as an error.
	hexQuote := testHexQuote
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		if call == 1 {
			// Stage 1: return nonce.
			json.NewEncoder(w).Encode(map[string]string{
				"machineId": "machine-aaa",
				"moniker":   "alice",
				"nonce":     "nonce0",
			})
			return
		}
		// Stage 2: return 500.
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer server.Close()

	poc := NewPoCClient([]string{server.URL}, 1, &http.Client{})
	result := poc.CheckQuote(context.Background(), hexQuote)

	if result.Err == nil {
		t.Fatal("expected error for stage-2 HTTP 500")
	}
}

func TestCheckQuote_Stage2NoJWT(t *testing.T) {
	// Verifies that exhausting all stage-2 peers without receiving a JWT is an error.
	hexQuote := testHexQuote
	monikers := []string{"alice", "bob"}
	servers := make([]*httptest.Server, 2)
	for i := range 2 {
		var calls atomic.Int32
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			call := calls.Add(1)
			if call == 1 {
				json.NewEncoder(w).Encode(map[string]string{
					"machineId": "machine-aaa",
					"moniker":   monikers[i],
					"nonce":     fmt.Sprintf("nonce%d", i),
				})
				return
			}
			// Stage 2: return partial sig instead of JWT.
			json.NewEncoder(w).Encode(map[string]string{
				monikers[i]: "partialsig",
			})
		}))
	}
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()

	poc := NewPoCClient([]string{servers[0].URL, servers[1].URL}, 2, &http.Client{})
	result := poc.CheckQuote(context.Background(), hexQuote)

	if result.Err == nil {
		t.Fatal("expected error when no peer returns a JWT")
	}
	if !strings.Contains(result.Err.Error(), "without final JWT") {
		t.Errorf("error should mention 'without final JWT': %v", result.Err)
	}
}

func TestCheckQuote_Stage2Forbidden(t *testing.T) {
	// Verifies that a 403 during stage 2 results in Registered=false with no error.
	hexQuote := testHexQuote
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		if call == 1 {
			json.NewEncoder(w).Encode(map[string]string{
				"machineId": "machine-aaa",
				"moniker":   "alice",
				"nonce":     "nonce0",
			})
			return
		}
		// Stage 2: return 403.
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	poc := NewPoCClient([]string{server.URL}, 1, &http.Client{})
	result := poc.CheckQuote(context.Background(), hexQuote)

	if result.Err != nil {
		t.Fatalf("expected no error for stage-2 403, got: %v", result.Err)
	}
	if result.Registered {
		t.Error("expected Registered=false for stage-2 403")
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
