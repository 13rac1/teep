package attestation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestCheckQuoteMultisigFullFlow exercises the complete 3-peer multisig flow:
// Stage 1: collect nonces from 3 peers, Stage 2: chain partial sigs, final JWT.
func TestCheckQuoteMultisigFullFlow(t *testing.T) {
	hexQuote := "aabbccdd"

	// Track calls per peer to serve correct stage responses.
	var peerCalls [3]atomic.Int32

	monikers := []string{"alice", "bob", "carol"}
	nonces := []string{"nonce_alice", "nonce_bob", "nonce_carol"}
	testJWT := "header.payload.signature"

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

	client := &http.Client{}
	poc := NewPoCClient(peers, PoCQuorum, client)
	// Override JWT verification because the test uses a synthetic non-JWT token.
	// Production code uses verifyPoCJWTClaims by default (F-39).
	poc.jwtVerifyFn = func(jwtStr, machineID string) error { return nil }
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

// TestBuildReportWithPoCRegistered verifies cpu_id_registry Pass with PoC result.
func TestBuildReportWithPoCRegistered(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	pocResult := &PoCResult{Registered: true, Label: "test-machine"}

	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, PoC: pocResult})
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

	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, PoC: pocResult})
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

	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, PoC: pocResult})
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

	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, TDX: tdxResult})
	f := findFactor(t, report, "cpu_id_registry")
	if f.Status != Skip {
		t.Errorf("cpu_id_registry with PPID offline: got %s, want SKIP", f.Status)
	}
	if !strings.Contains(f.Detail, "aabbccdd") {
		t.Errorf("detail should contain PPID prefix: %s", f.Detail)
	}
}
