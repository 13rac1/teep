package chutes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestNoncePool_Take(t *testing.T) {
	chuteID := "test-chute-uuid-0001-0002-000000000001"
	instancesResp := e2eInstancesResponse{
		Instances: []e2eInstance{
			{
				InstanceID: "inst-1",
				E2EPubKey:  "base64pubkey1",
				Nonces:     []string{"nonce-a", "nonce-b", "nonce-c"},
			},
			{
				InstanceID: "inst-2",
				E2EPubKey:  "base64pubkey2",
				Nonces:     []string{"nonce-d", "nonce-e"},
			},
		},
		NonceExpIn: 60,
	}

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch r.URL.Path {
		case "/e2e/instances/" + chuteID:
			json.NewEncoder(w).Encode(instancesResp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	resolver := &fakeResolver{id: chuteID}
	pool := NewNoncePool(srv.URL, "test-key", resolver, srv.Client())

	ctx := context.Background()

	// Take 5 nonces — should consume all from both instances.
	seen := make(map[string]bool)
	for i := range 5 {
		mat, err := pool.Take(ctx, "test-model")
		if err != nil {
			t.Fatalf("Take %d: %v", i, err)
		}
		if mat.ChuteID != chuteID {
			t.Errorf("Take %d: ChuteID = %q, want %q", i, mat.ChuteID, chuteID)
		}
		key := mat.InstanceID + ":" + mat.E2ENonce
		if seen[key] {
			t.Errorf("Take %d: duplicate nonce %q", i, key)
		}
		seen[key] = true
	}

	// Should have fetched instances exactly once.
	if callCount != 1 {
		t.Errorf("API calls = %d, want 1 (nonces should be pooled)", callCount)
	}

	// Take 6th nonce — pool is empty, should trigger refresh.
	mat, err := pool.Take(ctx, "test-model")
	if err != nil {
		t.Fatalf("Take 6: %v", err)
	}
	if callCount != 2 {
		t.Errorf("API calls = %d, want 2 (refresh on empty pool)", callCount)
	}
	_ = mat
}

func TestNoncePool_PrefersHealthyInstances(t *testing.T) {
	chuteID := "test-chute-uuid-0001-0002-000000000002"
	instancesResp := e2eInstancesResponse{
		Instances: []e2eInstance{
			{
				InstanceID: "inst-bad",
				E2EPubKey:  "pk-bad",
				Nonces:     []string{"nonce-1", "nonce-2"},
			},
			{
				InstanceID: "inst-good",
				E2EPubKey:  "pk-good",
				Nonces:     []string{"nonce-3", "nonce-4"},
			},
		},
		NonceExpIn: 60,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(instancesResp)
	}))
	defer srv.Close()

	resolver := &fakeResolver{id: chuteID}
	pool := NewNoncePool(srv.URL, "test-key", resolver, srv.Client())

	ctx := context.Background()

	// Prime the pool.
	_, err := pool.Take(ctx, "test-model")
	if err != nil {
		t.Fatal(err)
	}

	// Mark inst-bad as failed.
	pool.MarkFailed(chuteID, "inst-bad")

	// Next take should prefer inst-good.
	mat, err := pool.Take(ctx, "test-model")
	if err != nil {
		t.Fatal(err)
	}
	if mat.InstanceID != "inst-good" {
		t.Errorf("InstanceID = %q, want inst-good (fewer failures)", mat.InstanceID)
	}
}

func TestNoncePool_ExpiresNonces(t *testing.T) {
	chuteID := "test-chute-uuid-0001-0002-000000000003"
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(e2eInstancesResponse{
			Instances: []e2eInstance{
				{
					InstanceID: "inst-1",
					E2EPubKey:  "pk-1",
					Nonces:     []string{"nonce-1"},
				},
			},
			NonceExpIn: 1, // 1 second TTL
		})
	}))
	defer srv.Close()

	resolver := &fakeResolver{id: chuteID}
	pool := NewNoncePool(srv.URL, "test-key", resolver, srv.Client())

	ctx := context.Background()

	// First take: fetches and uses nonce-1.
	mat, err := pool.Take(ctx, "test-model")
	if err != nil {
		t.Fatal(err)
	}
	if mat.E2ENonce != "nonce-1" {
		t.Errorf("nonce = %q, want nonce-1", mat.E2ENonce)
	}
	if callCount != 1 {
		t.Errorf("calls = %d, want 1", callCount)
	}

	// Wait for expiry (TTL=1s, but we subtract 5s margin so it expires immediately
	// ... the safety margin reduces TTL to negative effectively for TTL <= margin*2).
	// For TTL=1 <= 5*2=10, no margin is subtracted, so it's 1s.
	time.Sleep(1100 * time.Millisecond)

	// Second take: pool expired, should refetch.
	_, err = pool.Take(ctx, "test-model")
	if err != nil {
		t.Fatal(err)
	}
	if callCount != 2 {
		t.Errorf("calls = %d, want 2 (pool should have expired)", callCount)
	}
}

func TestNoncePool_Invalidate(t *testing.T) {
	chuteID := "test-chute-uuid-0001-0002-000000000004"
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(e2eInstancesResponse{
			Instances: []e2eInstance{
				{
					InstanceID: "inst-1",
					E2EPubKey:  "pk-1",
					Nonces:     []string{"nonce-1", "nonce-2"},
				},
			},
			NonceExpIn: 60,
		})
	}))
	defer srv.Close()

	resolver := &fakeResolver{id: chuteID}
	pool := NewNoncePool(srv.URL, "test-key", resolver, srv.Client())

	ctx := context.Background()

	if _, err := pool.Take(ctx, "test-model"); err != nil {
		t.Fatalf("first Take: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("calls = %d, want 1", callCount)
	}

	pool.Invalidate(chuteID)

	if _, err := pool.Take(ctx, "test-model"); err != nil {
		t.Fatalf("second Take after Invalidate: %v", err)
	}
	if callCount != 2 {
		t.Errorf("calls = %d, want 2 (invalidated pool should refetch)", callCount)
	}
}

func TestNoncePool_ConcurrentTake(t *testing.T) {
	chuteID := "test-chute-uuid-0001-0002-000000000005"
	nonces := make([]string, 100)
	for i := range nonces {
		nonces[i] = "nonce-" + string(rune('A'+i%26)) + string(rune('0'+i/26))
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(e2eInstancesResponse{
			Instances: []e2eInstance{
				{
					InstanceID: "inst-1",
					E2EPubKey:  "pk-1",
					Nonces:     nonces,
				},
			},
			NonceExpIn: 60,
		})
	}))
	defer srv.Close()

	resolver := &fakeResolver{id: chuteID}
	pool := NewNoncePool(srv.URL, "test-key", resolver, srv.Client())

	ctx := context.Background()
	var mu sync.Mutex
	seen := make(map[string]bool)
	var wg sync.WaitGroup

	for range 50 {
		wg.Go(func() {
			mat, err := pool.Take(ctx, "test-model")
			if err != nil {
				t.Errorf("concurrent Take: %v", err)
				return
			}
			mu.Lock()
			if seen[mat.E2ENonce] {
				t.Errorf("duplicate nonce: %s", mat.E2ENonce)
			}
			seen[mat.E2ENonce] = true
			mu.Unlock()
		})
	}
	wg.Wait()

	mu.Lock()
	if len(seen) != 50 {
		t.Errorf("unique nonces = %d, want 50", len(seen))
	}
	mu.Unlock()
}

// fakeResolver is a test helper that returns a fixed chute UUID.
type fakeResolver struct {
	id string
}

func (r *fakeResolver) Resolve(_ context.Context, _ string) (string, error) {
	return r.id, nil
}
