package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct"
)

func TestAuthorizationFailureDiagnosticsRetainAttemptGeneration(t *testing.T) {
	identity, err := tlsct.NewTransportIdentity("model.example", strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	published := time.Now()
	value := &authorization{identity: identity, generation: 7, publishedAt: published}
	mismatch := &tlsct.SPKIMismatchError{Authority: identity.Authority(), ServerName: "model.example", Expected: identity.Fingerprint(), Observed: strings.Repeat("cd", 32)}
	for _, removed := range []bool{false, true} {
		attrs := authorizationFailureDiagnostics(value, errors.Join(errors.New("handshake"), mismatch), removed)
		fields := make(map[string]any)
		for i := 0; i < len(attrs); i += 2 {
			fields[attrs[i].(string)] = attrs[i+1]
		}
		if fields["authorization_generation"] != authorizationGeneration(7) || fields["authorization_removed"] != removed || fields["authorization_published_at"] != published || fields["tls_sni"] != "model.example" {
			t.Fatalf("incorrect attempt diagnostics: %v", fields)
		}
		for _, name := range []string{"expected_spki", "observed_spki"} {
			want := mismatch.Expected
			if name == "observed_spki" {
				want = mismatch.Observed
			}
			if !tlsct.SPKIFingerprintsEqual(fields[name].(string), want) {
				t.Fatalf("incorrect %s", name)
			}
		}
	}
}

// publicationLockWriter checks the lock from inside the synchronous log write.
type publicationLockWriter struct {
	store    *authorizationStore
	observed atomic.Bool
	locked   atomic.Bool
}

func (w *publicationLockWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "authorization published") {
		w.observed.Store(true)
		if w.store.mu.TryLock() {
			w.store.mu.Unlock()
		} else {
			w.locked.Store(true)
		}
	}
	return len(p), nil
}
func TestAuthorizationPublicationLogsOutsideLock(t *testing.T) {
	store := newAuthorizationStore(10, 2, time.Second)
	defer store.close()
	writer := &publicationLockWriter{store: store}
	store.logger = slog.New(slog.NewTextHandler(writer, nil))
	key, candidate := testAuthorizationCandidate(t, "model")
	loadTestAuthorization(t, store, key, candidate)
	if !writer.observed.Load() || writer.locked.Load() {
		t.Fatal("publication log must run outside the store lock")
	}
}

// Install before starting store operations. Each handler serializes its writes;
// tests inspect the buffer only after all operations have returned.
func captureAuthorizationDiagnostics(t *testing.T, store *authorizationStore) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	store.logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return &logs
}

func TestAuthorizationDiagnosticLoggersAreIndependent(t *testing.T) {
	t.Parallel()
	var wg sync.WaitGroup
	logs := make([]*bytes.Buffer, 2)
	for i := range logs {
		store := newAuthorizationStore(10, 2, time.Second)
		t.Cleanup(store.close)
		logs[i] = captureAuthorizationDiagnostics(t, store)
		key, candidate := testAuthorizationCandidate(t, fmt.Sprintf("isolated-model-%d", i))
		wg.Go(func() {
			_, _, err := store.load(t.Context(), key, nil, nil, func(context.Context) (authorizationVerification, error) {
				return authorizationVerification{candidate: candidate}, nil
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	for i, buffer := range logs {
		for _, field := range []string{"authorization verification started", "authorization verification result received", "authorization_verification_shared=false"} {
			if !strings.Contains(buffer.String(), field) {
				t.Fatalf("missing %q in verification diagnostics: %s", field, buffer.String())
			}
		}
		if !strings.Contains(buffer.String(), fmt.Sprintf("isolated-model-%d", i)) || strings.Contains(buffer.String(), fmt.Sprintf("isolated-model-%d", 1-i)) {
			t.Fatalf("store diagnostics were mixed: %s", buffer.String())
		}
	}
}
