package proxy

import (
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/tlsct/testtls"
)

func TestAuthorizedNearCloudIgnoredAffinity(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		for _, mode := range []string{"honored", "disabled", "empty_map", "unknown_group"} {
			for _, encrypted := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/encrypted=%v", mode, encrypted), func(t *testing.T) { testCloudAffinity(t, authority, mode, encrypted) })
			}
		}
	})
}

func testCloudAffinity(t *testing.T, authority *testtls.Authority, mode string, encrypted bool) {
	t.Helper()
	a, err := e2ee.NewNearCloudSession()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Zero()
	b, err := e2ee.NewNearCloudSession()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Zero()
	f := &cloudAffinityFixture{t: t, mode: mode, encrypted: encrypted, a: a, b: b, ready: make(chan struct{})}
	upstream, fp := newTLSBindingTestServerWithHandler(t, authority, http.HandlerFunc(f.serve))
	server, input, initial := nearCompletionAuthorization(t, "nearcloud", upstream.URL, fp)
	input.provider.E2EE = encrypted
	candidate, err := newAuthorization(initial.key, initial.report, a.ClientEd25519PubHex(), encrypted, false)
	if err != nil {
		t.Fatal(err)
	}
	server.authorizations.invalidate(initial.key)
	current := loadTestAuthorization(t, server.authorizations, initial.key, candidate)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			request := *input
			request.stream = i%2 == 0
			out, err := server.inferAuthorized(t.Context(), newInferenceRecorder(), &request)
			success := !encrypted || mode == "honored"
			if (err == nil) != success {
				t.Errorf("expected success=%v error=%v", success, err)
			}
			if !success && out.status == "ok" {
				t.Error("unauthenticated response reported success")
			}
		})
	}
	wg.Wait()
	if f.calls.Load() != 8 {
		t.Fatal("ignored hint caused replay")
	}
	wantDecrypted := int32(0)
	if encrypted && mode == "honored" {
		wantDecrypted = 8
	}
	if f.decrypted.Load() != wantDecrypted {
		t.Fatal("protected fields reached wrong key")
	}
	after, ok := server.authorizations.acquire(current.key)
	if encrypted && mode != "honored" {
		if ok {
			t.Fatal("response authentication failure retained used authorization")
		}
		return
	}
	if !ok || after.generation != current.generation {
		t.Fatal("successful requests replaced authorization")
	}
	for _, factor := range after.report.Factors {
		if !encrypted && factor.Name == attestation.FactorE2EEUsable && factor.Status == attestation.Pass {
			t.Fatal("TLS-only ignored hint promoted E2EE")
		}
	}
}

type cloudAffinityFixture struct {
	t                *testing.T
	mode             string
	encrypted        bool
	a, b             *e2ee.NearCloudSession
	calls, decrypted atomic.Int32
	ready            chan struct{}
}

func (f *cloudAffinityFixture) serve(w http.ResponseWriter, r *http.Request) {
	t, mode, encrypted, a, b := f.t, f.mode, f.encrypted, f.a, f.b

	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Model-Pub-Key")), []byte(a.ClientEd25519PubHex())) != 1 {
		t.Error("hint differs from acquired key")
	}
	// These are the gateway's distinct routing preconditions. Unavailable key
	// restrictions can select B even though the client supplied A's key.
	enabled := mode != "disabled"
	groups := map[string]*e2ee.NearCloudSession{}
	if mode != "empty_map" {
		groups[b.ClientEd25519PubHex()] = b
	}
	if mode == "honored" {
		groups[a.ClientEd25519PubHex()] = a
	}
	selected := b
	if enabled {
		if matching := groups[r.Header.Get("X-Model-Pub-Key")]; matching != nil {
			selected = matching
		}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		t.Error(err)
		return
	}
	var input struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if _, _, err := jsonstrict.Unmarshal(body, &input); err != nil || len(input.Messages) != 1 {
		t.Error("invalid request envelope")
		return
	}
	if encrypted {
		plain, err := selected.Decrypt(input.Messages[0].Content)
		if err == nil {
			f.decrypted.Add(1)
			if string(plain) != "test" {
				t.Error("unexpected decrypted field")
			}
		} else if len(plain) != 0 {
			t.Error("failed authentication exposed plaintext")
		}
		if (err == nil) != (mode == "honored") {
			t.Error("gateway routing did not exercise selected key")
		}
	}
	if f.calls.Add(1) == 8 {
		close(f.ready)
	}
	select {
	case <-f.ready:
	case <-r.Context().Done():
		return
	}
	if encrypted && mode != "honored" {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"unauthenticated\"}}]}\n\ndata: [DONE]\n\n")
		return
	}
	writeNearPolicyChat(t, w, r)
}
