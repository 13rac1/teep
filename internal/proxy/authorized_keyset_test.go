package proxy

import (
	"net/http"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/provider"
)

// On the pinned path, a response without a keyset digest fails and ends the
// authorization generation that the request used. A response of another
// keyset digest is relayed, and the generation ends so that the next request
// verifies again (ACI/1 §5.2). A replacement generation stays.
func TestCheckAuthorizedKeyset(t *testing.T) {
	server := &Server{authorizations: newAuthorizationStore(10, 2, time.Second)}
	defer server.authorizations.close()
	key, candidate := testAuthorizationCandidate(t, "model")
	candidate.report.ACIKeysetDigest = "sha256:aa"
	input := &authorizedRequest{provider: &provider.Provider{Name: key.ProviderName()}, key: key}
	header := func(digest string) http.Header {
		h := http.Header{}
		if digest != "" {
			h.Set("X-Aci-Keyset-Digest", digest)
		}
		return h
	}
	for _, tc := range []struct {
		name, served string
		wantErr      bool
		ended        bool
	}{
		{"verified digest", "sha256:aa", false, false},
		{"other digest", "sha256:bb", false, true},
		{"no digest", "", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server.authorizations.invalidate(key)
			value := loadTestAuthorization(t, server.authorizations, key, candidate)
			err := server.checkAuthorizedKeyset(t.Context(), input, value, header(tc.served))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			current, ok := server.authorizations.acquire(key)
			if ended := !ok || current.generation != value.generation; ended != tc.ended {
				t.Errorf("generation ended = %v, want %v", ended, tc.ended)
			}
		})
	}

	old := loadTestAuthorization(t, server.authorizations, key, candidate)
	server.authorizations.invalidate(key)
	replacement := loadTestAuthorization(t, server.authorizations, key, candidate)
	if err := server.checkAuthorizedKeyset(t.Context(), input, old, header("sha256:bb")); err != nil {
		t.Fatal(err)
	}
	if current, ok := server.authorizations.acquire(key); !ok || current.generation != replacement.generation {
		t.Error("a response of an earlier generation ended the replacement")
	}
}
