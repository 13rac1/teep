package aci

import (
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/e2ee"
)

// The signing key counts as a keyset E2EE key only under the E2EE v2
// secp256k1 suite, the suite that teep encrypts with.
func TestKeysetContainsE2EEKeyRequiresSecp256k1Suite(t *testing.T) {
	key := "04" + strings.Repeat("ab", 64)
	for _, tc := range []struct {
		algo string
		want bool
	}{
		{e2ee.ACIv2Algo, true},
		{"x25519-aes-256-gcm-hkdf-sha256", false},
		{"ecdsa", false},
		{"", false},
	} {
		ks := &aciWorkloadKeyset{E2EEPublicKeys: []aciKey{{KeyID: "k", Algo: tc.algo, PublicKey: key}}}
		if got := keysetContainsE2EEKey(ks, key); got != tc.want {
			t.Errorf("algo %q: keysetContainsE2EEKey = %v, want %v", tc.algo, got, tc.want)
		}
	}
}
