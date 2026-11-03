// Package chutestest loads the captured Chutes attestations of
// internal/integration/testdata for tests in other packages.
package chutestest

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/provider/chutes"
)

// Capture is one captured direct Chutes attestation, parsed with the
// production parser.
type Capture struct {
	Name string
	// Nonce is the client nonce of the capture.
	Nonce attestation.Nonce
	Raw   *attestation.RawAttestation
}

// Captures loads every chutes_* capture under testdata.
func Captures(tb testing.TB, testdata string) []Capture {
	tb.Helper()
	dirs, err := filepath.Glob(filepath.Join(testdata, "chutes_*"))
	if err != nil || len(dirs) == 0 {
		tb.Fatalf("no Chutes captures in %s: %v", testdata, err)
	}
	out := make([]Capture, 0, len(dirs))
	for _, dir := range dirs {
		manifest, entries, err := capture.Load(dir)
		if err != nil {
			tb.Fatalf("%s: %v", dir, err)
		}
		nonce, err := attestation.ParseNonce(manifest.NonceHex)
		if err != nil {
			tb.Fatalf("%s: %v", dir, err)
		}
		instances := body(tb, dir, entries, "/e2e/instances/")
		evidence := body(tb, dir, entries, "/evidence")
		raw, err := chutes.ParseAttestationResponse(context.Background(), instances, evidence, nonce)
		if err != nil {
			tb.Fatalf("%s: %v", dir, err)
		}
		out = append(out, Capture{Name: filepath.Base(dir), Nonce: nonce, Raw: raw})
	}
	return out
}

// body returns the body of the one entry whose URL contains part.
func body(tb testing.TB, dir string, entries []capture.RecordedEntry, part string) []byte {
	tb.Helper()
	var found []byte
	for i := range entries {
		if !strings.Contains(entries[i].URL, part) {
			continue
		}
		if found != nil {
			tb.Fatalf("%s: more than one %s response", dir, part)
		}
		found = entries[i].Body
	}
	if found == nil {
		tb.Fatalf("%s: no %s response", dir, part)
	}
	return found
}
