package verify

import (
	"net/http"

	"github.com/13rac1/teep/internal/capture"
)

// verificationCapture belongs to one Run invocation. Discovery is immutable;
// evidence is replaced on re-attestation so replay cannot combine an old key
// with the final inference outcome. Both recorders share the caller's pool.
type verificationCapture struct {
	discovery *capture.RecordingTransport
	evidence  *capture.RecordingTransport
}

func (c *verificationCapture) beginEvidence(client *http.Client) {
	c.evidence = capture.WrapRecording(c.discovery.Base)
	client.Transport = c.evidence
}

// entries snapshots completed exchanges, including on caller cancellation.
func (c *verificationCapture) entries() []capture.RecordedEntry {
	entries := c.discovery.Snapshot()
	if c.evidence != nil {
		entries = append(entries, c.evidence.Snapshot()...)
	}
	return entries
}
