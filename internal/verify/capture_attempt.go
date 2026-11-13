package verify

import (
	"net/http"

	"github.com/13rac1/teep/internal/capture"
)

// verificationCapture belongs to one Run invocation. Discovery is immutable;
// evidence is replaced on re-attestation so replay cannot combine an old key
// with the final inference outcome. Metadata and evidence retain their independently owned pools.
type verificationCapture struct {
	attestation          http.RoundTripper
	attestationDiscovery *capture.RecordingTransport
	discovery            *capture.RecordingTransport
	evidence             *capture.RecordingTransport
	freshEvidence        *capture.RecordingTransport
	// e2ee records the live E2EE test exchange. Replay does not send it
	// again: the outcome comes from the manifest.
	e2ee *capture.RecordingTransport
}

func (c *verificationCapture) beginEvidence(client *http.Client) {
	c.freshEvidence = nil
	c.evidence = capture.WrapRecording(c.attestation)
	client.Transport = c.evidence
}

// entries snapshots completed exchanges, including on caller cancellation.
func (c *verificationCapture) entries() []capture.RecordedEntry {
	var entries []capture.RecordedEntry
	if c.discovery != nil {
		entries = c.discovery.Snapshot()
	}
	if c.attestationDiscovery != nil {
		entries = append(entries, c.attestationDiscovery.Snapshot()...)
	}
	if c.evidence != nil {
		entries = append(entries, c.evidence.Snapshot()...)
	}
	if c.freshEvidence != nil {
		entries = append(entries, c.freshEvidence.Snapshot()...)
	}
	if c.e2ee != nil {
		entries = append(entries, c.e2ee.Snapshot()...)
	}
	return entries
}

// recordE2EE wraps the transport of the live E2EE test client. A later E2EE
// test of the same run replaces the recording.
func (c *verificationCapture) recordE2EE(base http.RoundTripper) http.RoundTripper {
	c.e2ee = capture.WrapRecording(base)
	return c.e2ee
}

func (c *verificationCapture) recordFreshEvidence(base http.RoundTripper) http.RoundTripper {
	c.freshEvidence = capture.WrapRecording(base)
	return c.freshEvidence
}
