package attestation

import (
	"context"
	"crypto/subtle"
	"slices"
)

// GatewayMemo holds the gateway verification result of one verification of
// several instances of a model. Every instance carries the same gateway
// evidence, so the gateway quote, compose and Proof of Cloud checks run once.
// It is not safe for concurrent use: one verification uses it in sequence.
type GatewayMemo[T any] struct {
	key   string
	value T
	set   bool
}

// Get returns the result for the gateway evidence of raw. It calls verify
// for the first instance and again for any instance whose gateway evidence
// differs from the stored one.
func (m *GatewayMemo[T]) Get(raw *RawAttestation, verify func() T) T {
	key := gatewayMemoKey(raw)
	if m.set && subtle.ConstantTimeCompare([]byte(m.key), []byte(key)) == 1 {
		return m.value
	}
	m.key, m.value, m.set = key, verify(), true
	return m.value
}

// gatewayMemoKey joins the gateway evidence that the gateway checks read.
// The gateway event log is bound to the quote by the RTMR replay.
func gatewayMemoKey(raw *RawAttestation) string {
	return raw.GatewayIntelQuote + "\x00" + raw.GatewayAppCompose + "\x00" + raw.GatewayNonceHex + "\x00" +
		raw.GatewaySigningAddress + "\x00" + raw.GatewayTLSFingerprint
}

// SupplyChainMemo holds the Sigstore and Rekor results of one verification
// of several instances of a model, so each image digest is looked up once.
// A result depends only on the digest and, for provenance, on its
// repository and the supply chain policy, which one verification does not
// change. It is not safe for concurrent use: one verification uses it in
// sequence.
type SupplyChainMemo struct {
	sigstore map[string]SigstoreResult
	rekor    map[string]RekorProvenance
}

// NewSupplyChainMemo returns an empty memo.
func NewSupplyChainMemo() *SupplyChainMemo {
	return &SupplyChainMemo{sigstore: make(map[string]SigstoreResult), rekor: make(map[string]RekorProvenance)}
}

// CheckSigstoreDigests returns rc.CheckSigstoreDigests(digests), and sends
// requests only for digests that the memo has no result for. A nil memo
// sends a request for every digest.
func (m *SupplyChainMemo) CheckSigstoreDigests(ctx context.Context, rc *RekorClient, digests []string) []SigstoreResult {
	if m == nil {
		return rc.CheckSigstoreDigests(ctx, digests)
	}
	var missing []string
	for _, d := range digests {
		if _, ok := m.sigstore[d]; !ok && !slices.Contains(missing, d) {
			missing = append(missing, d)
		}
	}
	if len(missing) > 0 {
		for _, r := range rc.CheckSigstoreDigests(ctx, missing) {
			m.sigstore[r.Digest] = r
		}
	}
	out := make([]SigstoreResult, 0, len(digests))
	for _, d := range digests {
		out = append(out, m.sigstore[d])
	}
	return out
}

// FetchRekorProvenancesForPolicy returns
// rc.FetchRekorProvenancesForPolicy(digests, digestToRepo, policy), and sends
// requests only for digest and repository pairs that the memo has no result
// for.
func (m *SupplyChainMemo) FetchRekorProvenancesForPolicy(ctx context.Context, rc *RekorClient,
	digests []string, digestToRepo map[string]string, policy *SupplyChainPolicy,
) []RekorProvenance {
	if m == nil {
		return rc.FetchRekorProvenancesForPolicy(ctx, digests, digestToRepo, policy)
	}
	key := func(d string) string { return d + "\x00" + digestToRepo[d] }
	var missing []string
	for _, d := range digests {
		if _, ok := m.rekor[key(d)]; !ok && !slices.Contains(missing, d) {
			missing = append(missing, d)
		}
	}
	if len(missing) > 0 {
		results := rc.FetchRekorProvenancesForPolicy(ctx, missing, digestToRepo, policy)
		for i := range results {
			m.rekor[key(missing[i])] = results[i]
		}
	}
	out := make([]RekorProvenance, 0, len(digests))
	for _, d := range digests {
		out = append(out, m.rekor[key(d)])
	}
	return out
}
