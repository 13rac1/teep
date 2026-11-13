package attestation

import (
	"context"
	"encoding/json"
	"slices"
)

// GatewayResults are the results of the gateway TDX checks of one
// verification: the gateway quote with its REPORTDATA binding, the gateway
// compose binding, and the Proof of Cloud check of the gateway quote.
type GatewayResults struct {
	TDX     *TDXVerifyResult
	Compose *ComposeBindingResult
	PoC     *PoCResult
}

// GatewayMemo holds the gateway results of one verification of several
// instances of a model. Every instance of a NEAR cloud model carries the same
// gateway evidence, so the gateway checks run once.
//
// A result is reused only for an instance whose key fields are equal, so a
// failure of the first instance's gateway checks (a transient collateral or
// Proof of Cloud error, or a cancelled context) is reused for the others too.
// The verdict stays the same for every instance, and no request repeats.
//
// It is not safe for concurrent use: one verification uses it in sequence.
type GatewayMemo struct {
	key   gatewayMemoKey
	value GatewayResults
	set   bool
}

// Get returns the gateway results for raw. It calls verify for the first
// instance and again for any instance whose key fields differ.
func (m *GatewayMemo) Get(raw *RawAttestation, verify func() GatewayResults) GatewayResults {
	key := newGatewayMemoKey(raw)
	if m.set && key == m.key {
		return m.value
	}
	m.key, m.value, m.set = key, verify(), true
	return m.value
}

// gatewayMemoKey holds every field of RawAttestation that a gateway check
// or a gateway REPORTDATA verifier reads. The key is public evidence, so the
// comparison need not be constant time.
//
// The gateway checks read GatewayIntelQuote, GatewayAppCompose, and, in
// the REPORTDATA verifiers: GatewayNonceHex, GatewaySigningAddress and
// GatewayTLSFingerprint (nearcloud); SigningKey and SigningAddress
// (venice); SigningKey, ACICanonicalReport and the ACI workload keyset
// (aci). The memoised function does not read GatewayEventLog: the report
// builder replays it for each instance from that instance's attestation.
// The key holds it too, so equal keys mean equal gateway evidence. A field
// that a gateway check starts to read must be added here.
type gatewayMemoKey struct {
	quote, compose, nonce, gatewayAddress, gatewayTLS string
	signingKey, signingAddress                        string
	aciCanonical                                      bool
	aciKeysetDigest, aciKeyset, eventLog              string
}

func newGatewayMemoKey(raw *RawAttestation) gatewayMemoKey {
	return gatewayMemoKey{
		quote: raw.GatewayIntelQuote, compose: raw.GatewayAppCompose, nonce: raw.GatewayNonceHex,
		gatewayAddress: raw.GatewaySigningAddress, gatewayTLS: raw.GatewayTLSFingerprint,
		signingKey: raw.SigningKey, signingAddress: raw.SigningAddress,
		aciCanonical: raw.ACICanonicalReport, aciKeysetDigest: raw.ACIWorkloadKeysetDigest,
		aciKeyset: memoJSON(raw.ACIWorkloadKeyset), eventLog: memoJSON(raw.GatewayEventLog),
	}
}

// memoJSON encodes v for a memo key. A value that does not encode gets a
// key that matches no other, so its result is never reused.
func memoJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "unencodable:" + NewNonce().Hex()
	}
	return string(b)
}

// SupplyChainMemo holds the Sigstore and Rekor results of one verification
// of several instances of a model, so each image digest is looked up once.
// A failed lookup (a transient Rekor error or a cancelled context) is reused
// for the other instances too: the verdict stays the same for every
// instance, and no request repeats.
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
