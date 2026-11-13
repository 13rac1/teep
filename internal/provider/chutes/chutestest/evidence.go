package chutestest

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
)

// Evidence returns a synthetic Chutes evidence response with one entry for
// each id in ids, as a JSON document that a test can change before it
// marshals it. Each entry has the members of the response and an
// attested_body whose quote is the entry's quote and whose nonce is nonce.
// The quotes are not TDX quotes.
func Evidence(nonce attestation.Nonce, ids ...string) map[string]any {
	entries := make([]any, len(ids))
	for i, id := range ids {
		quote := base64.StdEncoding.EncodeToString([]byte("quote of " + id))
		body, err := json.Marshal(map[string]any{
			"evidence": map[string]any{"tdx_quote": quote, "nvtrust_evidence": ""},
			"nonce":    nonce.Hex(),
		})
		if err != nil {
			panic(err) // a map of strings always marshals
		}
		entries[i] = map[string]any{
			"attested_body": base64.StdEncoding.EncodeToString(body),
			"certificate":   "",
			"gpu_evidence":  []any{},
			"instance_id":   id,
			"quote":         quote,
			"signature":     "signature of " + id,
			"tee_type":      "tdx",
		}
	}
	return map[string]any{
		"evidence":              entries,
		"excluded_instance_ids": []any{},
		"failed_instance_ids":   []any{},
	}
}

// Marshal returns the JSON encoding of doc.
func Marshal(tb testing.TB, doc map[string]any) []byte {
	tb.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		tb.Fatalf("marshal evidence: %v", err)
	}
	return b
}

// Entry returns entry i of the evidence list of doc, a document of
// Evidence. It panics when doc has no such entry.
func Entry(doc map[string]any, i int) map[string]any {
	entries, ok := doc["evidence"].([]any)
	if !ok || i >= len(entries) {
		panic("chutestest: no evidence entry")
	}
	entry, ok := entries[i].(map[string]any)
	if !ok {
		panic("chutestest: evidence entry is not an object")
	}
	return entry
}
