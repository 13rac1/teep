package attestation

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

// nearLauncherIndexDigest is the signed index of NEAR's compose-manager
// launcher that the GLM deployments of 2026-09-09 pin in their compose
// (docs/attestation_gaps/near_image_provenance.md). It is the subject digest
// of NEAR's Rekor records, so the transparency log search finds it directly.
const nearLauncherIndexDigest = "91fdff3cfa3543d72656b2368c7d8a0a83d95a0f1087378c897aa1537acdba56"

// A compose that pins the signed index digest passes the Sigstore lookup,
// so it needs no allow_fail exception for sigstore_verification. A digest
// that the log does not hold fails it.
func TestNearIndexPinnedComposePassesEnforcedSigstore(t *testing.T) {
	compose := `{"docker_compose_file":"services:\n  compose-manager-launcher:\n    image: nearaidev/compose-manager-launcher@sha256:` + nearLauncherIndexDigest + `\n"}`
	digests := ExtractComposeDigests(compose).Digests
	if !slices.Equal(digests, []string{nearLauncherIndexDigest}) {
		t.Fatalf("compose digests = %v, want the pinned index digest", digests)
	}

	// The log holds the index digest only.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/index/retrieve" {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Hash string `json:"hash"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if body.Hash == "sha256:"+nearLauncherIndexDigest {
			_, _ = w.Write([]byte(`["24296fb24b8ad77a5ad5ec6ae4a2ab7d79c7b26fd0e6a0c4fd1e3b0e1a1e5bfd1a2b3c4d5e6f7a8b"]`))
			return
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	defer ts.Close()
	rc := NewRekorClientWithBase(ts.URL, ts.Client())

	for _, tc := range []struct {
		name   string
		digest string
		want   Status
	}{
		{"pinned signed index", nearLauncherIndexDigest, Pass},
		{"digest not in the log", "aa" + nearLauncherIndexDigest[2:], Fail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results := rc.CheckSigstoreDigests(t.Context(), []string{tc.digest})
			factors := evalSigstoreVerification(&ReportInput{Sigstore: results})
			if len(factors) != 1 || factors[0].Name != FactorSigstoreVerify || factors[0].Status != tc.want {
				t.Fatalf("sigstore_verification = %+v, want %s", factors, tc.want)
			}
		})
	}
}
