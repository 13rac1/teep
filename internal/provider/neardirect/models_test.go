package neardirect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

type staticLister []string

func (l staticLister) ListModels(context.Context) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, 0, len(l))
	for _, id := range l {
		out = append(out, json.RawMessage(`{"id":"`+id+`","object":"model","owned_by":"nearai"}`))
	}
	return out, nil
}

func listedIDs(t *testing.T, l *modelLister) []string {
	t.Helper()
	models, err := l.ListModels(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(models))
	for _, raw := range models {
		var e struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, e.ID)
	}
	return ids
}

// The endpoint list of 2026-11-13 serves z-ai/glm-5.3-flash-long, which the
// catalog does not list; teep lists it while the endpoint list serves it.
func TestModelListerExtraModels(t *testing.T) {
	if !slices.Contains(extraModels(), "z-ai/glm-5.3-flash-long") {
		t.Fatalf("extra models = %v", extraModels())
	}
	endpoints := func(models ...string) *Attester {
		t.Helper()
		body, err := json.Marshal(map[string]any{"endpoints": []any{
			map[string]any{"domain": "glm-5-3-flash-i0.completions.near.ai", "models": models},
		}})
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		}))
		t.Cleanup(srv.Close)
		r := newEndpointResolverForTest(srv.URL)
		r.client = srv.Client()
		t.Cleanup(r.Stop)
		return NewAttesterWithResolver("https://completions.near.ai", "key", r)
	}
	for _, tc := range []struct {
		name     string
		inner    staticLister
		want     []string
		attester func() *Attester
	}{
		{"served", staticLister{"z-ai/glm-5.3-flash"},
			[]string{"z-ai/glm-5.3-flash", "z-ai/glm-5.3-flash-long"},
			func() *Attester { return endpoints("z-ai/glm-5.3-flash", "z-ai/glm-5.3-flash-long") }},
		{"not served", staticLister{"z-ai/glm-5.3-flash"},
			[]string{"z-ai/glm-5.3-flash"},
			func() *Attester { return endpoints("z-ai/glm-5.3-flash") }},
		{"already in the catalog", staticLister{"z-ai/glm-5.3-flash-long"},
			[]string{"z-ai/glm-5.3-flash-long"},
			func() *Attester { return endpoints("z-ai/glm-5.3-flash-long") }},
		{"static origin", staticLister{"m"},
			[]string{"m"},
			func() *Attester { return NewAttester("https://backend.example:8443", "key") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := NewModelLister(tc.inner, tc.attester()).(*modelLister)
			if got := listedIDs(t, l); !slices.Equal(got, tc.want) {
				t.Errorf("models = %v, want %v", got, tc.want)
			}
		})
	}
}
