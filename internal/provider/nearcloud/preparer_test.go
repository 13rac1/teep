package nearcloud_test

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/nearcloud"
	"github.com/13rac1/teep/internal/provider/neardirect"
)

func TestPreparerUsesCanonicalAuthenticatedModelKey(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	defer clear(private)
	key := hex.EncodeToString(private.Public().(ed25519.PublicKey))
	preparer := nearcloud.NewPreparer("test")
	modelKey, err := e2ee.ParseNearModelKey(strings.ToUpper(key))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			req := httptest.NewRequest(http.MethodPost, "https://cloud-api.near.ai/v1/chat/completions", http.NoBody)
			req.Header["x-model-pub-key"] = []string{"untrusted", "duplicate"}
			req.Header.Set("X-Model-Pub-Key", "untrusted")
			if err := preparer.PrepareRequest(req, nil, nil, false, "/v1/chat/completions", provider.PreparationData{ModelKey: modelKey}); err != nil {
				t.Error(err)
				return
			}
			count := 0
			for name, values := range req.Header {
				if http.CanonicalHeaderKey(name) == "X-Model-Pub-Key" {
					count += len(values)
				}
			}
			if count != 1 || subtle.ConstantTimeCompare([]byte(req.Header.Get("X-Model-Pub-Key")), []byte(key)) != 1 {
				t.Error("routing hint is not the canonical acquired key")
			}
			if req.Header.Get("X-Encryption-Version") != "" {
				t.Error("routing hint enabled E2EE")
			}
		})
	}
	wg.Wait()
}

func TestNearCloudPreparationBothModes(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	defer clear(private)
	key := hex.EncodeToString(private.Public().(ed25519.PublicKey))
	route, err := provider.NewResolvedRoute("https://cloud-api.near.ai", "")
	if err != nil {
		t.Fatal(err)
	}
	modelKey, err := e2ee.ParseNearModelKey(strings.ToUpper(key))
	if err != nil {
		t.Fatal(err)
	}
	for _, encrypted := range []bool{false, true} {
		prov := &provider.Provider{Name: "nearcloud", E2EE: encrypted, Encryptor: neardirect.NewE2EE(), Preparer: nearcloud.NewPreparer("test")}
		for _, endpoint := range []struct {
			path string
			kind e2ee.EndpointType
			body string
		}{
			{"/v1/chat/completions", e2ee.EndpointChat, `{"model":"model","messages":[{"role":"user","content":"hello"}]}`},
			{"/v1/embeddings", e2ee.EndpointEmbeddings, `{"model":"model","input":"hello"}`},
		} {
			req, result, err := provider.PrepareInference(context.Background(), prov, route, &provider.InferenceInput{Body: []byte(endpoint.body), ModelKey: modelKey, Path: endpoint.path, ContentType: "application/json", Endpoint: endpoint.kind})
			if err != nil {
				t.Fatal(err)
			}
			if subtle.ConstantTimeCompare([]byte(req.Header.Get("X-Model-Pub-Key")), []byte(key)) != 1 {
				t.Error("preparation did not use the authenticated model key")
			}
			if (result.Session != nil) != encrypted {
				t.Error("wrong encryption mode")
			}
			e2ee.ZeroSessions(result.Session, result.Chutes, result.EHBP)
		}
	}
	for _, encrypted := range []bool{false, true} {
		for _, key := range []string{"", "invalid", strings.Repeat("zz", 32), key} {
			prov := &provider.Provider{Name: "nearcloud", E2EE: encrypted, Encryptor: neardirect.NewE2EE(), Preparer: nearcloud.NewPreparer("test")}
			_, result, err := provider.PrepareInference(t.Context(), prov, route, &provider.InferenceInput{Body: []byte(`{"model":"model","messages":[{"role":"user","content":"test"}]}`), SigningKey: key, Path: "/v1/chat/completions", Endpoint: e2ee.EndpointChat})
			e2ee.ZeroSessions(result.Session, result.Chutes, result.EHBP)
			if err == nil {
				t.Fatal("accepted absent typed routing key or used raw string key")
			}
		}
	}
	req := httptest.NewRequest(http.MethodPost, "https://cloud-api.near.ai/v1/chat/completions", http.NoBody)
	if err := nearcloud.NewPreparer("test").PrepareRequest(req, nil, nil, false, "/v1/chat/completions", provider.PreparationData{}); err == nil {
		t.Fatal("accepted zero validated routing key")
	}
}
