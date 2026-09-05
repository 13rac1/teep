package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct"
)

func TestIntegration_NearDirectHTTP2(t *testing.T) { testLiveNearHTTP2(t, "neardirect") }
func TestIntegration_NearCloudHTTP2(t *testing.T)  { testLiveNearHTTP2(t, "nearcloud") }

// This suite uses online serve policy. Observation is confined to the test
// transport and records connection metadata, never inference bodies or keys.
func testLiveNearHTTP2(t *testing.T, name string) {
	t.Helper()
	if testing.Short() || os.Getenv("NEARAI_API_KEY") == "" {
		t.Skip("live NEAR HTTP/2 tests require NEARAI_API_KEY and non-short mode")
	}
	origin := "https://completions.near.ai"
	if name == "nearcloud" {
		origin = "https://cloud-api.near.ai"
	}
	server, err := New(&config.Config{Providers: map[string]*config.Provider{
		name: {Name: name, BaseURL: origin, APIKey: os.Getenv("NEARAI_API_KEY"), E2EE: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	prov := server.providers[name]
	model := liveNearTextModel(ctx, t, prov)
	route, key, err := resolveRequestRoute(ctx, prov, model)
	if err != nil {
		t.Fatal("resolve live NEAR route failed")
	}
	attestationTrace := &nearTransportObservation{}
	attestationClient := config.NewAttestationClient(false)
	attestationClient.Transport = &observedNearTransport{base: attestationClient.Transport, observation: attestationTrace}
	defer attestationClient.CloseIdleConnections()
	setter, ok := prov.Attester.(interface{ SetClient(*http.Client) })
	if !ok {
		t.Fatal("attester does not expose its client")
	}
	setter.SetClient(attestationClient)
	value, blocked, err := server.loadAuthorization(ctx, prov, route, key)
	if err != nil || blocked != nil {
		t.Fatal("live NEAR attestation did not authorize inference; see factor diagnostics")
	}
	attestationTrace.assertHTTP2(t, value.identity)
	client, err := server.pinnedClientForIdentity(name, value.identity)
	if err != nil {
		t.Fatal(err)
	}
	inferenceTrace := &nearTransportObservation{}
	client.Transport = &observedNearTransport{base: client.Transport, observation: inferenceTrace}
	input := &authorizedRequest{provider: prov, route: route, key: key, path: prov.ChatPath, endpoint: e2ee.EndpointChat, contentType: "application/json"}
	// Both response modes must decrypt successfully and reuse the warm pool.
	for _, stream := range []bool{false, true} {
		if err := runLiveNearInference(ctx, server, input, stream); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			if err := runLiveNearInference(ctx, server, input, i%2 == 0); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	inferenceTrace.assertHTTP2(t, value.identity)
	inferenceTrace.assertReuseAndOverlap(t)
}

func liveNearTextModel(ctx context.Context, t *testing.T, prov *provider.Provider) string {
	t.Helper()
	models, err := prov.ModelLister.ListModels(ctx)
	if err != nil {
		t.Fatal("live NEAR model discovery failed")
	}
	wanted := strings.TrimPrefix(os.Getenv("NEARAI_E2EE_MODEL"), prov.Name+":")
	for _, raw := range models {
		var model struct {
			ID               string   `json:"id"`
			OutputModalities []string `json:"output_modalities"`
		}
		// The catalog has additional metadata; select only a text-output model.
		if _, _, err := jsonstrict.Unmarshal(raw, &model); err != nil || model.ID == "" {
			t.Fatal("invalid live NEAR model metadata")
		}
		if slices.Contains(model.OutputModalities, "text") && (wanted == "" || wanted == model.ID) {
			return model.ID
		}
	}
	t.Fatal("NEAR discovery contains no matching text-output model")
	return ""
}

func runLiveNearInference(ctx context.Context, server *Server, template *authorizedRequest, stream bool) error {
	input := *template
	input.stream = stream
	body, err := json.Marshal(map[string]any{"model": input.key.Model(), "messages": []map[string]string{{"role": "user", "content": "Say hello"}}, "stream": stream, "max_tokens": 64})
	if err != nil {
		return err
	}
	input.body = body
	out, err := server.inferAuthorized(ctx, newInferenceRecorder(), &input)
	if err != nil || out.status != "ok" {
		return errors.New("live NEAR encrypted inference failed; no response body is logged")
	}
	return nil
}

type nearTransportRecord struct {
	connection net.Conn
	reused     bool
	protocol   int
	identity   tlsct.TransportIdentity
	start, end time.Time
}

type nearTransportObservation struct {
	mu      sync.Mutex
	records []*nearTransportRecord
}

type observedNearTransport struct {
	base        http.RoundTripper
	observation *nearTransportObservation
}

func (t *observedNearTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (t *observedNearTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	o := t.observation
	record := &nearTransportRecord{}
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			o.mu.Lock()
			record.connection, record.reused = info.Conn, info.Reused
			o.mu.Unlock()
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				o.mu.Lock()
				record.start = time.Now()
				o.mu.Unlock()
			}
		},
	}
	resp, err := t.base.RoundTrip(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
	if err != nil {
		return resp, err
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		resp.Body.Close()
		return nil, errors.New("missing TLS peer")
	}
	fp := sha256.Sum256(resp.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
	identity, err := tlsct.NewTransportIdentity(req.URL.Host, hex.EncodeToString(fp[:]))
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	o.mu.Lock()
	record.protocol, record.identity = resp.ProtoMajor, identity
	o.records = append(o.records, record)
	o.mu.Unlock()
	resp.Body = &observedNearBody{ReadCloser: resp.Body, finish: func() { o.mu.Lock(); record.end = time.Now(); o.mu.Unlock() }}
	return resp, nil
}

type observedNearBody struct {
	io.ReadCloser
	finish func()
}

func (b *observedNearBody) Close() error { err := b.ReadCloser.Close(); b.finish(); return err }

func (o *nearTransportObservation) assertHTTP2(t *testing.T, identity tlsct.TransportIdentity) {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.records) == 0 {
		t.Fatal("no transport observations")
	}
	for _, record := range o.records {
		if record.protocol != 2 || !record.identity.Equal(identity) {
			t.Error("HTTP/2 transport identity differs from attested route")
		}
	}
}

func (o *nearTransportObservation) assertReuseAndOverlap(t *testing.T) {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.records) != 6 {
		t.Fatalf("inference observations=%d, want 6", len(o.records))
	}
	first, second := o.records[0], o.records[1]
	if first.connection != second.connection || !second.reused {
		t.Error("sequential inference did not reuse the connection")
	}
	for i, a := range o.records[2:] {
		for _, b := range o.records[2+i+1:] {
			if a.connection == b.connection && !a.start.IsZero() && !b.start.IsZero() && a.start.Before(b.end) && b.start.Before(a.end) {
				return
			}
		}
	}
	t.Error("concurrent inference did not overlap on an HTTP/2 connection")
}
