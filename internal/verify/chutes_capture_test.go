package verify

import (
	"context"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"path"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/config"
)

const chutesFixture = "../integration/testdata/current/chutes_chutes"

// noDialContext returns a context whose HTTP requests fail the test and
// cancel the context when a real transport starts to get a connection. The
// replay transport does not get connections, so a replay must not trigger it.
func noDialContext(t *testing.T) (context.Context, *atomic.Int32) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	var dials atomic.Int32
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			dials.Add(1)
			t.Errorf("replay opened a network connection to %s", hostPort)
			cancel()
		},
	}), &dials
}

func chutesReplayLoader(string) (*config.Config, *config.Provider, error) {
	cp := &config.Provider{Name: "chutes", BaseURL: "https://api.chutes.ai", E2EE: true}
	cfg := &config.Config{
		Providers:         map[string]*config.Provider{"chutes": cp},
		ProviderAllowFail: map[string][]string{"chutes": config.ProviderDefaultAllowFail()["chutes"]},
	}
	return cfg, cp, nil
}

// chuteIDFromEntries returns the chute UUID from the captured instances request.
func chuteIDFromEntries(t *testing.T, entries []capture.RecordedEntry) string {
	t.Helper()
	for i := range entries {
		u, err := url.Parse(entries[i].URL)
		if err == nil && strings.HasPrefix(u.Path, "/e2e/instances/") {
			return path.Base(u.Path)
		}
	}
	t.Fatal("no instances request in the fixture")
	return ""
}

// copyChutesCapture saves the fixture in a temporary directory, with a
// /v1/models exchange when withModels is true.
func copyChutesCapture(t *testing.T, withModels bool) string {
	t.Helper()
	m, entries, err := capture.Load(chutesFixture)
	if err != nil {
		t.Fatal(err)
	}
	const modelsURL = "https://llm.chutes.ai/v1/models"
	recorded := false
	kept := entries[:0]
	for i := range entries {
		if entries[i].URL == modelsURL {
			recorded = true
			if !withModels {
				continue
			}
		}
		kept = append(kept, entries[i])
	}
	entries = kept
	if withModels && !recorded {
		entries = append(entries, capture.RecordedEntry{
			Method:  http.MethodGet,
			URL:     "https://llm.chutes.ai/v1/models",
			Status:  http.StatusOK,
			Headers: http.Header{"Content-Type": {"application/json"}},
			Body: []byte(`{"object":"list","data":[{"id":"` + m.Model + `","chute_id":"` +
				chuteIDFromEntries(t, entries) + `","object":"model"}]}`),
		})
	}
	dir, err := capture.Save(t.TempDir(), &m, "", entries)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// A chutes capture with the /v1/models exchange replays without a network
// connection: model-name resolution uses the replay client.
func TestChutesReplayResolvesModelFromCapture(t *testing.T) {
	dir := copyChutesCapture(t, true)
	ctx, dials := noDialContext(t)
	report, _, err := Replay(ctx, dir, chutesReplayLoader)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if report == nil || report.Model == "" {
		t.Fatalf("Replay returned no report: %+v", report)
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("replay opened %d network connections", n)
	}
}

// A capture without the /v1/models exchange (the fixture with that exchange
// removed) fails replay and names the missing exchange; it sends no live
// request.
func TestChutesReplayWithoutModelListFails(t *testing.T) {
	dir := copyChutesCapture(t, false)
	ctx, dials := noDialContext(t)
	_, _, err := Replay(ctx, dir, chutesReplayLoader)
	if err == nil {
		t.Fatal("Replay succeeded without the /v1/models exchange")
	}
	for _, want := range []string{"resolve model", "https://llm.chutes.ai/v1/models", "replay: no matching entry"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Replay error %q does not contain %q", err, want)
		}
	}
	if n := dials.Load(); n != 0 {
		t.Fatalf("replay opened %d network connections", n)
	}
}
