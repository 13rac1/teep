package attestation

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// nearComposeManagerFixture holds two instances of one NEAR model from one
// cloud-api.near.ai response: the instance quote and the
// compose_manager_attestation of each, and the client nonce.
type nearComposeManagerFixture struct {
	Nonce     string `json:"nonce"`
	Instances []struct {
		InstanceID     string          `json:"instance_id"`
		IntelQuote     string          `json:"intel_quote"`
		ComposeManager json.RawMessage `json:"compose_manager_attestation"`
	} `json:"instances"`
}

func loadComposeManagerFixture(t *testing.T) (nearComposeManagerFixture, Nonce) {
	t.Helper()
	data, err := os.ReadFile("testdata/near_compose_manager.json")
	if err != nil {
		t.Fatal(err)
	}
	var f nearComposeManagerFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	nonce, err := ParseNonce(f.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	return f, nonce
}

// offlineVerifier checks the certificate chain and signature of a quote
// without Intel PCS collateral.
var offlineVerifier = NewTDXVerifier(true, nil, time.Time{})

// composeFilesFixture is the GitHub side of the fixture: the compose file of
// every deployment in near_compose_manager.json by "commit/file".
type composeFilesFixture struct {
	Files map[string]string `json:"files"`
}

// serveComposeFiles serves GitHub's raw files from the fixture, edited by
// edit, and returns the server.
func serveComposeFiles(t *testing.T, edit func(*composeFilesFixture)) *httptest.Server {
	t.Helper()
	f, err := os.Open("testdata/near_compose_files.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var fx composeFilesFixture
	if err := json.NewDecoder(zr).Decode(&fx); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(&fx)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := fx.Files[strings.TrimPrefix(r.URL.Path, "/"+ComposeFilesRepo+"/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// onlineSources returns a ComposeSources that fetches from srv.
func onlineSources(srv *httptest.Server) *ComposeSources {
	return newComposeSources(srv.URL, srv.Client(), false)
}

// cmReport verifies the compose-manager evidence cm against the instance
// quote, with compose files from sources, and builds the report.
func cmReport(t *testing.T, sources *ComposeSources, instanceQuote string, cm []byte, nonce Nonce) (*ComposeManagerResult, map[string]FactorResult) {
	t.Helper()
	raw := &RawAttestation{BackendFormat: FormatNear, ComposeManagerAttestation: cm}
	r := VerifyComposeManager(context.Background(), raw, offlineVerifier(context.Background(), instanceQuote), nonce, offlineVerifier, sources)
	in := &ReportInput{Raw: raw, ComposeManager: r}
	out := map[string]FactorResult{}
	for _, eval := range []evaluatorFunc{evalComposeManagerQuote, evalComposeManagerTCB, evalComposeManagerActions} {
		f := eval(in)[0]
		out[f.Name] = f
	}
	return r, out
}

func wantStatus(t *testing.T, factors map[string]FactorResult, name string, want Status, detail string) {
	t.Helper()
	f := factors[name]
	if f.Status != want {
		t.Fatalf("%s = %v, want %v (%s)", name, f.Status, want, f.Detail)
	}
	if detail != "" && !strings.Contains(f.Detail, detail) {
		t.Fatalf("%s detail %q does not contain %q", name, f.Detail, detail)
	}
}

// editActions applies edit to the decoded compose_manager_attestation and
// re-encodes it.
func editActions(t *testing.T, cm []byte, edit func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(cm, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestComposeManagerCapturedInstances applies the rule to both instances of
// the captured response. Instance fccd496a deployed only published files that
// pin every image; instance 7bb9af0a still reports a GLM deployment of
// 5 Sep whose file builds its server image in the CVM.
func TestComposeManagerCapturedInstances(t *testing.T) {
	sources := onlineSources(serveComposeFiles(t, nil))
	f, nonce := loadComposeManagerFixture(t)
	for _, inst := range f.Instances {
		t.Run(inst.InstanceID, func(t *testing.T) {
			_, factors := cmReport(t, sources, inst.IntelQuote, inst.ComposeManager, nonce)
			wantStatus(t, factors, FactorCMQuote, Pass, "REPORTDATA = sha256(")
			wantStatus(t, factors, FactorCMTCB, Skip, "offline")
			if strings.HasPrefix(inst.InstanceID, "fccd496a") {
				wantStatus(t, factors, FactorCMActions, Pass, "7 compose files, each published at its commit of nearai/cvm-compose-files")
			} else {
				wantStatus(t, factors, FactorCMActions, Fail, "prod/GLM-5.3-Flash-SGL-TP4.yaml at 3e3fa7cb0a55")
				wantStatus(t, factors, FactorCMActions, Fail, "uses build")
			}
		})
	}
}

func TestComposeManagerTamperedActionLog(t *testing.T) {
	f, nonce := loadComposeManagerFixture(t)
	inst := f.Instances[0]
	cm := editActions(t, inst.ComposeManager, func(m map[string]any) {
		actions := m["actions"].([]any)
		last := actions[len(actions)-1].(map[string]any)
		last["services"] = []any{"exfiltrate"}
	})
	_, factors := cmReport(t, nil, inst.IntelQuote, cm, nonce)
	wantStatus(t, factors, FactorCMQuote, Fail, "is not sha256(actions)")
	wantStatus(t, factors, FactorCMActions, Fail, "not bound")
}

func TestComposeManagerDroppedAction(t *testing.T) {
	f, nonce := loadComposeManagerFixture(t)
	inst := f.Instances[0]
	cm := editActions(t, inst.ComposeManager, func(m map[string]any) {
		actions := m["actions"].([]any)
		m["actions"] = actions[1:]
	})
	_, factors := cmReport(t, nil, inst.IntelQuote, cm, nonce)
	wantStatus(t, factors, FactorCMQuote, Fail, "is not sha256(actions)")
}

func TestComposeManagerWrongNonce(t *testing.T) {
	f, nonce := loadComposeManagerFixture(t)
	inst := f.Instances[0]
	nonce[0] ^= 1
	_, factors := cmReport(t, nil, inst.IntelQuote, inst.ComposeManager, nonce)
	wantStatus(t, factors, FactorCMQuote, Fail, "|| nonce")
	wantStatus(t, factors, FactorCMActions, Fail, "not bound")
}

// TestComposeManagerOtherInstance gives instance A the genuine, fresh and
// correctly bound compose-manager attestation of instance B, from another
// TD of the same model.
func TestComposeManagerOtherInstance(t *testing.T) {
	f, nonce := loadComposeManagerFixture(t)
	a, b := f.Instances[0], f.Instances[1]
	_, factors := cmReport(t, nil, a.IntelQuote, b.ComposeManager, nonce)
	wantStatus(t, factors, FactorCMQuote, Fail, "not from the instance TD")
	wantStatus(t, factors, FactorCMActions, Fail, "not bound")
}

// passingInstance is the captured instance whose log the rule accepts.
func passingInstance(t *testing.T) (string, []byte, Nonce) {
	t.Helper()
	f, nonce := loadComposeManagerFixture(t)
	for _, inst := range f.Instances {
		if strings.HasPrefix(inst.InstanceID, "fccd496a") {
			return inst.IntelQuote, inst.ComposeManager, nonce
		}
	}
	t.Fatal("no instance fccd496a")
	return "", nil, nonce
}

func TestComposeManagerRuleRefusals(t *testing.T) {
	const commit = "30fbba879f83dcd046f1b5e5f47c827e57dfdc1c"
	const file = commit + "/prod/deepseek-v4.1-flash-1017-vllm-dep4x2.yaml"
	const proxy = "nearaidev/vllm-proxy-rs@sha256:e3a4fbcacdf83f83212d4c6c0ad4d766d602b88c004dc82a2dd4ae147dccde94"
	for _, tc := range []struct {
		name string
		edit func(*composeFilesFixture)
		want string
	}{
		{"unknown commit", func(fx *composeFilesFixture) {
			maps.DeleteFunc(fx.Files, func(k, _ string) bool { return strings.HasPrefix(k, commit+"/") })
		}, "HTTP 404"},
		{"file not published", func(fx *composeFilesFixture) { delete(fx.Files, file) }, "HTTP 404"},
		{"foreign image", func(fx *composeFilesFixture) {
			fx.Files[file] = strings.Replace(fx.Files[file], proxy, "attacker/proxy@sha256:"+strings.Repeat("0", 64), 1)
		}, "published file hashes to"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			quote, cm, nonce := passingInstance(t)
			_, factors := cmReport(t, onlineSources(serveComposeFiles(t, tc.edit)), quote, cm, nonce)
			wantStatus(t, factors, FactorCMQuote, Pass, "")
			wantStatus(t, factors, FactorCMActions, Fail, tc.want)
		})
	}
	t.Run("offline", func(t *testing.T) {
		srv := serveComposeFiles(t, nil)
		quote, cm, nonce := passingInstance(t)
		raw := &RawAttestation{BackendFormat: FormatNear, ComposeManagerAttestation: cm}
		r := VerifyComposeManager(context.Background(), raw, offlineVerifier(context.Background(), quote), nonce, offlineVerifier, newComposeSources(srv.URL, srv.Client(), true))
		if r.SourceErr == nil || !strings.Contains(r.SourceErr.Error(), "offline") {
			t.Fatalf("SourceErr = %v, want offline", r.SourceErr)
		}
	})
	t.Run("github unreachable", func(t *testing.T) {
		srv := serveComposeFiles(t, nil)
		quote, cm, nonce := passingInstance(t)
		_, factors := cmReport(t, newComposeSources("https://127.0.0.1:1", srv.Client(), false), quote, cm, nonce)
		wantStatus(t, factors, FactorCMActions, Fail, "127.0.0.1:1")
	})
}

func TestComposeManagerComposeImages(t *testing.T) {
	pinned := "a/b@sha256:" + strings.Repeat("ab", 32)
	for _, tc := range []struct {
		name, yaml, err string
	}{
		{"ok", "services:\n  a:\n    image: " + pinned + "\n  b:\n    image: nginx:1.29@sha256:" + strings.Repeat("cd", 32) + "\n", ""},
		{"anchor", "x: &img\n  image: " + pinned + "\nservices:\n  a:\n    <<: *img\n", ""},
		{"tag", "services:\n  a:\n    image: a/b:latest\n", "not pinned by digest"},
		{"interpolated", "services:\n  a:\n    image: ${IMG:-" + pinned + "}\n", "not pinned by digest"},
		{"no image", "services:\n  a:\n    command: x\n", "not pinned by digest"},
		{"build", "services:\n  a:\n    image: " + pinned + "\n    build: .\n", "uses build"},
		{"extends", "services:\n  a:\n    image: " + pinned + "\n    extends: {file: b.yaml, service: a}\n", "uses extends"},
		{"include", "include: [b.yaml]\nservices:\n  a:\n    image: " + pinned + "\n", "include"},
		{"no services", "volumes: {}\n", "no services"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkComposeImages([]byte(tc.yaml))
			if (err == nil) != (tc.err == "") || (err != nil && !strings.Contains(err.Error(), tc.err)) {
				t.Fatalf("err = %v, want %q", err, tc.err)
			}
		})
	}
}

func TestComposeManagerDeploymentsRules(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	commit := strings.Repeat("c", 40)
	img := "nearaidev/compose-manager@sha256:" + sha
	started := ComposeManagerAction{Action: "compose_manager_started", Image: img}
	up := ComposeManagerAction{Action: "compose_up", Commit: commit, File: "prod/a.yaml", FileSHA256: sha}
	stage := up
	stage.Action = "compose_stage"
	quiet := []ComposeManagerAction{}
	for _, a := range []string{"compose_down", "docker_restart", "docker_clean", "docker_evict", "launcher_restart",
		"dstack_agent_restart", "kernel_algif_blacklist_ok", "env_override_set", "env_override_unset"} {
		quiet = append(quiet, ComposeManagerAction{Action: a})
	}
	for _, tc := range []struct {
		name    string
		actions []ComposeManagerAction
		err     string
	}{
		{"ok", append([]ComposeManagerAction{stage, up, started}, quiet...), ""},
		{"unknown action", []ComposeManagerAction{{Action: "docker_build"}, started}, "unknown action"},
		{"no start", []ComposeManagerAction{up}, "no compose_manager_started"},
		{"up without hash", []ComposeManagerAction{{Action: "compose_up", Commit: commit, File: "a"}, started}, "file_sha256"},
		{"uppercase hash", []ComposeManagerAction{{Action: "compose_up", Commit: commit, File: "a", FileSHA256: strings.ToUpper(sha)}, started}, "file_sha256"},
		{"tag as commit", []ComposeManagerAction{{Action: "compose_up", Commit: "v0.0.620", File: "a", FileSHA256: sha}, started}, "commit"},
		{"no file", []ComposeManagerAction{{Action: "compose_up", Commit: commit, FileSHA256: sha}, started}, "no file"},
		{"image by tag", []ComposeManagerAction{{Action: "compose_manager_started", Image: "nearaidev/compose-manager:latest"}}, "not nearaidev/compose-manager pinned by digest"},
		{"foreign compose-manager", []ComposeManagerAction{{Action: "compose_manager_started", Image: "attacker/compose-manager@sha256:" + sha}}, "not nearaidev/compose-manager"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps, _, err := ComposeManagerDeployments(tc.actions)
			if (err == nil) != (tc.err == "") || (err != nil && !strings.Contains(err.Error(), tc.err)) {
				t.Fatalf("err = %v, want %q", err, tc.err)
			}
			if tc.err == "" && len(deps) != 1 {
				t.Fatalf("deployments = %v, want one", deps)
			}
		})
	}
}

func TestComposeManagerEvidenceParse(t *testing.T) {
	evidence := func(actions string, extra string) []byte {
		return []byte(fmt.Sprintf(`{"actions":%s,"actions_hash":"","nonce":"","nonce_source":"client","quote":"","event_log":"","report_data":""%s}`, actions, extra))
	}
	var many strings.Builder
	many.WriteByte('[')
	for i := range maxComposeManagerActions + 1 {
		if i > 0 {
			many.WriteByte(',')
		}
		many.WriteString(`{"timestamp":"t","action":"compose_down"}`)
	}
	many.WriteByte(']')
	for _, tc := range []struct {
		name string
		data []byte
		err  string
	}{
		{"absent", nil, "no compose_manager_attestation"},
		{"ok", evidence(`[{"timestamp":"t","action":"compose_down","services":["a"]}]`, ""), ""},
		{"null actions", evidence(`null`, ""), "actions"},
		{"too many", []byte(evidence(many.String(), "")), "more than"},
		{"null service", evidence(`[{"timestamp":"t","action":"compose_down","services":[null]}]`, ""), "services"},
		{"number service", evidence(`[{"timestamp":"t","action":"compose_down","services":[1]}]`, ""), "services"},
		{"unknown action member", evidence(`[{"timestamp":"t","action":"compose_down","env":"x"}]`, ""), "unknown members"},
		{"unknown member", evidence(`[]`, `,"extra":1`), "unknown members"},
		{"duplicate member", evidence(`[{"timestamp":"t","action":"compose_down","action":"compose_up"}]`, ""), "duplicate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := parseComposeManager(tc.data)
			if (err == nil) != (tc.err == "") || (err != nil && !strings.Contains(err.Error(), tc.err)) {
				t.Fatalf("err = %v, want %q", err, tc.err)
			}
		})
	}
}

func TestComposeManagerCanonicalJSON(t *testing.T) {
	got, err := canonicalJSON([]byte(`[ {"b": "<&> é", "a": ["x"]} ]`))
	if err != nil {
		t.Fatal(err)
	}
	if want := `[{"a":["x"],"b":"<&> é"}]`; string(got) != want {
		t.Fatalf("canonical = %s, want %s", got, want)
	}
}

func TestComposeManagerNotApplicableOrMissing(t *testing.T) {
	in := &ReportInput{Raw: &RawAttestation{BackendFormat: FormatDstack}}
	if got := evalComposeManagerQuote(in)[0].Status; got != NotApplicable {
		t.Fatalf("dstack: %v, want N/A", got)
	}
	raw := &RawAttestation{BackendFormat: FormatNear}
	if r := VerifyComposeManager(context.Background(), &RawAttestation{BackendFormat: FormatDstack}, nil, Nonce{}, offlineVerifier, nil); r != nil {
		t.Fatalf("dstack result = %+v, want nil", r)
	}
	r := VerifyComposeManager(context.Background(), raw, nil, Nonce{}, offlineVerifier, nil)
	in = &ReportInput{Raw: raw, ComposeManager: r}
	for _, eval := range []evaluatorFunc{evalComposeManagerQuote, evalComposeManagerTCB, evalComposeManagerActions} {
		if f := eval(in)[0]; f.Status != Fail || !strings.Contains(f.Detail, "no compose_manager_attestation") {
			t.Fatalf("%s = %v (%s), want Fail", f.Name, f.Status, f.Detail)
		}
	}
	in.ComposeManager = nil
	if f := evalComposeManagerActions(in)[0]; f.Status != Fail {
		t.Fatalf("unverified: %v, want Fail", f.Status)
	}
}

// TestComposeSourcesConcurrentCheck checks the deployments of the passing
// instance from several goroutines on one ComposeSources, then again with
// GitHub closed: accepted files are not fetched again.
func TestComposeSourcesConcurrentCheck(t *testing.T) {
	srv := serveComposeFiles(t, nil)
	sources := onlineSources(srv)
	_, cm, _ := passingInstance(t)
	_, actions, _, err := parseComposeManager(cm)
	if err != nil {
		t.Fatal(err)
	}
	deps, _, err := ComposeManagerDeployments(actions)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { errs <- sources.Check(t.Context(), deps) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	srv.Close()
	if err := sources.Check(t.Context(), deps); err != nil {
		t.Fatalf("accepted files fetched again: %v", err)
	}
}
