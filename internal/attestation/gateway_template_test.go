package attestation

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The private-ai-gateway composes the observatory recorded from 15 Oct to 17
// Nov (a baseline and nine changes) and the one live on 22 Nov, in order.
// testdata/aci_gateway holds each raw app_compose, named by its sha256, and
// releases.json the commit and OS measurements its quote carried.
type gatewayRelease struct {
	ComposeHash string `json:"compose_hash"`
	Commit      string `json:"commit"`
	OSImage     string `json:"os_image"`
	MRTD        string `json:"mrtd"`
	MRSeam      string `json:"mrseam"`
	RTMR1       string `json:"rtmr1"`
	RTMR2       string `json:"rtmr2"`
	compose     string
}

const (
	gatewayLauncher = "c083ff9e6a5ddf10f6c9e9bb1f74cc618deebecfea5208b563c574399db4637c"
	// gatewayTemplateNow is the template of the composes live since 6 Nov.
	gatewayTemplateNow = "23ee06d72660205482a5528f26accc4f49354c53395cbda5e0bcd0432c4c8e79"
	// branchOnlyCommit is on a branch of the gateway repository but not on
	// its default branch.
	branchOnlyCommit = "9c2b3bceee4ab284c442efdaf667cf465218383c"
)

// gatewayTemplatesRecorded are the five templates of the ten changes.
var gatewayTemplatesRecorded = []string{
	"ea6bf364600d1c6a85fdf4fe36003a342151e79e1434b2b182afc688cc732f31", // 303472: adds privatemode-proxy
	"c4cb789bc0b942c90ddc350cf709b74bbe8efa976fbcb91d1f7c778d30d076c5", // 170fb2: dstack-ingress 2.8, no CAA
	"026cd26525b6d9807b05afaef7ebb6707caeddf8008355c639bc67a7675efb84", // 4dbdcd: drops DSTACK_ROOT_PUBLIC_KEY, new proxy flags
	"a2f41ed5383641151f007cbd369f036ef513d80618bcbb9b217f88b31dd3e484", // aa767d: allows DSTACK_ROOT_PUBLIC_KEY again
	gatewayTemplateNow, // 66e91a: pre-launch script v0.0.20, new Privatemode credential
}

func loadGatewayReleases(t *testing.T) []gatewayRelease {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "aci_gateway", "releases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rels []gatewayRelease
	if err := json.Unmarshal(b, &rels); err != nil {
		t.Fatal(err)
	}
	for i := range rels {
		f, err := os.Open(filepath.Join("testdata", "aci_gateway", rels[i].ComposeHash+".json.gz"))
		if err != nil {
			t.Fatal(err)
		}
		zr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(zr)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != rels[i].ComposeHash {
			t.Fatalf("fixture %s does not hash to its name", rels[i].ComposeHash)
		}
		rels[i].compose = string(raw)
	}
	if len(rels) != 11 {
		t.Fatalf("%d recorded composes, want 11", len(rels))
	}
	return rels
}

// fakeGitHub answers compare HEAD...<commit> for the gateway repository:
// "behind" for published commits, "diverged" for branchOnlyCommit, 404
// otherwise.
func fakeGitHub(t *testing.T, published []string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := "/repos/Dstack-TEE/private-ai-gateway/compare/HEAD..."
		commit, ok := strings.CutPrefix(r.URL.Path, prefix)
		var status string
		switch {
		case ok && commit == branchOnlyCommit:
			status = "diverged"
		case ok && strings.Contains(strings.Join(published, " "), commit):
			status = "behind"
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
	}))
	old := GitHubAPIURL
	GitHubAPIURL = srv.URL
	publishedCommits.Clear()
	t.Cleanup(func() {
		srv.Close()
		GitHubAPIURL = old
		publishedCommits.Clear()
	})
	return srv
}

func hexSet(t *testing.T, values ...string) map[string]struct{} {
	t.Helper()
	m := map[string]struct{}{}
	for _, v := range values {
		m[v] = struct{}{}
	}
	return m
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// gatewayInput is the gateway half of a report for one recorded release,
// with CheckGatewaySource run against srv.
func gatewayInput(t *testing.T, srv *httptest.Server, rel *gatewayRelease, policy MeasurementPolicy) *ReportInput {
	t.Helper()
	tdx := &TDXVerifyResult{MRTD: mustHex(t, rel.MRTD), MRSeam: mustHex(t, rel.MRSeam)}
	copy(tdx.RTMRs[1][:], mustHex(t, rel.RTMR1))
	copy(tdx.RTMRs[2][:], mustHex(t, rel.RTMR2))
	return &ReportInput{
		Raw:            &RawAttestation{GatewayAppCompose: rel.compose},
		GatewayTDX:     tdx,
		GatewayCompose: &ComposeBindingResult{Checked: true},
		GatewaySource:  CheckGatewaySource(context.Background(), srv.Client(), rel.compose, policy, false),
		GatewayPolicy:  policy,
	}
}

func gatewayRulePolicy(t *testing.T, templates []string, rels []gatewayRelease) MeasurementPolicy {
	t.Helper()
	p := MeasurementPolicy{
		Compose: &GatewayComposePolicy{
			TemplateAllow:       hexSet(t, templates...),
			LauncherDigestAllow: hexSet(t, gatewayLauncher),
		},
		MRTDAllow:   map[string]struct{}{},
		MRSeamAllow: map[string]struct{}{},
	}
	p.RTMRAllow[1] = map[string]struct{}{}
	p.RTMRAllow[2] = map[string]struct{}{}
	for i := range rels {
		r := &rels[i]
		p.MRTDAllow[r.MRTD] = struct{}{}
		p.MRSeamAllow[r.MRSeam] = struct{}{}
		p.RTMRAllow[1][r.RTMR1] = struct{}{}
		p.RTMRAllow[2][r.RTMR2] = struct{}{}
	}
	return p
}

// TestGatewayComposeTemplateReplay checks every recorded gateway change
// against one rule: the five recorded templates, the one launcher, a commit
// published on the default branch, and the OS measurements of dstack 0.5.9
// and 0.5.12.
func TestGatewayComposeTemplateReplay(t *testing.T) {
	rels := loadGatewayReleases(t)
	commits := make([]string, 0, len(rels))
	for i := range rels {
		commits = append(commits, rels[i].Commit)
	}
	srv := fakeGitHub(t, commits)
	policy := gatewayRulePolicy(t, gatewayTemplatesRecorded, rels)

	if len(policy.MRTDAllow) != 2 || len(policy.RTMRAllow[1]) != 2 || len(policy.RTMRAllow[2]) != 2 {
		t.Fatalf("want the OS measurements of two dstack releases, got MRTD %d RTMR1 %d RTMR2 %d",
			len(policy.MRTDAllow), len(policy.RTMRAllow[1]), len(policy.RTMRAllow[2]))
	}
	sameTemplate := 0
	prev, err := ParseGatewayComposeTemplate(rels[0].compose)
	if err == nil || !strings.Contains(err.Error(), "privatemode") {
		t.Fatalf("baseline has no privatemode-proxy and should not fit the template: %v %s", err, prev.Hash)
	}
	for i := range rels[1:] {
		rel := &rels[i+1]
		tmpl, err := ParseGatewayComposeTemplate(rel.compose)
		if err != nil {
			t.Fatalf("%s: %v", rel.ComposeHash[:8], err)
		}
		if tmpl.Commit != rel.Commit || tmpl.Repo != "Dstack-TEE/private-ai-gateway" || tmpl.LauncherDigest != gatewayLauncher {
			t.Errorf("%s: slots %+v disagree with the attested source %s", rel.ComposeHash[:8], tmpl, rel.Commit)
		}
		if tmpl.Hash == prev.Hash {
			sameTemplate++
		}
		prev = tmpl
		in := gatewayInput(t, srv, rel, policy)
		for _, got := range [][]FactorResult{evalGatewayComposeBinding(in), evalGatewayMeasurement(in), evalGatewayBootConfig(in)} {
			if got[0].Status != Pass {
				t.Errorf("%s (%s): %s %v: %s", rel.ComposeHash[:8], rel.OSImage, got[0].Name, got[0].Status, got[0].Detail)
			}
		}
	}
	// Changes that kept the template of the compose before them, and so
	// needed no new template entry: 59841f, 3dcf9d, 04d79a and 261760.
	// f9c6a9 returned to an earlier template.
	if sameTemplate != 4 {
		t.Errorf("%d changes kept the previous template, want 4", sameTemplate)
	}
}

// TestGatewayComposeTemplateRefusals starts from the compose live on 22 Nov
// under a table that lists only the current template.
func TestGatewayComposeTemplateRefusals(t *testing.T) {
	rels := loadGatewayReleases(t)
	now := rels[len(rels)-1]
	srv := fakeGitHub(t, []string{now.Commit})
	policy := gatewayRulePolicy(t, []string{gatewayTemplateNow}, rels[len(rels)-1:])
	otherDigest := strings.Repeat("ab", 32)

	edit := func(old, repl string) func(string) string {
		return func(s string) string {
			if strings.Count(s, old) != 1 {
				t.Fatalf("anchor %q occurs %d times", old, strings.Count(s, old))
			}
			return strings.Replace(s, old, repl, 1)
		}
	}
	tests := []struct {
		name    string
		compose func(string) string
		want    string
	}{
		{"current", func(s string) string { return s }, ""},
		{"other launcher", edit(gatewayLauncher, otherDigest), "gateway_launcher_digest_allow"},
		{"commit on a branch only", edit(now.Commit, branchOnlyCommit), "not on the default branch"},
		{"unknown commit", edit(now.Commit, strings.Repeat("0", 40)), "HTTP 404"},
		{"extra service", edit(`\n  dstack-verifier:\n`, `\n  extra:\n    image: alpine@sha256:`+otherDigest+`\n\n  dstack-verifier:\n`), "gateway_compose_template_allow"},
		{"root key allowed", edit(`"allowed_envs":[`, `"allowed_envs":["DSTACK_ROOT_PUBLIC_KEY",`), "gateway_compose_template_allow"},
		{"other ingress", edit(`dstack-ingress:2.8@sha256:60e6`, `dstack-ingress:2.8@sha256:60e7`), "gateway_compose_template_allow"},
		{"privatemode digests disagree", edit(`privatemode-proxy@sha256:cf04`, `privatemode-proxy@sha256:cf05`), "its config names"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rel := now
			rel.compose = tt.compose(now.compose)
			got := evalGatewayComposeBinding(gatewayInput(t, srv, &rel, policy))[0]
			switch {
			case tt.want == "" && got.Status != Pass:
				t.Fatalf("want Pass, got %v: %s", got.Status, got.Detail)
			case tt.want != "" && (got.Status != Fail || !strings.Contains(got.Detail, tt.want)):
				t.Fatalf("want Fail naming %q, got %v: %s", tt.want, got.Status, got.Detail)
			}
		})
	}

	// The 21 Oct compose allowed DSTACK_ROOT_PUBLIC_KEY; today's table refuses it.
	got := evalGatewayComposeBinding(gatewayInput(t, srv, &rels[5], policy))[0]
	if got.Status != Fail || !strings.Contains(got.Detail, "gateway_compose_template_allow") {
		t.Errorf("aa767d: want Fail on its template, got %v: %s", got.Status, got.Detail)
	}
}

// TestCheckGatewaySourceFailsClosed shows the failure mode: a commit GitHub
// has not confirmed in this process is refused offline or with GitHub down,
// and a confirmed one is not asked about again.
func TestCheckGatewaySourceFailsClosed(t *testing.T) {
	rels := loadGatewayReleases(t)
	now := rels[len(rels)-1]
	srv := fakeGitHub(t, []string{now.Commit})
	policy := gatewayRulePolicy(t, []string{gatewayTemplateNow}, rels[len(rels)-1:])
	ctx := context.Background()

	if r := CheckGatewaySource(ctx, srv.Client(), now.compose, MeasurementPolicy{}, false); r != nil {
		t.Fatalf("no template policy: want nil, got %+v", r)
	}
	if r := CheckGatewaySource(ctx, srv.Client(), now.compose, policy, true); r.Err == nil {
		t.Fatal("offline and unconfirmed: want an error")
	}
	client := srv.Client()
	if r := CheckGatewaySource(ctx, client, now.compose, policy, false); r.Err != nil {
		t.Fatalf("published: %v", r.Err)
	}
	srv.Close()
	if r := CheckGatewaySource(ctx, client, now.compose, policy, false); r.Err != nil {
		t.Fatalf("confirmed earlier, GitHub down: %v", r.Err)
	}
	publishedCommits.Clear()
	if r := CheckGatewaySource(ctx, client, now.compose, policy, false); r.Err == nil {
		t.Fatal("unconfirmed, GitHub down: want an error")
	}
}
