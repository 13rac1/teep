package attestation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"
)

// gatewayTemplateSlots are the values of the private-ai-gateway app_compose
// that a gateway release may change without changing its template: the
// gateway source commit, the config revision label, and the image digests of
// the launcher, the dstack-verifier sidecar and the Privatemode proxy (named
// twice: in its service and in the gateway config). Each must occur exactly
// once. Everything else in the app_compose, including the pre-launch script,
// allowed_envs, the service set and the dstack-ingress image, is fixed by the
// template hash.
var gatewayTemplateSlots = []struct {
	name string
	re   *regexp.Regexp
}{
	{"commit", regexp.MustCompile(`PRIVATE_AI_GATEWAY_REPO_COMMIT=([0-9a-f]{40})`)},
	{"config_rev", regexp.MustCompile(`private-ai-gateway\.config-rev: \\"(\d+)\\"`)},
	{"launcher", regexp.MustCompile(`image: ghcr\.io/redpill-ai/private-ai-launcher@sha256:([0-9a-f]{64})`)},
	{"verifier", regexp.MustCompile(`image: ghcr\.io/dstack-tee/dstack-verifier:([0-9A-Za-z._-]+@sha256:[0-9a-f]{64})`)},
	{"privatemode", regexp.MustCompile(`image: ghcr\.io/edgelesssys/privatemode/privatemode-proxy@sha256:([0-9a-f]{64})`)},
	{"privatemode_config", regexp.MustCompile(`\\"proxy_image_digest\\": \\"sha256:([0-9a-f]{64})\\"`)},
}

var gatewayRepoRe = regexp.MustCompile(`PRIVATE_AI_GATEWAY_REPO_URL=https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\.git\\n`)

// GatewayComposeTemplate is an ACI gateway app_compose split into its
// template and its slot values.
type GatewayComposeTemplate struct {
	// Hash is the hex sha256 of the raw app_compose with each slot value
	// replaced by "{" + slot name + "}".
	Hash           string
	Repo           string // owner/name on github.com
	Commit         string
	LauncherDigest string
}

// ParseGatewayComposeTemplate splits a raw private-ai-gateway app_compose
// into its template hash and slot values.
func ParseGatewayComposeTemplate(appCompose string) (GatewayComposeTemplate, error) {
	var t GatewayComposeTemplate
	repos := gatewayRepoRe.FindAllStringSubmatch(appCompose, -1)
	if len(repos) != 1 {
		return t, fmt.Errorf("gateway app_compose names %d GitHub source repositories, want 1", len(repos))
	}
	t.Repo = repos[0][1]
	vals := map[string]string{}
	s := appCompose
	for _, slot := range gatewayTemplateSlots {
		loc := slot.re.FindAllStringSubmatchIndex(s, -1)
		if len(loc) != 1 {
			return t, fmt.Errorf("gateway app_compose has %d %s slots, want 1", len(loc), slot.name)
		}
		vals[slot.name] = s[loc[0][2]:loc[0][3]]
		s = s[:loc[0][2]] + "{" + slot.name + "}" + s[loc[0][3]:]
	}
	if vals["privatemode"] != vals["privatemode_config"] {
		return t, fmt.Errorf("gateway app_compose runs privatemode-proxy %s but its config names %s",
			vals["privatemode"], vals["privatemode_config"])
	}
	sum := sha256.Sum256([]byte(s))
	t.Hash = hex.EncodeToString(sum[:])
	t.Commit = vals["commit"]
	t.LauncherDigest = vals["launcher"]
	return t, nil
}

// GitHubAPIURL is the GitHub REST API that CheckGatewaySource asks.
var GitHubAPIURL = "https://api.github.com"

// publishedCommits holds "owner/name@commit" keys GitHub has confirmed. A
// commit on a default branch stays there, so GitHub is asked once per commit
// per process.
var publishedCommits sync.Map

// GatewaySourceResult records whether the gateway's source commit is on the
// default branch of the public repository its app_compose names.
type GatewaySourceResult struct {
	Repo   string
	Commit string
	Err    error
}

// CheckGatewaySource asks GitHub whether the commit the gateway app_compose
// names is an ancestor of, or equal to, the head of its repository's default
// branch. It returns nil when the policy sets no compose template. It fails
// closed: offline, or with GitHub unreachable, a commit not already confirmed
// in this process is not published.
func CheckGatewaySource(ctx context.Context, client *http.Client, appCompose string, p MeasurementPolicy, offline bool) *GatewaySourceResult {
	if !p.HasComposeTemplatePolicy() {
		return nil
	}
	t, err := ParseGatewayComposeTemplate(appCompose)
	if err != nil {
		return &GatewaySourceResult{Err: err}
	}
	r := &GatewaySourceResult{Repo: t.Repo, Commit: t.Commit}
	key := t.Repo + "@" + t.Commit
	if _, ok := publishedCommits.Load(key); ok {
		return r
	}
	if offline {
		r.Err = errors.New("offline: publication of the gateway commit not checked")
		return r
	}
	r.Err = githubCommitOnDefaultBranch(ctx, client, t.Repo, t.Commit)
	if r.Err == nil {
		publishedCommits.Store(key, struct{}{})
	}
	return r
}

func githubCommitOnDefaultBranch(ctx context.Context, client *http.Client, repo, commit string) error {
	url := fmt.Sprintf("%s/repos/%s/compare/HEAD...%s?per_page=1", GitHubAPIURL, repo, commit)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GitHub compare for github.com/%s: %w", repo, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("GitHub compare for github.com/%s: %w", repo, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub compare HEAD...%s in github.com/%s: HTTP %d", commit, repo, resp.StatusCode)
	}
	var cmp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &cmp); err != nil {
		return fmt.Errorf("GitHub compare for github.com/%s: %w", repo, err)
	}
	if cmp.Status != "behind" && cmp.Status != "identical" {
		return fmt.Errorf("commit %s is not on the default branch of github.com/%s (compare status %q)", commit, repo, cmp.Status)
	}
	return nil
}
