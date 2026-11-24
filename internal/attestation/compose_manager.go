package attestation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"sync"

	"go.yaml.in/yaml/v3"

	"github.com/13rac1/teep/internal/jsonstrict"
)

// maxComposeManagerActions bounds the action log of one compose-manager
// attestation.
const maxComposeManagerActions = 10_000

// ComposeManagerAction is one entry of the compose-manager action log, with
// the members that nearai/compose-manager defines (DeploymentAction).
type ComposeManagerAction struct {
	Timestamp  string    `json:"timestamp"`
	Action     string    `json:"action"`
	Tag        string    `json:"tag,omitempty"`
	Commit     string    `json:"commit,omitempty"`
	File       string    `json:"file,omitempty"`
	FileSHA256 string    `json:"file_sha256,omitempty"`
	Services   []*string `json:"services,omitempty"`
	Container  string    `json:"container,omitempty"`
	Image      string    `json:"image,omitempty"`
}

// composeManagerEvidence is the compose_manager_attestation member of a NEAR
// model entry, as served by compose-manager's /v1/attestation/report.
type composeManagerEvidence struct {
	Actions     json.RawMessage `json:"actions"`
	ActionsHash string          `json:"actions_hash"`
	Nonce       string          `json:"nonce"`
	NonceSource string          `json:"nonce_source"`
	Quote       string          `json:"quote"`
	EventLog    string          `json:"event_log"`
	ReportData  string          `json:"report_data"`
	VMConfig    string          `json:"vm_config,omitempty"`
}

// ComposeManagerResult is the verification of the compose_manager_attestation
// of a NEAR model instance. NEAR's model CVM compose runs compose-manager,
// which starts the inference proxy and the model server after boot from
// files of nearai/cvm-compose-files, so neither is in RTMR3 or MRConfigID.
// compose-manager records each deployment in an action log and serves a
// second TDX quote whose REPORTDATA is sha256(canonical action log) followed
// by the client nonce.
type ComposeManagerResult struct {
	// Err is set when the evidence is missing or malformed.
	Err error
	// Quote is the verification of the compose-manager quote.
	Quote *TDXVerifyResult
	// TDErr is set when the quote is not from the TD of the instance quote.
	TDErr error
	// BindErr is set when REPORTDATA is not sha256(actions) || nonce.
	BindErr error
	// Actions is the action log that the quote binds when BindErr is nil.
	Actions []ComposeManagerAction
	// Deployments and Images are what the bound log runs, and SourceErr why
	// they fail the rule of ComposeSources.Check, when the quote binds the log
	// to the instance and the nonce.
	Deployments []ComposeDeployment
	Images      []string
	SourceErr   error
}

// VerifyComposeManager verifies the compose_manager_attestation of a NEAR
// model entry: the quote with verify, the same TD as instance (the verified
// quote of the entry), and REPORTDATA = sha256(canonical actions) || nonce.
// When those hold, it checks what the log runs against the rule of
// sources. It returns nil for every other backend format.
func VerifyComposeManager(ctx context.Context, raw *RawAttestation, instance *TDXVerifyResult, nonce Nonce, verify TDXVerifier, sources *ComposeSources) *ComposeManagerResult {
	if raw.BackendFormat != FormatNear {
		return nil
	}
	quote, actions, digest, err := parseComposeManager(raw.ComposeManagerAttestation)
	if err != nil {
		return &ComposeManagerResult{Err: err}
	}
	r := &ComposeManagerResult{Quote: verify(ctx, quote), Actions: actions}
	if r.Quote.ParseErr != nil {
		return r
	}
	r.TDErr = sameTD(instance, r.Quote)
	want := append(digest[:], nonce[:]...)
	if subtle.ConstantTimeCompare(r.Quote.ReportData[:], want) != 1 {
		r.BindErr = fmt.Errorf("REPORTDATA %s is not sha256(actions) %s || nonce %s",
			hex.EncodeToString(r.Quote.ReportData[:]), hex.EncodeToString(digest[:]), nonce.Hex())
	}
	if r.TDErr != nil || r.BindErr != nil {
		return r
	}
	r.Deployments, r.Images, r.SourceErr = ComposeManagerDeployments(actions)
	if r.SourceErr == nil {
		r.SourceErr = sources.Check(ctx, r.Deployments)
	}
	return r
}

// parseComposeManager decodes the evidence strictly and returns the quote,
// the typed actions and sha256 of the canonical action list.
func parseComposeManager(data []byte) (string, []ComposeManagerAction, [32]byte, error) {
	var digest [32]byte
	if len(bytes.TrimSpace(data)) == 0 {
		return "", nil, digest, errors.New("model entry has no compose_manager_attestation")
	}
	var ev composeManagerEvidence
	unknown, err := jsonstrict.UnmarshalObject(data, &ev, "compose_manager_attestation")
	if err != nil {
		return "", nil, digest, err
	}
	if len(unknown) != 0 {
		return "", nil, digest, fmt.Errorf("compose_manager_attestation has unknown members %v", unknown)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(ev.Actions, &items); err != nil || items == nil {
		return "", nil, digest, errors.New("compose_manager_attestation.actions: expected an array")
	}
	if len(items) > maxComposeManagerActions {
		return "", nil, digest, fmt.Errorf("compose_manager_attestation.actions: %d entries, more than %d", len(items), maxComposeManagerActions)
	}
	actions := make([]ComposeManagerAction, len(items))
	for i, item := range items {
		path := fmt.Sprintf("compose_manager_attestation.actions[%d]", i)
		unknown, err := jsonstrict.UnmarshalObject(item, &actions[i], path)
		if err != nil {
			return "", nil, digest, err
		}
		if len(unknown) != 0 {
			return "", nil, digest, fmt.Errorf("%s has unknown members %v", path, unknown)
		}
		if slices.Contains(actions[i].Services, nil) {
			return "", nil, digest, fmt.Errorf("%s.services: null is not permitted", path)
		}
	}
	canonical, err := canonicalJSON(ev.Actions)
	if err != nil {
		return "", nil, digest, fmt.Errorf("compose_manager_attestation.actions: %w", err)
	}
	return ev.Quote, actions, sha256.Sum256(canonical), nil
}

// canonicalJSON re-encodes data with object keys sorted, no whitespace and
// no HTML escaping: the encoding of compose-manager's canonicalize_actions
// and of Python's json.dumps(sort_keys=True, separators=(",", ":"),
// ensure_ascii=False).
func canonicalJSON(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// sameTD returns an error unless cm has every TD measurement of instance:
// MRTD, MRSEAM, MRCONFIGID, MROWNER, MROWNERCONFIG and RTMR0-3. RTMR3
// carries the instance-id event, so it separates two instances of one image.
func sameTD(instance, cm *TDXVerifyResult) error {
	if instance == nil || instance.ParseErr != nil {
		return errors.New("the instance quote did not parse")
	}
	fields := []struct {
		name string
		a, b []byte
	}{
		{"MRTD", instance.MRTD, cm.MRTD},
		{"MRSEAM", instance.MRSeam, cm.MRSeam},
		{"MRCONFIGID", instance.MRConfigID, cm.MRConfigID},
		{"MROWNER", instance.MROwner, cm.MROwner},
		{"MROWNERCONFIG", instance.MROwnerConfig, cm.MROwnerConfig},
	}
	for i := range instance.RTMRs {
		fields = append(fields, struct {
			name string
			a, b []byte
		}{fmt.Sprintf("RTMR%d", i), instance.RTMRs[i][:], cm.RTMRs[i][:]})
	}
	for _, f := range fields {
		if len(f.a) == 0 || subtle.ConstantTimeCompare(f.a, f.b) != 1 {
			return fmt.Errorf("%s differs from the instance quote: %s, instance %s", f.name, hex.EncodeToString(f.b), hex.EncodeToString(f.a))
		}
	}
	return nil
}

// ComposeFilesRepo is the GitHub repository whose files NEAR's compose-manager
// deploys (GITHUB_REPO in the measured model compose).
const ComposeFilesRepo = "nearai/cvm-compose-files"

// rawGitHubURL serves the files of a GitHub repository at a commit.
const rawGitHubURL = "https://raw.githubusercontent.com"

// maxComposeFileBytes bounds one fetched compose file.
const maxComposeFileBytes = 4 << 20

// composeManagerImageRE matches the compose-manager image the measured
// launcher may run: its repository, pinned by digest.
var composeManagerImageRE = regexp.MustCompile(`^nearaidev/compose-manager@sha256:[0-9a-f]{64}$`)

// composeImageRE matches an image reference pinned by digest, with an
// optional tag and no interpolation.
var composeImageRE = regexp.MustCompile(`^[^\s$@]+@sha256:[0-9a-f]{64}$`)

var (
	hex40RE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ComposeDeployment is a compose file that the action log stages or brings up.
type ComposeDeployment struct {
	Commit, File, FileSHA256 string
}

// ComposeManagerDeployments returns the compose files that the log stages or
// brings up, and the compose-manager images it records starting. Every
// action that can run code names what it runs: compose_up and compose_stage
// (which pulls and builds) a file at a commit, compose_manager_started the
// image. The other actions compose-manager records start nothing new:
// compose_down, docker_restart, docker_clean (prune), docker_evict (removes
// cached weights), launcher_restart (the measured launcher), the
// dstack_agent_* systemctl actions, the kernel_algif_blacklist_* script and
// env_override_set/unset (key names only; see the README on env values). Any
// other action fails, and a log without a compose_manager_started entry does
// not attest the running compose-manager.
func ComposeManagerDeployments(actions []ComposeManagerAction) (deps []ComposeDeployment, images []string, err error) {
	for i := range actions {
		a := &actions[i]
		switch a.Action {
		case "compose_up", "compose_stage":
			if !hex40RE.MatchString(a.Commit) {
				return nil, nil, fmt.Errorf("actions[%d] %s: commit %q is not 40 lowercase hex", i, a.Action, a.Commit)
			}
			if !hex64RE.MatchString(a.FileSHA256) {
				return nil, nil, fmt.Errorf("actions[%d] %s: file_sha256 %q is not 32 bytes of lowercase hex", i, a.Action, a.FileSHA256)
			}
			if a.File == "" {
				return nil, nil, fmt.Errorf("actions[%d] %s: no file", i, a.Action)
			}
			d := ComposeDeployment{a.Commit, a.File, a.FileSHA256}
			if !slices.Contains(deps, d) {
				deps = append(deps, d)
			}
		case "compose_manager_started":
			if !composeManagerImageRE.MatchString(a.Image) {
				return nil, nil, fmt.Errorf("actions[%d] compose_manager_started: image %q is not nearaidev/compose-manager pinned by digest", i, a.Image)
			}
			if !slices.Contains(images, a.Image) {
				images = append(images, a.Image)
			}
		case "compose_down", "docker_restart", "docker_clean", "docker_evict", "launcher_restart",
			"dstack_agent_start", "dstack_agent_stop", "dstack_agent_restart", "dstack_agent_status",
			"kernel_algif_blacklist_ok", "kernel_algif_blacklist_script_failed", "kernel_algif_blacklist_invocation_failed",
			"env_override_set", "env_override_unset":
		default:
			return nil, nil, fmt.Errorf("actions[%d]: unknown action %q", i, a.Action)
		}
	}
	if len(images) == 0 {
		return nil, nil, errors.New("the action log has no compose_manager_started entry")
	}
	return deps, images, nil
}

// ComposeSources checks compose files of ComposeFilesRepo against the rule
// and keeps the files that pass for its lifetime. Content at a commit does
// not change. It is safe for concurrent use.
type ComposeSources struct {
	baseURL  string
	client   *http.Client
	offline  bool
	mu       sync.Mutex
	accepted map[ComposeDeployment]struct{}
}

// NewComposeSources returns a ComposeSources that fetches files from
// raw.githubusercontent.com with client. Offline, it fetches nothing.
func NewComposeSources(client *http.Client, offline bool) *ComposeSources {
	return newComposeSources(rawGitHubURL, client, offline)
}

func newComposeSources(baseURL string, client *http.Client, offline bool) *ComposeSources {
	return &ComposeSources{baseURL: baseURL, client: client, offline: offline, accepted: make(map[ComposeDeployment]struct{})}
}

// Check applies the rule to every deployment, stopping at the first that
// fails: the file at that commit of ComposeFilesRepo is published and hashes
// to file_sha256, and every service in it runs an image pinned by digest
// (checkComposeImages). Offline, or with GitHub unreachable, a deployment not
// already accepted fails.
func (c *ComposeSources) Check(ctx context.Context, deps []ComposeDeployment) error {
	for _, d := range deps {
		c.mu.Lock()
		_, ok := c.accepted[d]
		c.mu.Unlock()
		if ok {
			continue
		}
		if c.offline {
			return fmt.Errorf("offline: %s at %s not checked", d.File, d.Commit)
		}
		if err := c.checkSource(ctx, d); err != nil {
			return fmt.Errorf("%s at %s: %w", d.File, d.Commit, err)
		}
		c.mu.Lock()
		c.accepted[d] = struct{}{}
		c.mu.Unlock()
	}
	return nil
}

// A public commit pinned by hash identifies what ran, whatever branch holds it.
func (c *ComposeSources) checkSource(ctx context.Context, d ComposeDeployment) error {
	url := fmt.Sprintf("%s/%s/%s/%s", c.baseURL, ComposeFilesRepo, d.Commit, d.File)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxComposeFileBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxComposeFileBytes {
		return fmt.Errorf("GET %s: more than %d bytes", url, maxComposeFileBytes)
	}
	want, err := hex.DecodeString(d.FileSHA256)
	if err != nil {
		return err
	}
	if got := sha256.Sum256(body); subtle.ConstantTimeCompare(got[:], want) != 1 {
		return fmt.Errorf("published file hashes to %x, the log says %s", got, d.FileSHA256)
	}
	return checkComposeImages(body)
}

// checkComposeImages requires every service of a compose file to run an image
// pinned by digest, so the file names what runs. It refuses a build (the
// image would be whatever the build produces), extends and include (another
// file decides), and interpolation in an image (unlogged env decides).
func checkComposeImages(data []byte) error {
	var doc struct {
		Include  any                       `yaml:"include"`
		Services map[string]map[string]any `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("compose file: %w", err)
	}
	if doc.Include != nil {
		return errors.New("compose file uses include")
	}
	if len(doc.Services) == 0 {
		return errors.New("compose file has no services")
	}
	for _, name := range slices.Sorted(maps.Keys(doc.Services)) {
		svc := doc.Services[name]
		for _, k := range []string{"build", "extends"} {
			if _, ok := svc[k]; ok {
				return fmt.Errorf("service %s uses %s", name, k)
			}
		}
		img, _ := svc["image"].(string)
		if !composeImageRE.MatchString(img) {
			return fmt.Errorf("service %s image %q is not pinned by digest", name, svc["image"])
		}
	}
	return nil
}
