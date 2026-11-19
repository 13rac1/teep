package attestation

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"regexp"
	"strconv"
	"strings"

	"github.com/13rac1/teep/internal/jsonstrict"
)

// VerifyComposeBinding checks that sha256(appCompose) matches the MRConfigID
// from the TDX quote. MRConfigID is expected to start with the byte 0x01
// followed by the sha256 hash of appCompose (big-endian).
func VerifyComposeBinding(appCompose string, mrConfigID []byte) error {
	if len(mrConfigID) == 0 {
		return errors.New("MRConfigID is empty")
	}

	hash := sha256.Sum256([]byte(appCompose))
	// Expected: 01 + sha256(appCompose) in first 33 bytes of MRConfigID.
	expectedPrefix := make([]byte, 0, 33)
	expectedPrefix = append(expectedPrefix, 0x01)
	expectedPrefix = append(expectedPrefix, hash[:]...)

	if len(mrConfigID) < len(expectedPrefix) {
		return fmt.Errorf("MRConfigID too short (%d bytes), need at least %d", len(mrConfigID), len(expectedPrefix))
	}

	actual := mrConfigID[:len(expectedPrefix)]
	if subtle.ConstantTimeCompare(actual, expectedPrefix) != 1 {
		return fmt.Errorf(
			"MRConfigID does not match app_compose hash (expected prefix=%s, actual=%s)",
			hex.EncodeToString(expectedPrefix),
			hex.EncodeToString(mrConfigID),
		)
	}
	return checkAppComposeObject(appCompose)
}

// checkAppComposeObject requires appCompose, whose hash the quote binds, to
// be read the same way by teep and dstack.
func checkAppComposeObject(appCompose string) error {
	// The quote binds these bytes, but teep reads the images from the
	// docker_compose_file member. An app_compose object that teep and
	// dstack read differently (a duplicate member, or a member that
	// differs from docker_compose_file only in letter case) fails here,
	// before the images are extracted. dstack decodes app_compose as a JSON
	// object, so any other value (a list, a string, null, a leading byte
	// order mark) fails too.
	if !strings.HasPrefix(strings.TrimLeft(appCompose, " \t\r\n"), "{") {
		return errors.New("app_compose is not a JSON object")
	}
	if _, err := ExtractDockerCompose(appCompose); err != nil {
		return err
	}
	return nil
}

// appComposePayload is the JSON structure for the app_compose field.
type appComposePayload struct {
	DockerComposeFile string `json:"docker_compose_file"`
}

// ExtractDockerCompose extracts the docker_compose_file string from an
// app_compose JSON payload. Returns ("", nil) if the field is absent. It
// decodes with jsonstrict: a duplicate member, or a member that differs from
// docker_compose_file only in letter case, fails. dstack copies the member
// with the exact name (jq) and does not read a case variant, while
// encoding/json would take the last case-insensitive match. The other
// app_compose members are not checked.
func ExtractDockerCompose(appCompose string) (string, error) {
	var payload appComposePayload
	if _, _, err := jsonstrict.Unmarshal([]byte(appCompose), &payload); err != nil {
		return "", fmt.Errorf("parse app_compose JSON: %w", err)
	}
	return payload.DockerComposeFile, nil
}

// imageDigestRe matches @sha256:<64 hex chars> in image references.
var imageDigestRe = regexp.MustCompile(`@sha256:([0-9a-f]{64})`)

// imageRefDigestRe matches <image-ref>@sha256:<64 hex chars> where image-ref
// is a container image reference that may include registry, namespace, and tag.
var imageRefDigestRe = regexp.MustCompile(`([A-Za-z0-9._/:-]+)@sha256:[0-9a-f]{64}`)

// imageRefAndDigestRe captures both image reference and digest in two groups.
var imageRefAndDigestRe = regexp.MustCompile(`([A-Za-z0-9._/:-]+)@sha256:([0-9a-f]{64})`)

// maxImageDigests caps the number of distinct digests returned by
// ExtractImageDigests, bounding the number of sequential Sigstore/Rekor API
// calls that can be triggered by a single attested compose manifest (F-25).
const maxImageDigests = 64

// ExtractImageDigests returns deduplicated sha256 digests from image references
// in the given text (e.g. docker-compose content). Each digest is the 64-char
// hex string after @sha256:. At most maxImageDigests distinct digests are
// returned; additional matches are silently discarded.
func ExtractImageDigests(text string) []string {
	matches := imageDigestRe.FindAllStringSubmatch(text, -1)
	seen := make(map[string]struct{}, len(matches))
	var digests []string
	for _, m := range matches {
		if len(digests) >= maxImageDigests {
			break
		}
		digest := m[1]
		if _, ok := seen[digest]; ok {
			continue
		}
		seen[digest] = struct{}{}
		digests = append(digests, digest)
	}
	return digests
}

// ExtractImageRepositories returns deduplicated normalized image repositories
// extracted from image references that include a sha256 digest.
//
// Examples:
//   - ghcr.io/nearai/router@sha256:... -> ghcr.io/nearai/router
//   - ghcr.io/nearai/router:v1@sha256:... -> ghcr.io/nearai/router
//   - registry.example.com:5000/ns/img@sha256:... -> registry.example.com:5000/ns/img
func ExtractImageRepositories(text string) []string {
	matches := imageRefDigestRe.FindAllStringSubmatch(text, -1)
	seen := make(map[string]struct{}, len(matches))
	var repos []string
	for _, m := range matches {
		repo := normalizeImageRepository(m[1])
		if repo == "" {
			continue
		}
		if _, ok := seen[repo]; ok {
			continue
		}
		seen[repo] = struct{}{}
		repos = append(repos, repo)
	}
	return repos
}

func normalizeImageRepository(ref string) string {
	ref = strings.ToLower(strings.TrimSpace(ref))
	if ref == "" {
		return ""
	}
	// Docker compose can encode image defaults like:
	//   ${COMPOSE_MANAGER_IMAGE:-nearaidev/compose-manager}
	// After regex extraction, this may appear as
	//   compose_manager_image:-nearaidev/compose-manager
	// Keep only the default image reference so policy matching uses the repo.
	if idx := strings.Index(ref, ":-"); idx > 0 {
		left := ref[:idx]
		right := ref[idx+2:]
		// Only rewrite ${VAR:-default} expansions when the left side does not
		// already look like a qualified image reference. Real repo/image refs
		// include a slash; compose variable names do not.
		if !strings.Contains(left, "/") {
			ref = right
		}
	}
	// Drop optional tag from the final path segment while preserving registry
	// ports (e.g. registry:5000/ns/img:tag).
	lastSlash := strings.LastIndex(ref, "/")
	lastColon := strings.LastIndex(ref, ":")
	if lastColon > lastSlash {
		ref = ref[:lastColon]
	}
	return ref
}

// ExtractImageDigestToRepoMap returns a map from digest (64-char hex string) to
// normalized image repository name. All @sha256:-pinned image references found
// in text are included. Later duplicates for the same digest are ignored.
func ExtractImageDigestToRepoMap(text string) map[string]string {
	matches := imageRefAndDigestRe.FindAllStringSubmatch(text, -1)
	result := make(map[string]string, len(matches))
	for _, m := range matches {
		repo := normalizeImageRepository(m[1])
		digest := m[2]
		if repo == "" {
			continue
		}
		existing, ok := result[digest]
		if !ok {
			result[digest] = repo
			continue
		}
		if existing != repo {
			slog.Warn("digest maps to multiple repos within manifest; using first",
				"digest", "sha256:"+digest[:min(16, len(digest))]+"...",
				"kept", existing, "dropped", repo)
		}
	}
	return result
}

// ComposeDigests holds extracted image repositories and digests from a compose manifest.
type ComposeDigests struct {
	Repos        []string
	DigestToRepo map[string]string
	Digests      []string
}

// ExtractComposeDigests extracts image repos, digest-to-repo mappings, and digests
// from a compose manifest (app_compose or docker_compose_file within it).
func ExtractComposeDigests(appCompose string) ComposeDigests {
	dockerCompose, err := ExtractDockerCompose(appCompose)
	if err != nil {
		slog.Debug("extract docker_compose_file failed", "err", err)
	}
	if dockerCompose != "" {
		slog.Debug("attested docker compose manifest", "content", dockerCompose)
	}
	source := dockerCompose
	if source == "" {
		source = appCompose
	}
	return ComposeDigests{
		Repos:        ExtractImageRepositories(source),
		DigestToRepo: ExtractImageDigestToRepoMap(source),
		Digests:      ExtractImageDigests(source),
	}
}

// MergeComposeDigests merges model and gateway compose digests with deduplication.
// Model digests are inserted first; first-writer-wins for digestToRepo with conflict logging.
func MergeComposeDigests(model, gateway ComposeDigests) (allDigests []string, digestToRepo map[string]string) {
	digestToRepo = make(map[string]string)

	// Model digests first.
	maps.Copy(digestToRepo, model.DigestToRepo)
	// Gateway digests — first-writer-wins with conflict logging.
	for digest, repo := range gateway.DigestToRepo {
		existing, ok := digestToRepo[digest]
		if !ok {
			digestToRepo[digest] = repo
			continue
		}
		if existing != repo {
			slog.Warn("digest maps to multiple repos; using first",
				"digest", "sha256:"+digest[:min(16, len(digest))]+"...",
				"kept", existing, "dropped", repo)
		}
	}

	// Deduplicate digests.
	seen := make(map[string]struct{})
	for _, d := range model.Digests {
		if _, ok := seen[d]; !ok {
			seen[d] = struct{}{}
			allDigests = append(allDigests, d)
		}
	}
	for _, d := range gateway.Digests {
		if _, ok := seen[d]; !ok {
			seen[d] = struct{}{}
			allDigests = append(allDigests, d)
		}
	}
	return allDigests, digestToRepo
}

// mrConfigV3 is the launch document that a dstack 0.6 VMM binds into a TDX
// MR_CONFIG_ID of version 3 (MrConfigV3 in dstack-types mr_config.rs). The
// members are in sorted order and every value is ASCII, so json.Marshal
// writes the RFC 8785 form that dstack hashes.
type mrConfigV3 struct {
	AppID            string    `json:"app_id"`
	ComposeHash      string    `json:"compose_hash"`
	GPUPolicyHash    string    `json:"gpu_policy_hash,omitempty"`
	InitScriptHashes *[]string `json:"init_script_hashes,omitempty"`
	InstanceID       string    `json:"instance_id,omitempty"`
	KeyProvider      string    `json:"key_provider"`
	KeyProviderID    string    `json:"key_provider_id,omitempty"`
	Version          int       `json:"version"`
}

// appComposeV3 holds the app_compose members that the VMM copies into the
// MrConfigV3 document.
type appComposeV3 struct {
	KeyProvider     string   `json:"key_provider"`
	KeyProviderID   string   `json:"key_provider_id,omitempty"`
	ManifestVersion string   `json:"manifest_version"`
	InitScript      []string `json:"init_script,omitempty"`
}

// VerifyComposeBindingV3 checks a TDX MRConfigID of version 3: 0x03, then
// sha256("dstack-mr-config-v3:" || 0x00 || document), then 15 zero bytes.
// The quote carries no document, so teep builds the one that the dstack
// VMM builds (prepare_mr_config_v3 in dstack vmm/src/app/mr_config.rs):
// compose_hash is sha256(appCompose); key_provider, key_provider_id and,
// from manifest version 3, the sha256 of each init script come from
// appCompose; app_id, instance_id and, for a launch with GPUs,
// gpu_policy_hash come from the RTMR3 events. The caller must have checked
// that events reproduce the RTMRs of the quote.
func VerifyComposeBindingV3(appCompose string, events []EventLogEntry, gpu bool, mrConfigID []byte) error {
	var ac appComposeV3
	_, missing, err := jsonstrict.Unmarshal([]byte(appCompose), &ac)
	if err != nil {
		return fmt.Errorf("app_compose: %w", err)
	}
	if len(missing) > 0 {
		return fmt.Errorf("app_compose: missing members %q", missing)
	}
	manifest, err := strconv.Atoi(ac.ManifestVersion)
	if err != nil {
		return fmt.Errorf("app_compose manifest_version: %w", err)
	}
	composeHash := sha256.Sum256([]byte(appCompose))
	doc := mrConfigV3{ComposeHash: hex.EncodeToString(composeHash[:]), KeyProvider: ac.KeyProvider, KeyProviderID: ac.KeyProviderID, Version: 3}
	if manifest >= 3 {
		hashes := make([]string, len(ac.InitScript))
		for i, script := range ac.InitScript {
			sum := sha256.Sum256([]byte(script))
			hashes[i] = hex.EncodeToString(sum[:])
		}
		doc.InitScriptHashes = &hashes
	}
	if doc.AppID, err = runtimeEventPayload(events, "app-id"); err != nil {
		return err
	}
	if doc.InstanceID, err = runtimeEventPayload(events, "instance-id"); err != nil {
		return err
	}
	if gpu {
		if doc.GPUPolicyHash, err = runtimeEventPayload(events, "gpu-policy-hash"); err != nil {
			return err
		}
	}
	document, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("MrConfigV3 document: %w", err)
	}
	digest := sha256.Sum256(append([]byte("dstack-mr-config-v3:\x00"), document...))
	expected := make([]byte, 48)
	expected[0] = 3
	copy(expected[1:], digest[:])
	if subtle.ConstantTimeCompare(mrConfigID, expected) != 1 {
		return fmt.Errorf("MRConfigID %s does not bind the MrConfigV3 document %s", hex.EncodeToString(mrConfigID), document)
	}
	return checkAppComposeObject(appCompose)
}

// runtimeEventPayload returns the payload of the one RTMR3 dstack runtime
// event with this name, as lowercase hex.
func runtimeEventPayload(events []EventLogEntry, name string) (string, error) {
	var found [][]byte
	for _, e := range events {
		if e.IMR == 3 && e.EventType == DstackRuntimeEventType && e.Event == name {
			payload, err := hex.DecodeString(e.EventPayload)
			if err != nil {
				return "", fmt.Errorf("%s event payload: %w", name, err)
			}
			found = append(found, payload)
		}
	}
	if len(found) != 1 {
		return "", fmt.Errorf("event log has %d %s events, want 1", len(found), name)
	}
	return hex.EncodeToString(found[0]), nil
}
