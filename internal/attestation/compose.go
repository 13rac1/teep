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
	"strings"
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

	return nil
}

// appComposePayload is the JSON structure for the app_compose field.
type appComposePayload struct {
	DockerComposeFile string `json:"docker_compose_file"`
}

// ExtractDockerCompose extracts the docker_compose_file string from an
// app_compose JSON payload. Returns ("", nil) if the field is absent.
func ExtractDockerCompose(appCompose string) (string, error) {
	var payload appComposePayload
	if err := json.Unmarshal([]byte(appCompose), &payload); err != nil {
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
