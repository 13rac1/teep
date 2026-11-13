package aci

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"mime/multipart"
	"slices"
	"strconv"
	"strings"

	"github.com/13rac1/teep/internal/jsonstrict"
)

// SessionsPath is the ACI/1 attested-session route (§8.1).
const SessionsPath = "/v1/aci/sessions"

const (
	// MaxSessionBytes bounds one full session record. A Chutes session
	// embeds the evidence of every chute instance (3.9 MB on 2026-10-31).
	MaxSessionBytes = 16 << 20
	// MaxSessionListBytes bounds the session list of one model.
	MaxSessionListBytes = 2 << 20
	maxSessionsInList   = 256
	maxChannelBindings  = 16
)

// Channel-binding types of ACI/1 §8.2.
const (
	BindingTLSSPKI       = "tls_spki_sha256"
	BindingE2EEPublicKey = "e2ee_public_key_sha256"
)

// sessionClaimNames is the typed-claim vocabulary of ACI/1 §8.3.
var sessionClaimNames = []string{
	"tee_attested", "gpu_attested", "tcb_up_to_date", "os_known_good",
	"serving_software_known_good", "model_weights_provenance",
}

// ChannelBinding is one channel_binding entry of a session (ACI/1 §8.2).
// The fields of the other type are empty.
type ChannelBinding struct {
	Type            string
	Origin          string // tls_spki_sha256
	SPKISHA256      string // tls_spki_sha256
	Provider        string // e2ee_public_key_sha256
	KeyID           string // e2ee_public_key_sha256, optional
	Algorithm       string // e2ee_public_key_sha256
	PublicKeySHA256 string // e2ee_public_key_sha256
}

// SessionClaim is one typed claim (ACI/1 §8.3). Source and Reason are empty
// when Status is "unknown".
type SessionClaim struct {
	Status string
	Source string
	Reason string
}

// Session is an attested session record (ACI/1 §8.2). A full record has
// Evidence; a list entry has only EvidenceDigest.
type Session struct {
	// ID is the bare lowercase-hex session id. For a full record it is the
	// recomputed hex(sha256(JCS(record))); for a list entry it is the
	// served session_id, which only a full record can confirm.
	ID              string
	UpstreamName    string
	Endpoint        string // "" when the record states null
	VerifierID      string
	EstablishedAt   int64
	ExpiresAt       int64
	Identity        map[string]json.RawMessage // nil when absent
	ChannelBindings []ChannelBinding
	Claims          map[string]SessionClaim
	Extra           map[string]json.RawMessage
	EvidenceDigest  string
	// Evidence is the decoded evidence.data of a full record: the exact
	// bytes the gateway's verifier consumed. Nil for a list entry.
	Evidence *SessionEvidence

	// value is the parsed record in the ACI canonical value space, without
	// session_id, for RebuildSession.
	value map[string]any
}

// SessionEvidence is a decoded evidence data URI.
type SessionEvidence struct {
	MediaType string
	Params    map[string]string
	Data      []byte
	// uri is the data URI as served, for RebuildSession.
	uri string
}

// sessionJSON is a session record (§8.2) or a session list entry (§8.1).
// jsonstrict reports every undefined and every absent member at every
// depth; checkSessionMembers then decides which absent members the record's
// kind and content allow.
type sessionJSON struct {
	APIVersion     string               `json:"api_version"`
	UpstreamName   string               `json:"upstream_name"`
	Endpoint       *string              `json:"endpoint"`
	VerifierID     string               `json:"verifier_id"`
	EstablishedAt  int64                `json:"established_at"`
	ExpiresAt      int64                `json:"expires_at"`
	Identity       json.RawMessage      `json:"identity"`
	ChannelBinding []channelBindingJSON `json:"channel_binding"`
	Claims         sessionClaimsJSON    `json:"claims"`
	Evidence       sessionEvidenceJSON  `json:"evidence"`
	// SessionID is a member of list entries only.
	SessionID string `json:"session_id"`
}

// channelBindingJSON has the members of both binding types of §8.2; each
// entry must have exactly the members of its own type.
type channelBindingJSON struct {
	Type            string `json:"type"`
	Origin          string `json:"origin"`
	SPKISHA256      string `json:"spki_sha256"`
	Provider        string `json:"provider"`
	KeyID           string `json:"key_id"`
	Algorithm       string `json:"algorithm"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

// bindingMembers lists the members of each binding type; optional members
// may be absent.
var bindingMembers = map[string]struct{ required, optional []string }{
	BindingTLSSPKI:       {required: []string{"type", "origin", "spki_sha256"}},
	BindingE2EEPublicKey: {required: []string{"type", "provider", "algorithm", "public_key_sha256"}, optional: []string{"key_id"}},
}

var allBindingMembers = []string{"type", "origin", "spki_sha256", "provider", "key_id", "algorithm", "public_key_sha256"}

// sessionClaimsJSON holds the six typed claims of §8.3 and extra.
type sessionClaimsJSON struct {
	TEEAttested              sessionClaimJSON           `json:"tee_attested"`
	GPUAttested              sessionClaimJSON           `json:"gpu_attested"`
	TCBUpToDate              sessionClaimJSON           `json:"tcb_up_to_date"`
	OSKnownGood              sessionClaimJSON           `json:"os_known_good"`
	ServingSoftwareKnownGood sessionClaimJSON           `json:"serving_software_known_good"`
	ModelWeightsProvenance   sessionClaimJSON           `json:"model_weights_provenance"`
	Extra                    map[string]json.RawMessage `json:"extra"`
}

func (c *sessionClaimsJSON) byName() map[string]sessionClaimJSON {
	return map[string]sessionClaimJSON{
		"tee_attested":                c.TEEAttested,
		"gpu_attested":                c.GPUAttested,
		"tcb_up_to_date":              c.TCBUpToDate,
		"os_known_good":               c.OSKnownGood,
		"serving_software_known_good": c.ServingSoftwareKnownGood,
		"model_weights_provenance":    c.ModelWeightsProvenance,
	}
}

type sessionClaimJSON struct {
	Status string `json:"status"`
	Source string `json:"source"`
	Reason string `json:"reason"`
}

// sessionEvidenceJSON is {digest, data} in a full record and {digest} in a
// list entry.
type sessionEvidenceJSON struct {
	Digest string `json:"digest"`
	Data   string `json:"data"`
}

// ParseSession parses a full session record and checks it against id, the
// bare-hex session id that a session list or a receipt cites (ACI/1 §9.2
// steps 1 and 2): id must equal hex(sha256(JCS(record))), api_version must
// be aci/1, and evidence.data must decode and hash to evidence.digest. The
// record must have every member of §8.2, at every depth, and no other;
// only identity may be absent. Callers bound body to MaxSessionBytes.
func ParseSession(body []byte, id string) (*Session, error) {
	if len(body) > MaxSessionBytes {
		return nil, fmt.Errorf("session record exceeds %d bytes", MaxSessionBytes)
	}
	if !isLowerHex64(id) {
		return nil, errors.New("session id is not 64 lowercase hex characters")
	}
	value, err := sessionValue(body)
	if err != nil {
		return nil, fmt.Errorf("session record: %w", err)
	}
	canonical, err := canonicalize(value)
	if err != nil {
		return nil, fmt.Errorf("session record: canonical form: %w", err)
	}
	sum := sha256.Sum256(canonical)
	computed := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(id)) != 1 {
		return nil, fmt.Errorf("session record hashes to %s, not to the cited id %s", computed, id)
	}
	var record sessionJSON
	unknown, missing, err := jsonstrict.Unmarshal(body, &record)
	if err != nil {
		return nil, fmt.Errorf("session record: %w", err)
	}
	if err := checkSessionMembers(&record, "", unknown, missing, true); err != nil {
		return nil, fmt.Errorf("session record: %w", err)
	}
	s, err := sessionFromJSON(&record, true)
	if err != nil {
		return nil, fmt.Errorf("session %s: %w", id, err)
	}
	s.ID = computed
	s.value = value
	return s, nil
}

// ParseSessionList parses the response of the session list (ACI/1 §8.1).
// Each entry has the members of a session record with session_id added and
// evidence.data removed; an entry does not hash to its id, so only a full
// record or RebuildSession confirms it. Callers bound body to
// MaxSessionListBytes.
func ParseSessionList(body []byte) ([]*Session, error) {
	if len(body) > MaxSessionListBytes {
		return nil, fmt.Errorf("session list exceeds %d bytes", MaxSessionListBytes)
	}
	var list struct {
		APIVersion string        `json:"api_version"`
		Sessions   []sessionJSON `json:"sessions"`
	}
	unknown, missing, err := jsonstrict.Unmarshal(body, &list)
	if err != nil {
		return nil, fmt.Errorf("session list: %w", err)
	}
	if list.APIVersion != "aci/1" {
		return nil, fmt.Errorf("session list api_version is %q, want aci/1", list.APIVersion)
	}
	if list.Sessions == nil || len(list.Sessions) > maxSessionsInList {
		return nil, fmt.Errorf("session list: expected a list of at most %d sessions", maxSessionsInList)
	}
	if err := checkListMembers(len(list.Sessions), unknown, missing); err != nil {
		return nil, fmt.Errorf("session list: %w", err)
	}
	listValue, err := sessionValue(body)
	if err != nil {
		return nil, fmt.Errorf("session list: %w", err)
	}
	values, ok := listValue["sessions"].([]any)
	if !ok || len(values) != len(list.Sessions) {
		return nil, errors.New("session list: sessions is not a list")
	}
	out := make([]*Session, 0, len(list.Sessions))
	seen := map[string]bool{}
	for i := range list.Sessions {
		s, err := listEntry(&list.Sessions[i], values[i], fmt.Sprintf("sessions[%d].", i), unknown, missing)
		if err != nil {
			return nil, fmt.Errorf("session list entry %d: %w", i, err)
		}
		if seen[s.ID] {
			return nil, fmt.Errorf("session list lists session %s twice", s.ID)
		}
		seen[s.ID] = true
		out = append(out, s)
	}
	return out, nil
}

// checkListMembers fails on an undefined or absent member outside the
// session entries; checkSessionMembers checks each entry.
func checkListMembers(n int, unknown, missing []string) error {
	inEntry := func(path string) bool {
		for i := range n {
			if strings.HasPrefix(path, fmt.Sprintf("sessions[%d].", i)) {
				return true
			}
		}
		return false
	}
	for _, path := range unknown {
		if !inEntry(path) {
			return fmt.Errorf("undefined member %s", path)
		}
	}
	for _, path := range missing {
		if !inEntry(path) {
			return fmt.Errorf("missing member %s", path)
		}
	}
	return nil
}

func listEntry(entry *sessionJSON, value any, prefix string, unknown, missing []string) (*Session, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("expected an object")
	}
	if err := checkSessionMembers(entry, prefix, unknown, missing, false); err != nil {
		return nil, err
	}
	if !isLowerHex64(entry.SessionID) {
		return nil, errors.New("session_id is not 64 lowercase hex characters")
	}
	s, err := sessionFromJSON(entry, false)
	if err != nil {
		return nil, fmt.Errorf("session %s: %w", entry.SessionID, err)
	}
	object = maps.Clone(object)
	delete(object, "session_id")
	s.ID = entry.SessionID
	s.value = object
	return s, nil
}

// checkSessionMembers applies the member rules of §8.1 and §8.2 to the
// undefined and absent members that jsonstrict reported for the record at
// prefix. Undefined members fail. An absent member fails unless the rules
// allow it: identity may be absent; a full record has evidence.data and no
// session_id, a list entry the reverse; each channel binding has exactly
// the members of its type; a claim has source and reason exactly when its
// status is not unknown (§8.3).
func checkSessionMembers(r *sessionJSON, prefix string, unknown, missing []string, full bool) error {
	for _, path := range unknown {
		if rest, ok := strings.CutPrefix(path, prefix); ok {
			return fmt.Errorf("undefined member %s", rest)
		}
	}
	absent := map[string]bool{}
	for _, path := range missing {
		if rest, ok := strings.CutPrefix(path, prefix); ok {
			absent[rest] = true
		}
	}
	allowed := map[string]bool{"identity": true}
	if full {
		if !absent["session_id"] {
			return errors.New("a full record has no session_id")
		}
		allowed["session_id"] = true
	} else {
		if !absent["evidence.data"] {
			return errors.New("a list entry has no evidence.data")
		}
		allowed["evidence.data"] = true
	}
	for i, b := range r.ChannelBinding {
		at := fmt.Sprintf("channel_binding[%d].", i)
		members, ok := bindingMembers[b.Type]
		if !ok || absent[at+"type"] {
			return fmt.Errorf("channel_binding[%d]: type %q is not a channel binding of ACI/1", i, b.Type)
		}
		for _, m := range allBindingMembers {
			required := slices.Contains(members.required, m)
			own := required || slices.Contains(members.optional, m)
			switch {
			case !own && !absent[at+m]:
				return fmt.Errorf("channel_binding[%d]: %s is not a member of %s", i, m, b.Type)
			case !required:
				// A member of the other type, or an optional one, may be absent.
				allowed[at+m] = true
			}
		}
	}
	for name, c := range r.Claims.byName() {
		at := "claims." + name + "."
		if c.Status == "unknown" {
			if !absent[at+"source"] || !absent[at+"reason"] {
				return fmt.Errorf("claims.%s: a claim with status unknown has no source and no reason", name)
			}
			allowed[at+"source"], allowed[at+"reason"] = true, true
		}
	}
	for path := range absent {
		if !allowed[path] {
			return fmt.Errorf("missing member %s", path)
		}
	}
	return nil
}

// RebuildSession returns the full record of a list entry from the evidence
// of another full record with the same evidence digest, and checks the
// rebuilt record against the entry's id as ParseSession does. Sessions that
// the gateway established from one evidence fetch share that evidence, so
// one GET confirms every session of the bundle.
func RebuildSession(entry, full *Session) (*Session, error) {
	if entry.Evidence != nil || full.Evidence == nil {
		return nil, errors.New("rebuild needs a list entry and a full record")
	}
	if subtle.ConstantTimeCompare([]byte(entry.EvidenceDigest), []byte(full.EvidenceDigest)) != 1 {
		return nil, fmt.Errorf("session %s has another evidence digest than session %s", entry.ID, full.ID)
	}
	value := maps.Clone(entry.value)
	value["evidence"] = map[string]any{"digest": entry.EvidenceDigest, "data": full.Evidence.uri}
	record, err := canonicalize(value)
	if err != nil {
		return nil, fmt.Errorf("rebuild session %s: %w", entry.ID, err)
	}
	return ParseSession(record, entry.ID)
}

func sessionFromJSON(r *sessionJSON, full bool) (*Session, error) {
	if r.APIVersion != "aci/1" {
		return nil, fmt.Errorf("api_version is %q, want aci/1", r.APIVersion)
	}
	if r.UpstreamName == "" || r.VerifierID == "" {
		return nil, errors.New("upstream_name and verifier_id must not be empty")
	}
	if r.EstablishedAt <= 0 || r.ExpiresAt <= r.EstablishedAt {
		return nil, fmt.Errorf("established_at %d and expires_at %d do not form a period", r.EstablishedAt, r.ExpiresAt)
	}
	s := &Session{
		UpstreamName:  r.UpstreamName,
		VerifierID:    r.VerifierID,
		EstablishedAt: r.EstablishedAt,
		ExpiresAt:     r.ExpiresAt,
	}
	if r.Endpoint != nil {
		if *r.Endpoint == "" {
			return nil, errors.New("endpoint is empty; null states no single origin")
		}
		s.Endpoint = *r.Endpoint
	}
	if r.Identity != nil {
		// The members of identity are verifier-specific (§8.2).
		if err := json.Unmarshal(r.Identity, &s.Identity); err != nil || s.Identity == nil {
			return nil, errors.New("identity: expected an object")
		}
	}
	var err error
	if s.ChannelBindings, err = channelBindings(r.ChannelBinding); err != nil {
		return nil, err
	}
	if s.Claims, err = sessionClaims(&r.Claims); err != nil {
		return nil, err
	}
	if r.Claims.Extra == nil {
		return nil, errors.New("claims.extra: expected an object")
	}
	s.Extra = r.Claims.Extra
	if s.EvidenceDigest, s.Evidence, err = sessionEvidence(&r.Evidence, full); err != nil {
		return nil, err
	}
	return s, nil
}

func channelBindings(entries []channelBindingJSON) ([]ChannelBinding, error) {
	if len(entries) == 0 || len(entries) > maxChannelBindings {
		return nil, fmt.Errorf("channel_binding: expected 1 to %d entries", maxChannelBindings)
	}
	out := make([]ChannelBinding, 0, len(entries))
	for i, b := range entries {
		switch b.Type {
		case BindingTLSSPKI:
			if !strings.HasPrefix(b.Origin, "https://") || !isLowerHex64(b.SPKISHA256) {
				return nil, fmt.Errorf("channel_binding[%d]: tls_spki_sha256 needs an https origin and a 64-hex spki_sha256", i)
			}
			out = append(out, ChannelBinding{Type: b.Type, Origin: b.Origin, SPKISHA256: b.SPKISHA256})
		case BindingE2EEPublicKey:
			if b.Provider == "" || b.Algorithm == "" || !isLowerHex64(b.PublicKeySHA256) {
				return nil, fmt.Errorf("channel_binding[%d]: e2ee_public_key_sha256 needs a provider, an algorithm and a 64-hex public_key_sha256", i)
			}
			out = append(out, ChannelBinding{Type: b.Type, Provider: b.Provider, KeyID: b.KeyID, Algorithm: b.Algorithm, PublicKeySHA256: b.PublicKeySHA256})
		default:
			return nil, fmt.Errorf("channel_binding[%d]: type %q is not a channel binding of ACI/1", i, b.Type)
		}
	}
	return out, nil
}

func sessionClaims(c *sessionClaimsJSON) (map[string]SessionClaim, error) {
	claims := make(map[string]SessionClaim, len(sessionClaimNames))
	for name, claim := range c.byName() {
		switch claim.Status {
		case "unknown":
			claims[name] = SessionClaim{Status: claim.Status}
			continue
		case "asserted", "refuted":
		default:
			return nil, fmt.Errorf("claims.%s: status %q is not asserted, refuted or unknown", name, claim.Status)
		}
		switch claim.Source {
		case "hardware_proven", "verifier_derived", "provider_asserted", "operator_asserted":
		default:
			return nil, fmt.Errorf("claims.%s: source %q is not a claim source of ACI/1", name, claim.Source)
		}
		claims[name] = SessionClaim(claim)
	}
	return claims, nil
}

// sessionEvidence checks evidence.digest and, for a full record, decodes
// evidence.data and requires it to hash to the digest (§8.2).
func sessionEvidence(e *sessionEvidenceJSON, full bool) (string, *SessionEvidence, error) {
	if !isSHA256Digest(e.Digest) {
		return "", nil, errors.New("evidence.digest is not sha256:<64 lowercase hex>")
	}
	if !full {
		return e.Digest, nil, nil
	}
	evidence, err := decodeDataURI(e.Data)
	if err != nil {
		return "", nil, fmt.Errorf("evidence.data: %w", err)
	}
	sum := sha256.Sum256(evidence.Data)
	if subtle.ConstantTimeCompare([]byte("sha256:"+hex.EncodeToString(sum[:])), []byte(e.Digest)) != 1 {
		return "", nil, errors.New("evidence.data does not hash to evidence.digest")
	}
	return e.Digest, evidence, nil
}

// decodeDataURI decodes a base64 data URI (RFC 2397) with a media type.
func decodeDataURI(uri string) (*SessionEvidence, error) {
	rest, ok := strings.CutPrefix(uri, "data:")
	if !ok {
		return nil, errors.New("not a data URI")
	}
	meta, payload, ok := strings.Cut(rest, ",")
	if !ok {
		return nil, errors.New("data URI has no data")
	}
	mediaType, ok := strings.CutSuffix(meta, ";base64")
	if !ok {
		return nil, errors.New("data URI is not base64")
	}
	mt, params, err := mime.ParseMediaType(mediaType)
	if err != nil {
		return nil, fmt.Errorf("data URI media type: %w", err)
	}
	data, err := base64.StdEncoding.Strict().DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("data URI base64: %w", err)
	}
	return &SessionEvidence{MediaType: mt, Params: params, Data: data, uri: uri}, nil
}

// EvidencePart is one part of a multipart evidence bundle.
type EvidencePart struct {
	ContentType     string
	ContentID       string
	ContentLocation string
	Body            []byte
}

const maxEvidenceParts = 64

// Parts returns the parts of a multipart/mixed evidence bundle. Each part
// must carry Content-Type, a unique Content-ID and a Digest header
// "sha-256=<base64>" (RFC 3230) that matches its body.
func (e *SessionEvidence) Parts() ([]EvidencePart, error) {
	if e.MediaType != "multipart/mixed" || e.Params["boundary"] == "" {
		return nil, fmt.Errorf("evidence is %s, not a multipart/mixed bundle", e.MediaType)
	}
	reader := multipart.NewReader(bytes.NewReader(e.Data), e.Params["boundary"])
	var parts []EvidencePart
	seen := map[string]bool{}
	for {
		part, err := reader.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("evidence bundle: %w", err)
		}
		if len(parts) == maxEvidenceParts {
			return nil, fmt.Errorf("evidence bundle has more than %d parts", maxEvidenceParts)
		}
		body, err := io.ReadAll(part)
		if err != nil {
			return nil, fmt.Errorf("evidence bundle part %d: %w", len(parts), err)
		}
		p := EvidencePart{
			ContentType:     part.Header.Get("Content-Type"),
			ContentID:       part.Header.Get("Content-ID"),
			ContentLocation: part.Header.Get("Content-Location"),
			Body:            body,
		}
		if p.ContentType == "" || p.ContentID == "" {
			return nil, fmt.Errorf("evidence bundle part %d lacks Content-Type or Content-ID", len(parts))
		}
		if seen[p.ContentID] {
			return nil, fmt.Errorf("evidence bundle has Content-ID %s twice", p.ContentID)
		}
		seen[p.ContentID] = true
		if err := checkPartDigest(part.Header.Values("Digest"), body); err != nil {
			return nil, fmt.Errorf("evidence bundle part %s: %w", p.ContentID, err)
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return nil, errors.New("evidence bundle has no parts")
	}
	return parts, nil
}

func checkPartDigest(values []string, body []byte) error {
	if len(values) != 1 {
		return errors.New("expected one Digest header")
	}
	encoded, ok := strings.CutPrefix(values[0], "sha-256=")
	if !ok {
		return fmt.Errorf("digest header %q is not sha-256", values[0])
	}
	want, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("digest header: %w", err)
	}
	got := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		return errors.New("body does not match its Digest")
	}
	return nil
}

// sessionValue parses a session record or list entry into the ACI canonical
// value space: duplicate members fail, and every number must be an integer
// (Appendix A).
func sessionValue(data []byte) (map[string]any, error) {
	if err := jsonstrict.ValidateUniqueFields(data); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var v any
	if err := decoder.Decode(&v); err != nil {
		return nil, err
	}
	converted, err := integerValues(v)
	if err != nil {
		return nil, err
	}
	object, ok := converted.(map[string]any)
	if !ok {
		return nil, errors.New("expected an object")
	}
	return object, nil
}

func integerValues(v any) (any, error) {
	switch val := v.(type) {
	case json.Number:
		n, err := strconv.ParseInt(val.String(), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("number %s is not an integer", val)
		}
		return n, nil
	case []any:
		for i := range val {
			item, err := integerValues(val[i])
			if err != nil {
				return nil, err
			}
			val[i] = item
		}
		return val, nil
	case map[string]any:
		for k := range val {
			item, err := integerValues(val[k])
			if err != nil {
				return nil, err
			}
			val[k] = item
		}
		return val, nil
	default:
		return v, nil
	}
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range []byte(s) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isSHA256Digest(s string) bool {
	hexPart, ok := strings.CutPrefix(s, "sha256:")
	return ok && isLowerHex64(hexPart)
}
