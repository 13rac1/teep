package tinfoil

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/jsonstrict"
)

// Size limits on an untrusted attestation response.
const (
	// maxBodySize is the maximum attestation response body size (4 MiB).
	maxBodySize = 4 << 20

	// maxCPUReportSize is the upper bound on the decoded CPU quote (10 MiB).
	maxCPUReportSize = 10 << 20

	// maxCollateralEntries bounds the collateral array. An enclave serves six
	// entries; the limit leaves room for new ones without admitting an
	// unbounded array.
	maxCollateralEntries = 32

	// maxSectionItems bounds the item count in either endorsed section. The
	// largest shape is eight GPUs plus NVSwitch evidence.
	maxSectionItems = 32
)

// hexFieldLen is the length of a hex-encoded 32-byte field.
const hexFieldLen = 64

// reportDataLen is the length of a hex-encoded 64-byte REPORT_DATA value.
const reportDataLen = 128

// Format URIs of the v3 attestation document and its members. These come from
// the format registry in the tinfoil-go verifier/envelope package, which is the
// definition both the enclave and the verifier follow.
const (
	// FormatURI identifies the v3 attestation document.
	FormatURI = "https://tinfoil.sh/predicate/attestation/v3"

	// ReportDataV1Algorithm identifies the REPORT_DATA derivation and is
	// written into the hash as a domain separation label.
	ReportDataV1Algorithm = "https://tinfoil.sh/report-data/v1"

	cryptoMaterialV1Format = "https://tinfoil.sh/crypto-material/v1"
	deviceEvidenceV1Format = "https://tinfoil.sh/device-evidence/v1"

	sevSNPReportV1Format = "https://tinfoil.sh/format/sev-snp-report/v1"
	tdxQuoteV1Format     = "https://tinfoil.sh/format/tdx-quote/v1"

	// NvidiaGPUEvidenceV1Format is the item format of one GPU's evidence.
	NvidiaGPUEvidenceV1Format = "https://tinfoil.sh/format/nvidia-gpu-evidence/v1"

	keySPKIFPSHA256V1Format = "https://tinfoil.sh/key/spki-fp-sha256/v1"
	keyX25519HPKEV1Format   = "https://tinfoil.sh/key/x25519-hpke/v1"
)

// Item and collateral identifiers.
const (
	cryptoMaterialIDTLS  = "tls"
	cryptoMaterialIDHPKE = "hpke"

	roleEndorsement     = "endorsement"
	roleReferenceValues = "reference-values"

	collateralIDCode          = "code"
	collateralIDPlatform      = "platform"
	sigstoreCodeV1Format      = "https://tinfoil.sh/collateral/sigstore-code/v1"
	sigstorePlatformV1Format  = "https://tinfoil.sh/collateral/sigstore-platform/v1"
	sigstoreFreshnessV1Format = "https://tinfoil.sh/collateral/sigstore-freshness/v1"
)

// v3ReleaseCollateral is the data of a "code" or "platform" collateral entry.
// teep reads only the release name; it fetches the Sigstore bundle itself.
type v3ReleaseCollateral struct {
	Repo           string          `json:"repo"`
	Tag            string          `json:"tag"`
	Digest         string          `json:"digest"`
	SigstoreBundle json.RawMessage `json:"sigstore_bundle"`
}

// releaseTagRE bounds a release tag to the characters GitHub tags use here.
var releaseTagRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

// readReleases returns the code and platform releases the collateral names,
// each with its freshness witness bundle. An absent entry leaves its field
// empty; supply chain verification then fails with the reason.
func readReleases(entries []v3Collateral) (code, platform attestation.TinfoilRelease, err error) {
	for _, e := range entries {
		if e.Format == sigstoreFreshnessV1Format && (e.ID == collateralIDCode+"-freshness" || e.ID == collateralIDPlatform+"-freshness") {
			var c struct {
				SigstoreBundle json.RawMessage `json:"sigstore_bundle"`
			}
			if err := json.Unmarshal(e.Data, &c); err != nil {
				return code, platform, fmt.Errorf("tinfoil: collateral %q: %w", e.ID, err)
			}
			if e.ID == collateralIDCode+"-freshness" {
				code.Freshness = c.SigstoreBundle
			} else {
				platform.Freshness = c.SigstoreBundle
			}
		}
	}
	for _, e := range entries {
		var dst *attestation.TinfoilRelease
		switch {
		case e.ID == collateralIDCode && e.Format == sigstoreCodeV1Format:
			dst = &code
		case e.ID == collateralIDPlatform && e.Format == sigstorePlatformV1Format:
			dst = &platform
		default:
			continue
		}
		var c v3ReleaseCollateral
		if err := json.Unmarshal(e.Data, &c); err != nil {
			return code, platform, fmt.Errorf("tinfoil: collateral %q: %w", e.ID, err)
		}
		if !isValidSigstoreRepo(c.Repo) || !releaseTagRE.MatchString(c.Tag) {
			return code, platform, fmt.Errorf("tinfoil: collateral %q names an invalid release %q@%q", e.ID, c.Repo, c.Tag)
		}
		if err := checkLowerHex("collateral "+e.ID+" digest", c.Digest, hexFieldLen); err != nil {
			return code, platform, err
		}
		dst.Repo, dst.Tag, dst.Digest = c.Repo, c.Tag, c.Digest
	}
	return code, platform, nil
}

// supersededMembers are top-level members of the attestation document teep
// removed. The replacement document carries none of them, so any one of them
// identifies an enclave that still serves the superseded document.
var supersededMembers = []string{"report_data", "certificate", "signature", "cpu"}

// v3Document is the wire shape of a v3 attestation document.
//
// The two endorsed sections travel base64-encoded. The enclave serializes each
// section once and hashes those exact bytes into the CPU quote's REPORT_DATA,
// so a verifier recovers them with a plain decode and never re-serializes.
type v3Document struct {
	Format         string         `json:"format"`
	Challenge      v3Challenge    `json:"challenge"`
	CPUEvidence    v3CPUEvidence  `json:"cpu_evidence"`
	CryptoMaterial string         `json:"crypto_material"`
	DeviceEvidence string         `json:"device_evidence"`
	Collateral     []v3Collateral `json:"collateral"`
}

// v3Challenge binds the document to the nonce the client chose.
type v3Challenge struct {
	Nonce               string `json:"nonce"`
	ReportData          string `json:"report_data"`
	ReportDataAlgorithm string `json:"report_data_algorithm"`
}

// v3CPUEvidence is the hardware quote and the endorsed-section hashes it binds.
type v3CPUEvidence struct {
	Format       string     `json:"format"`
	ReportBase64 string     `json:"report_base64"`
	Endorsed     v3Endorsed `json:"endorsed"`
}

// v3Endorsed holds the hashes of the two endorsed sections.
type v3Endorsed struct {
	CryptoMaterialHash string `json:"crypto_material_hash"`
	DeviceEvidenceHash string `json:"device_evidence_hash"`
}

// v3Collateral is one self-describing collateral record. Collateral is
// unendorsed transport: an entry proves nothing until its own signature chain
// is verified, so teep bounds and structurally validates the array and reads
// no entry data.
type v3Collateral struct {
	ID       string          `json:"id"`
	Role     string          `json:"role"`
	Format   string          `json:"format"`
	Subjects []string        `json:"subjects,omitempty"`
	Data     json.RawMessage `json:"data"`
}

// v3CryptoMaterialSection is the endorsed crypto_material section.
type v3CryptoMaterialSection struct {
	Format string                 `json:"format"`
	Items  []v3CryptoMaterialItem `json:"items"`
}

// v3CryptoMaterialItem is one endorsed key. The item format URI determines how
// Data is read.
type v3CryptoMaterialItem struct {
	ID     string `json:"id"`
	Format string `json:"format"`
	Data   string `json:"data"`
}

// v3DeviceEvidenceSection is the endorsed device_evidence section. An enclave
// with no attestable device serves an empty item list; the section is always
// present.
type v3DeviceEvidenceSection struct {
	Format string                 `json:"format"`
	Items  []v3DeviceEvidenceItem `json:"items"`
}

// v3DeviceEvidenceItem is one device's evidence.
type v3DeviceEvidenceItem struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	Vendor   string          `json:"vendor"`
	Format   string          `json:"format"`
	Evidence json.RawMessage `json:"evidence"`
}

// parseV3Document parses a v3 attestation document into a RawAttestation.
//
// The steps are: reject a superseded or drifted schema, check the document and
// algorithm identity, decode the two endorsed sections, structurally validate
// the collateral array, read the TLS and HPKE keys, and decode the CPU quote.
//
// Parsing authenticates nothing. Every value it returns is a claim until
// VerifyReportData proves the hardware bound it.
func parseV3Document(body []byte) (*attestation.RawAttestation, error) {
	var doc v3Document
	unknown, missing, err := jsonstrict.UnmarshalWarn(body, &doc, "tinfoil v3")
	if err != nil {
		return nil, fmt.Errorf("tinfoil: unmarshal v3 document: %w", err)
	}
	if err := rejectSupersededDocument(unknown); err != nil {
		return nil, err
	}
	if err := rejectSchemaDrift(unknown, missing); err != nil {
		return nil, err
	}
	if err := checkDocumentIdentity(&doc); err != nil {
		return nil, err
	}

	cryptoBytes, deviceBytes, err := decodeEndorsedSections(&doc)
	if err != nil {
		return nil, err
	}
	if err := checkCollateral(doc.Collateral); err != nil {
		return nil, err
	}
	codeRelease, platformRelease, err := readReleases(doc.Collateral)
	if err != nil {
		return nil, err
	}

	crypto, err := parseCryptoMaterial(cryptoBytes)
	if err != nil {
		return nil, err
	}
	tlsKeyFP, hpkeKey, err := endorsedKeys(crypto)
	if err != nil {
		return nil, err
	}
	nvidiaPayload, err := readDeviceEvidence(deviceBytes, doc.Challenge.Nonce)
	if err != nil {
		return nil, err
	}

	raw := &attestation.RawAttestation{
		BackendFormat:  attestation.FormatTinfoil,
		NonceSource:    "client",
		Nonce:          doc.Challenge.Nonce,
		SigningKey:     hpkeKey,
		SigningAlgo:    "x25519-hpke",
		TLSFingerprint: tlsKeyFP,
		UnknownFields:  unknown,
		MissingFields:  missing,
		RawBody:        body,
		NvidiaPayload:  nvidiaPayload,

		TinfoilTLSKeyFP:            tlsKeyFP,
		TinfoilHPKEKey:             hpkeKey,
		TinfoilNonce:               doc.Challenge.Nonce,
		TinfoilCryptoMaterialBytes: cryptoBytes,
		TinfoilDeviceEvidenceBytes: deviceBytes,
		TinfoilEndorsedCryptoHash:  doc.CPUEvidence.Endorsed.CryptoMaterialHash,
		TinfoilEndorsedDeviceHash:  doc.CPUEvidence.Endorsed.DeviceEvidenceHash,
		TinfoilChallengeReportData: doc.Challenge.ReportData,
		TinfoilCodeRelease:         codeRelease,
		TinfoilPlatformRelease:     platformRelease,
	}
	if err := decodeCPUQuote(&doc, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// rejectSupersededDocument reports an enclave that still serves the attestation
// document teep removed. Both documents carry the same format URI, so without
// this check the operator reads a list of unexpected and absent members and has
// to work out what it means.
func rejectSupersededDocument(unknown []string) error {
	var found []string
	for _, m := range supersededMembers {
		if slices.Contains(unknown, m) {
			found = append(found, m)
		}
	}
	if len(found) == 0 {
		return nil
	}
	return fmt.Errorf("tinfoil: enclave serves the superseded attestation document (members %s); "+
		"it has not been migrated to the endorsed-section format that teep verifies",
		strings.Join(found, ", "))
}

// rejectSchemaDrift fails on any unexpected or absent member. The caller owns
// this policy: a document teep cannot fully account for is not a document it
// can verify.
func rejectSchemaDrift(unknown, missing []string) error {
	if len(unknown) == 0 && len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("tinfoil: v3 document schema mismatch: unexpected members %v, absent members %v",
		unknown, missing)
}

// checkDocumentIdentity checks the format URIs and the fixed-length hex fields.
//
// The format URI no longer separates the two documents that Tinfoil serves, so
// report_data_algorithm is what identifies the derivation teep implements.
func checkDocumentIdentity(doc *v3Document) error {
	if doc.Format != FormatURI {
		return fmt.Errorf("tinfoil: unexpected document format %q, want %q", doc.Format, FormatURI)
	}
	if doc.Challenge.ReportDataAlgorithm != ReportDataV1Algorithm {
		return fmt.Errorf("tinfoil: unsupported report_data_algorithm %q, want %q",
			doc.Challenge.ReportDataAlgorithm, ReportDataV1Algorithm)
	}
	if err := checkLowerHex("challenge.nonce", doc.Challenge.Nonce, hexFieldLen); err != nil {
		return err
	}
	if err := checkLowerHex("challenge.report_data", doc.Challenge.ReportData, reportDataLen); err != nil {
		return err
	}
	if err := checkLowerHex("cpu_evidence.endorsed.crypto_material_hash",
		doc.CPUEvidence.Endorsed.CryptoMaterialHash, hexFieldLen); err != nil {
		return err
	}
	if err := checkLowerHex("cpu_evidence.endorsed.device_evidence_hash",
		doc.CPUEvidence.Endorsed.DeviceEvidenceHash, hexFieldLen); err != nil {
		return err
	}
	if doc.CPUEvidence.Format == "" || doc.CPUEvidence.ReportBase64 == "" {
		return errors.New("tinfoil: cpu_evidence is incomplete")
	}
	return nil
}

// decodeEndorsedSections returns the exact bytes the enclave hashed.
func decodeEndorsedSections(doc *v3Document) (cryptoBytes, deviceBytes []byte, err error) {
	if doc.CryptoMaterial == "" {
		return nil, nil, errors.New("tinfoil: crypto_material section is absent")
	}
	if doc.DeviceEvidence == "" {
		return nil, nil, errors.New("tinfoil: device_evidence section is absent")
	}
	cryptoBytes, err = decodeCanonicalBase64("crypto_material", doc.CryptoMaterial)
	if err != nil {
		return nil, nil, err
	}
	deviceBytes, err = decodeCanonicalBase64("device_evidence", doc.DeviceEvidence)
	if err != nil {
		return nil, nil, err
	}
	return cryptoBytes, deviceBytes, nil
}

// checkCollateral validates the structure of the collateral array. teep reads
// no entry data, so this bounds the array and rejects a shape it cannot
// account for.
func checkCollateral(entries []v3Collateral) error {
	if len(entries) > maxCollateralEntries {
		return fmt.Errorf("tinfoil: collateral has %d entries, limit is %d",
			len(entries), maxCollateralEntries)
	}
	seen := make(map[string]bool, len(entries))
	for i, e := range entries {
		if e.ID == "" || e.Format == "" {
			return fmt.Errorf("tinfoil: collateral entry %d is incomplete", i)
		}
		if seen[e.ID] {
			return fmt.Errorf("tinfoil: duplicate collateral entry id %q", e.ID)
		}
		seen[e.ID] = true
		if e.Role != roleEndorsement && e.Role != roleReferenceValues {
			return fmt.Errorf("tinfoil: collateral entry %q has unknown role %q", e.ID, e.Role)
		}
	}
	return nil
}

// parseCryptoMaterial parses and validates the endorsed crypto_material section.
func parseCryptoMaterial(sectionBytes []byte) (*v3CryptoMaterialSection, error) {
	var section v3CryptoMaterialSection
	unknown, missing, err := jsonstrict.UnmarshalWarn(sectionBytes, &section, "tinfoil crypto_material")
	if err != nil {
		return nil, fmt.Errorf("tinfoil: unmarshal crypto_material: %w", err)
	}
	if len(unknown) > 0 || len(missing) > 0 {
		return nil, fmt.Errorf("tinfoil: crypto_material schema mismatch: unexpected %v, absent %v",
			unknown, missing)
	}
	if section.Format != cryptoMaterialV1Format {
		return nil, fmt.Errorf("tinfoil: unsupported crypto_material format %q, want %q",
			section.Format, cryptoMaterialV1Format)
	}
	if len(section.Items) > maxSectionItems {
		return nil, fmt.Errorf("tinfoil: crypto_material has %d items, limit is %d",
			len(section.Items), maxSectionItems)
	}
	seen := make(map[string]bool, len(section.Items))
	for _, item := range section.Items {
		if item.ID == "" || item.Format == "" {
			return nil, errors.New("tinfoil: crypto_material item is incomplete")
		}
		if seen[item.ID] {
			return nil, fmt.Errorf("tinfoil: duplicate crypto_material item id %q", item.ID)
		}
		seen[item.ID] = true
	}
	return &section, nil
}

// endorsedKeys returns the TLS SPKI fingerprint and the HPKE public key.
//
// Both are required. Without the fingerprint teep cannot bind the TLS channel
// to the enclave, and without the HPKE key it cannot encrypt to it.
func endorsedKeys(section *v3CryptoMaterialSection) (tlsKeyFP, hpkeKey string, err error) {
	tlsKeyFP, err = endorsedKey(section, cryptoMaterialIDTLS, keySPKIFPSHA256V1Format)
	if err != nil {
		return "", "", err
	}
	hpkeKey, err = endorsedKey(section, cryptoMaterialIDHPKE, keyX25519HPKEV1Format)
	if err != nil {
		return "", "", err
	}
	return tlsKeyFP, hpkeKey, nil
}

// endorsedKey returns the 32-byte hex value of one crypto_material item,
// requiring the item to carry the format the caller expects.
func endorsedKey(section *v3CryptoMaterialSection, id, wantFormat string) (string, error) {
	for _, item := range section.Items {
		if item.ID != id {
			continue
		}
		if item.Format != wantFormat {
			return "", fmt.Errorf("tinfoil: crypto_material item %q has format %q, want %q",
				id, item.Format, wantFormat)
		}
		if err := checkLowerHex("crypto_material item "+id, item.Data, hexFieldLen); err != nil {
			return "", err
		}
		return item.Data, nil
	}
	return "", fmt.Errorf("tinfoil: crypto_material has no %q item", id)
}

// nvidiaGPUEvidence is the evidence of one NVIDIA GPU item: the SPDM
// GET_MEASUREMENTS exchange, the device certificate chain, the GPU
// architecture, and the nonce the enclave sent the GPU as the SPDM requester
// nonce. The first three are the fields of one NVIDIA EAT evidence_list entry.
type nvidiaGPUEvidence struct {
	Arch        string `json:"arch"`
	Certificate string `json:"certificate"`
	Evidence    string `json:"evidence"`
	Nonce       string `json:"nonce"`
}

// nvidiaEAT is the NVIDIA EAT envelope teep's NVIDIA verifier reads.
type nvidiaEAT struct {
	Arch         string           `json:"arch"`
	Nonce        string           `json:"nonce"`
	EvidenceList []nvidiaEATEntry `json:"evidence_list"`
}

type nvidiaEATEntry struct {
	Arch        string `json:"arch"`
	Certificate string `json:"certificate"`
	Evidence    string `json:"evidence"`
}

// readDeviceEvidence parses the endorsed device_evidence section and returns
// its GPU evidence as an NVIDIA EAT payload, or "" when the enclave reports no
// device.
//
// The section is hash-bound into REPORT_DATA, so once VerifyReportData passes
// every item is the enclave's own claim. The EAT is built from the item fields
// unchanged, with the challenge nonce as the EAT nonce. The NVIDIA verifier
// then checks each GPU's certificate chain, its SPDM signature, and that the
// SPDM requester nonce is the client nonce, and NRAS appraises the same EAT.
//
// An item teep does not read fails the document: teep must not report device
// evidence it has not verified.
func readDeviceEvidence(sectionBytes []byte, challengeNonce string) (string, error) {
	var section v3DeviceEvidenceSection
	unknown, missing, err := jsonstrict.UnmarshalWarn(sectionBytes, &section, "tinfoil device_evidence")
	if err != nil {
		return "", fmt.Errorf("tinfoil: unmarshal device_evidence: %w", err)
	}
	if len(unknown) > 0 || len(missing) > 0 {
		return "", fmt.Errorf("tinfoil: device_evidence schema mismatch: unexpected %v, absent %v",
			unknown, missing)
	}
	if section.Format != deviceEvidenceV1Format {
		return "", fmt.Errorf("tinfoil: unsupported device_evidence format %q, want %q",
			section.Format, deviceEvidenceV1Format)
	}
	if len(section.Items) > maxSectionItems {
		return "", fmt.Errorf("tinfoil: device_evidence has %d items, limit is %d",
			len(section.Items), maxSectionItems)
	}
	if len(section.Items) == 0 {
		return "", nil
	}
	eat := nvidiaEAT{Nonce: challengeNonce, EvidenceList: make([]nvidiaEATEntry, 0, len(section.Items))}
	seen := make(map[string]bool, len(section.Items))
	for _, item := range section.Items {
		if item.Format != NvidiaGPUEvidenceV1Format || item.Kind != "gpu" || item.Vendor != "nvidia" {
			return "", fmt.Errorf("tinfoil: device_evidence item %q (kind %q, vendor %q, format %q) is not evidence teep reads",
				item.ID, item.Kind, item.Vendor, item.Format)
		}
		if item.ID == "" || seen[item.ID] {
			return "", fmt.Errorf("tinfoil: device_evidence item id %q is empty or repeated", item.ID)
		}
		seen[item.ID] = true
		var gpu nvidiaGPUEvidence
		unknown, missing, err := jsonstrict.UnmarshalWarn(item.Evidence, &gpu, "tinfoil nvidia-gpu-evidence")
		if err != nil {
			return "", fmt.Errorf("tinfoil: unmarshal GPU evidence %q: %w", item.ID, err)
		}
		if len(unknown) > 0 || len(missing) > 0 {
			return "", fmt.Errorf("tinfoil: GPU evidence %q schema mismatch: unexpected %v, absent %v",
				item.ID, unknown, missing)
		}
		if gpu.Nonce != challengeNonce {
			return "", fmt.Errorf("tinfoil: GPU evidence %q nonce %q is not the challenge nonce",
				item.ID, attestation.NoncePrefix(gpu.Nonce))
		}
		if eat.Arch == "" {
			eat.Arch = gpu.Arch
		}
		if gpu.Arch == "" || gpu.Arch != eat.Arch {
			return "", fmt.Errorf("tinfoil: GPU evidence %q arch %q differs from %q", item.ID, gpu.Arch, eat.Arch)
		}
		eat.EvidenceList = append(eat.EvidenceList, nvidiaEATEntry{
			Arch: gpu.Arch, Certificate: gpu.Certificate, Evidence: gpu.Evidence,
		})
	}
	b, err := json.Marshal(eat)
	if err != nil {
		return "", fmt.Errorf("tinfoil: marshal GPU EAT: %w", err)
	}
	return string(b), nil
}

// decodeCPUQuote decodes the CPU quote and selects the TEE hardware from the
// evidence format URI.
func decodeCPUQuote(doc *v3Document, raw *attestation.RawAttestation) error {
	reportBytes, err := decodeCanonicalBase64("cpu_evidence.report_base64", doc.CPUEvidence.ReportBase64)
	if err != nil {
		return err
	}
	if len(reportBytes) > maxCPUReportSize {
		return fmt.Errorf("tinfoil: cpu quote is %d bytes, limit is %d", len(reportBytes), maxCPUReportSize)
	}
	switch doc.CPUEvidence.Format {
	case tdxQuoteV1Format:
		raw.TEEHardware = HardwareIntelTDX
		raw.IntelQuote = hex.EncodeToString(reportBytes)
	case sevSNPReportV1Format:
		raw.TEEHardware = HardwareAMDSEV
		raw.SEVReportBytes = reportBytes
	default:
		return fmt.Errorf("tinfoil: unknown cpu_evidence format %q", doc.CPUEvidence.Format)
	}
	return nil
}

// lowerHexRE matches a lowercase hex string. Uppercase is rejected so one byte
// string has exactly one accepted spelling.
var lowerHexRE = regexp.MustCompile(`^[0-9a-f]*$`)

// checkLowerHex checks that a field is lowercase hex of an exact character
// length. Callers keep the hex string, so it is never decoded here.
func checkLowerHex(name, value string, wantLen int) error {
	if len(value) != wantLen {
		return fmt.Errorf("tinfoil: %s must be %d hex chars, got %d", name, wantLen, len(value))
	}
	if !lowerHexRE.MatchString(value) {
		return fmt.Errorf("tinfoil: %s is not lowercase hex", name)
	}
	return nil
}

// decodeCanonicalBase64 decodes a standard-base64 field and rejects
// non-canonical spellings.
//
// Strict rejects non-zero padding bits but still skips carriage returns and
// newlines, so the round-trip comparison is what leaves exactly one accepted
// spelling per byte string. An endorsed section is hashed by its bytes, so a
// second spelling of the same section would be a second hash.
func decodeCanonicalBase64(name, value string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("tinfoil: decoding %s: %w", name, err)
	}
	if base64.StdEncoding.EncodeToString(b) != value {
		return nil, fmt.Errorf("tinfoil: %s is not canonical base64", name)
	}
	return b, nil
}
