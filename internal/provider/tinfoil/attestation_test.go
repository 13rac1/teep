package tinfoil

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
)

// Captured documents. SEE: the file header comment in each for provenance.
const (
	fixtureCloudRouter = "testdata/v3_cloud_router.json"
	fixtureDirectGPU   = "testdata/v3_direct_gpu.json"

	// deepseek-v4-1-flash enclaves, captured 2026-11-20 with a random nonce:
	// inf16-0 (TDX, release v0.0.10+b200) and inf22-0 (SEV-SNP,
	// v0.0.10+b300). Each serves four Blackwell GPUs.
	fixtureDirectTDXB200 = "testdata/v3_direct_tdx_b200.json"
	fixtureDirectSNPB300 = "testdata/v3_direct_snp_b300.json"
	fixtureSuperseded    = "testdata/superseded.json"
)

// docBuilder builds a v3 attestation document the way an enclave does: it
// serializes each endorsed section once, hashes those exact bytes, and derives
// REPORT_DATA from the hashes. A test that changes a field after the build
// therefore breaks the binding, which is the property under test.
type docBuilder struct {
	nonce       [32]byte
	tlsFP       [32]byte
	hpke        [32]byte
	cpuFormat   string
	cpuReport   []byte
	deviceItems []v3DeviceEvidenceItem
	collateral  []v3Collateral
}

// newDocBuilder returns a builder for a valid SEV-SNP document with no device
// evidence, which is the shape a router or a CPU-only enclave serves.
func newDocBuilder() *docBuilder {
	b := &docBuilder{
		cpuFormat: sevSNPReportV1Format,
		cpuReport: []byte("cpu-quote-bytes"),
		collateral: []v3Collateral{{
			ID:       "cpu-endorsement",
			Role:     roleEndorsement,
			Format:   "https://tinfoil.sh/collateral/amd-vcek/v1",
			Subjects: []string{"cpu"},
			Data:     json.RawMessage(`{"vcek_der_base64":"AA=="}`),
		}},
	}
	for i := range b.nonce {
		b.nonce[i] = byte(i)
		b.tlsFP[i] = byte(i + 100)
		b.hpke[i] = byte(i + 200)
	}
	return b
}

// sections returns the exact bytes of the two endorsed sections.
func (b *docBuilder) sections(t *testing.T) (cryptoBytes, deviceBytes []byte) {
	t.Helper()
	crypto := v3CryptoMaterialSection{
		Format: cryptoMaterialV1Format,
		Items: []v3CryptoMaterialItem{
			{ID: cryptoMaterialIDTLS, Format: keySPKIFPSHA256V1Format, Data: hex.EncodeToString(b.tlsFP[:])},
			{ID: cryptoMaterialIDHPKE, Format: keyX25519HPKEV1Format, Data: hex.EncodeToString(b.hpke[:])},
		},
	}
	items := b.deviceItems
	if items == nil {
		items = []v3DeviceEvidenceItem{}
	}
	device := v3DeviceEvidenceSection{Format: deviceEvidenceV1Format, Items: items}

	cryptoBytes, err := json.Marshal(crypto)
	if err != nil {
		t.Fatalf("marshal crypto_material: %v", err)
	}
	deviceBytes, err = json.Marshal(device)
	if err != nil {
		t.Fatalf("marshal device_evidence: %v", err)
	}
	return cryptoBytes, deviceBytes
}

// build returns the document body and the REPORT_DATA a quote must carry.
func (b *docBuilder) build(t *testing.T) (body []byte, reportData [64]byte) {
	t.Helper()
	cryptoBytes, deviceBytes := b.sections(t)
	cryptoHash := sha256.Sum256(cryptoBytes)
	deviceHash := sha256.Sum256(deviceBytes)

	collateral := b.collateral
	if collateral == nil {
		collateral = []v3Collateral{}
	}
	reportData = computeReportData(b.nonce[:], cryptoHash[:], deviceHash[:])
	doc := v3Document{
		Format: FormatURI,
		Challenge: v3Challenge{
			Nonce:               hex.EncodeToString(b.nonce[:]),
			ReportData:          hex.EncodeToString(reportData[:]),
			ReportDataAlgorithm: ReportDataV1Algorithm,
		},
		CPUEvidence: v3CPUEvidence{
			Format:       b.cpuFormat,
			ReportBase64: base64.StdEncoding.EncodeToString(b.cpuReport),
			Endorsed: v3Endorsed{
				CryptoMaterialHash: hex.EncodeToString(cryptoHash[:]),
				DeviceEvidenceHash: hex.EncodeToString(deviceHash[:]),
			},
		},
		CryptoMaterial: base64.StdEncoding.EncodeToString(cryptoBytes),
		DeviceEvidence: base64.StdEncoding.EncodeToString(deviceBytes),
		Collateral:     collateral,
	}
	marshaled, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	return marshaled, reportData
}

// buildMutated builds a document and then applies mutate to the decoded JSON,
// so a test can produce a document the builder itself would never emit.
func (b *docBuilder) buildMutated(t *testing.T, mutate func(m map[string]any)) []byte {
	t.Helper()
	body, _ := b.build(t)
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal for mutation: %v", err)
	}
	mutate(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal mutated document: %v", err)
	}
	return out
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return body
}

func TestParseV3Document_CapturedCloudRouter(t *testing.T) {
	raw, err := parseV3Document(readFixture(t, fixtureCloudRouter))
	if err != nil {
		t.Fatalf("parseV3Document: %v", err)
	}
	if raw.TEEHardware != HardwareAMDSEV {
		t.Errorf("TEEHardware = %q, want %q", raw.TEEHardware, HardwareAMDSEV)
	}
	if len(raw.SEVReportBytes) == 0 {
		t.Error("SEVReportBytes is empty")
	}
	if len(raw.TinfoilTLSKeyFP) != hexFieldLen {
		t.Errorf("TinfoilTLSKeyFP has %d chars, want %d", len(raw.TinfoilTLSKeyFP), hexFieldLen)
	}
	if len(raw.TinfoilHPKEKey) != hexFieldLen {
		t.Errorf("TinfoilHPKEKey has %d chars, want %d", len(raw.TinfoilHPKEKey), hexFieldLen)
	}
	if raw.TLSFingerprint != raw.TinfoilTLSKeyFP {
		t.Error("TLSFingerprint does not match the endorsed tls key")
	}
	if len(raw.TinfoilCryptoMaterialBytes) == 0 || len(raw.TinfoilDeviceEvidenceBytes) == 0 {
		t.Error("endorsed section bytes were not retained")
	}
	if len(raw.UnknownFields) != 0 || len(raw.MissingFields) != 0 {
		t.Errorf("captured document did not parse cleanly: unknown=%v missing=%v",
			raw.UnknownFields, raw.MissingFields)
	}
}

// The captured section bytes must be the bytes the enclave hashed. Recomputing
// the hashes here proves teep retained them without re-serializing.
func TestParseV3Document_RetainsHashedSectionBytes(t *testing.T) {
	raw, err := parseV3Document(readFixture(t, fixtureCloudRouter))
	if err != nil {
		t.Fatalf("parseV3Document: %v", err)
	}
	cryptoHash := sha256.Sum256(raw.TinfoilCryptoMaterialBytes)
	if got := hex.EncodeToString(cryptoHash[:]); got != raw.TinfoilEndorsedCryptoHash {
		t.Errorf("crypto_material hash = %s, endorsed %s", got, raw.TinfoilEndorsedCryptoHash)
	}
	deviceHash := sha256.Sum256(raw.TinfoilDeviceEvidenceBytes)
	if got := hex.EncodeToString(deviceHash[:]); got != raw.TinfoilEndorsedDeviceHash {
		t.Errorf("device_evidence hash = %s, endorsed %s", got, raw.TinfoilEndorsedDeviceHash)
	}
}

// A captured GPU enclave's evidence becomes an NVIDIA EAT whose nonce is the
// challenge nonce, and every GPU's certificate chain and SPDM signature
// verifies against that nonce. The collateral names the code and platform
// releases.
func TestParseV3Document_CapturedGPUEnclaves(t *testing.T) {
	tests := map[string]struct {
		path, hardware, arch, codeRepo, codeTag string
		gpus                                    int
	}{
		"hopper": {fixtureDirectGPU, HardwareAMDSEV, "HOPPER", "tinfoilsh/confidential-gemma4-31b", "v0.0.25", 1},
		"tdx_b200": {fixtureDirectTDXB200, HardwareIntelTDX, "BLACKWELL",
			"tinfoilsh/confidential-deepseek-v4-1-flash", "v0.0.10+b200", 4},
		"snp_b300": {fixtureDirectSNPB300, HardwareAMDSEV, "BLACKWELL",
			"tinfoilsh/confidential-deepseek-v4-1-flash", "v0.0.10+b300", 4},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			raw, err := parseV3Document(readFixture(t, tc.path))
			if err != nil {
				t.Fatalf("parseV3Document: %v", err)
			}
			if raw.TEEHardware != tc.hardware {
				t.Errorf("TEEHardware = %q, want %q", raw.TEEHardware, tc.hardware)
			}
			if raw.TinfoilCodeRelease.Repo != tc.codeRepo || raw.TinfoilCodeRelease.Tag != tc.codeTag {
				t.Errorf("code release = %+v, want %s@%s", raw.TinfoilCodeRelease, tc.codeRepo, tc.codeTag)
			}
			if raw.TinfoilPlatformRelease.Repo == "" || len(raw.TinfoilPlatformRelease.Digest) != hexFieldLen {
				t.Errorf("platform release = %+v", raw.TinfoilPlatformRelease)
			}
			nonceBytes, err := hex.DecodeString(raw.Nonce)
			if err != nil {
				t.Fatal(err)
			}
			var nonce attestation.Nonce
			copy(nonce[:], nonceBytes)
			r := attestation.VerifyNVIDIAPayload(context.Background(), raw.NvidiaPayload, nonce)
			if r.SignatureErr != nil || r.ClaimsErr != nil || !r.SignaturesVerified {
				t.Fatalf("GPU evidence did not verify: sig=%v claims=%v", r.SignatureErr, r.ClaimsErr)
			}
			if r.GPUCount != tc.gpus || r.Arch != tc.arch || r.Nonce != raw.Nonce {
				t.Errorf("verified %d %s GPUs with nonce %s, want %d %s with %s",
					r.GPUCount, r.Arch, r.Nonce, tc.gpus, tc.arch, raw.Nonce)
			}

			var other attestation.Nonce
			other[0] = nonce[0] ^ 1
			if r := attestation.VerifyNVIDIAPayload(context.Background(), raw.NvidiaPayload, other); r.SignaturesVerified {
				t.Error("GPU evidence verified against a nonce it does not carry")
			}
		})
	}
}

// The superseded document carries the same format URI, so the error must say
// the enclave was not migrated rather than list absent members.
func TestParseV3Document_CapturedSupersededDocument(t *testing.T) {
	_, err := parseV3Document(readFixture(t, fixtureSuperseded))
	if err == nil {
		t.Fatal("parseV3Document accepted the superseded document")
	}
	if !strings.Contains(err.Error(), "superseded") || !strings.Contains(err.Error(), "migrated") {
		t.Errorf("error does not identify the superseded document: %v", err)
	}
}

func TestParseV3Document_SEVSNP(t *testing.T) {
	body, _ := newDocBuilder().build(t)
	raw, err := parseV3Document(body)
	if err != nil {
		t.Fatalf("parseV3Document: %v", err)
	}
	if raw.TEEHardware != HardwareAMDSEV {
		t.Errorf("TEEHardware = %q, want %q", raw.TEEHardware, HardwareAMDSEV)
	}
	if raw.IntelQuote != "" {
		t.Error("IntelQuote is set for a SEV-SNP document")
	}
	if raw.NonceSource != "client" {
		t.Errorf("NonceSource = %q, want client", raw.NonceSource)
	}
	if raw.SigningAlgo != "x25519-hpke" {
		t.Errorf("SigningAlgo = %q, want x25519-hpke", raw.SigningAlgo)
	}
}

func TestParseV3Document_TDX(t *testing.T) {
	b := newDocBuilder()
	b.cpuFormat = tdxQuoteV1Format
	body, _ := b.build(t)
	raw, err := parseV3Document(body)
	if err != nil {
		t.Fatalf("parseV3Document: %v", err)
	}
	if raw.TEEHardware != HardwareIntelTDX {
		t.Errorf("TEEHardware = %q, want %q", raw.TEEHardware, HardwareIntelTDX)
	}
	if raw.IntelQuote != hex.EncodeToString(b.cpuReport) {
		t.Error("IntelQuote does not carry the decoded quote")
	}
	if len(raw.SEVReportBytes) != 0 {
		t.Error("SEVReportBytes is set for a TDX document")
	}
}

func TestParseV3Document_Rejects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(m map[string]any)
		want   string
	}{
		{
			name:   "unexpected member",
			mutate: func(m map[string]any) { m["surprise"] = "value" },
			want:   "schema mismatch",
		},
		{
			name:   "absent member",
			mutate: func(m map[string]any) { delete(m, "collateral") },
			want:   "schema mismatch",
		},
		{
			name:   "wrong document format",
			mutate: func(m map[string]any) { m["format"] = "https://tinfoil.sh/predicate/attestation/v4" },
			want:   "unexpected document format",
		},
		{
			name: "unsupported report data algorithm",
			mutate: func(m map[string]any) {
				m["challenge"].(map[string]any)["report_data_algorithm"] = "https://tinfoil.sh/report-data/v2"
			},
			want: "unsupported report_data_algorithm",
		},
		{
			name: "uppercase hex nonce",
			mutate: func(m map[string]any) {
				c := m["challenge"].(map[string]any)
				c["nonce"] = strings.ToUpper(c["nonce"].(string))
			},
			want: "not lowercase hex",
		},
		{
			name: "short nonce",
			mutate: func(m map[string]any) {
				m["challenge"].(map[string]any)["nonce"] = "abcd"
			},
			want: "challenge.nonce must be",
		},
		{
			name: "report data wrong length",
			mutate: func(m map[string]any) {
				m["challenge"].(map[string]any)["report_data"] = strings.Repeat("a", 64)
			},
			want: "challenge.report_data must be",
		},
		{
			name: "non-canonical crypto_material base64",
			mutate: func(m map[string]any) {
				m["crypto_material"] = m["crypto_material"].(string) + "\n"
			},
			want: "not canonical base64",
		},
		{
			name:   "absent crypto_material section",
			mutate: func(m map[string]any) { m["crypto_material"] = "" },
			want:   "crypto_material section is absent",
		},
		{
			name:   "absent device_evidence section",
			mutate: func(m map[string]any) { m["device_evidence"] = "" },
			want:   "device_evidence section is absent",
		},
		{
			name: "unknown cpu evidence format",
			mutate: func(m map[string]any) {
				m["cpu_evidence"].(map[string]any)["format"] = "https://tinfoil.sh/format/riscv/v1"
			},
			want: "unknown cpu_evidence format",
		},
		{
			name: "incomplete cpu evidence",
			mutate: func(m map[string]any) {
				m["cpu_evidence"].(map[string]any)["report_base64"] = ""
			},
			want: "cpu_evidence is incomplete",
		},
		{
			name: "unknown collateral role",
			mutate: func(m map[string]any) {
				m["collateral"].([]any)[0].(map[string]any)["role"] = "advice"
			},
			want: "unknown role",
		},
		{
			name: "collateral entry without id",
			mutate: func(m map[string]any) {
				m["collateral"].([]any)[0].(map[string]any)["id"] = ""
			},
			want: "collateral entry 0 is incomplete",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := newDocBuilder().buildMutated(t, tt.mutate)
			_, err := parseV3Document(body)
			if err == nil {
				t.Fatal("parseV3Document accepted the document")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestParseV3Document_RejectsDuplicateCollateralID(t *testing.T) {
	b := newDocBuilder()
	entry := b.collateral[0]
	b.collateral = []v3Collateral{entry, entry}
	body, _ := b.build(t)
	_, err := parseV3Document(body)
	if err == nil || !strings.Contains(err.Error(), "duplicate collateral entry id") {
		t.Fatalf("error = %v, want a duplicate collateral entry id", err)
	}
}

func TestParseV3Document_RejectsOversizeCollateral(t *testing.T) {
	b := newDocBuilder()
	b.collateral = make([]v3Collateral, maxCollateralEntries+1)
	for i := range b.collateral {
		b.collateral[i] = v3Collateral{
			ID:     hex.EncodeToString([]byte{byte(i)}),
			Role:   roleReferenceValues,
			Format: "https://tinfoil.sh/collateral/sigstore-code/v1",
			Data:   json.RawMessage(`{}`),
		}
	}
	body, _ := b.build(t)
	_, err := parseV3Document(body)
	if err == nil || !strings.Contains(err.Error(), "limit is") {
		t.Fatalf("error = %v, want a collateral limit error", err)
	}
}

// The two keys are required: without them teep cannot bind the TLS channel or
// encrypt to the enclave.
func TestParseV3Document_RequiresEndorsedKeys(t *testing.T) {
	tests := []struct {
		name string
		drop string
		want string
	}{
		{name: "no tls item", drop: cryptoMaterialIDTLS, want: `no "tls" item`},
		{name: "no hpke item", drop: cryptoMaterialIDHPKE, want: `no "hpke" item`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := rebuildWithCryptoItems(t, func(items []v3CryptoMaterialItem) []v3CryptoMaterialItem {
				kept := make([]v3CryptoMaterialItem, 0, len(items))
				for _, item := range items {
					if item.ID != tt.drop {
						kept = append(kept, item)
					}
				}
				return kept
			})
			_, err := parseV3Document(body)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestParseV3Document_RejectsWrongKeyFormat(t *testing.T) {
	body := rebuildWithCryptoItems(t, func(items []v3CryptoMaterialItem) []v3CryptoMaterialItem {
		for i := range items {
			if items[i].ID == cryptoMaterialIDTLS {
				items[i].Format = keyX25519HPKEV1Format
			}
		}
		return items
	})
	_, err := parseV3Document(body)
	if err == nil || !strings.Contains(err.Error(), "want") {
		t.Fatalf("error = %v, want a key format mismatch", err)
	}
}

func TestParseV3Document_RejectsDuplicateCryptoItemID(t *testing.T) {
	body := rebuildWithCryptoItems(t, func(items []v3CryptoMaterialItem) []v3CryptoMaterialItem {
		return append(items, items[0])
	})
	_, err := parseV3Document(body)
	if err == nil || !strings.Contains(err.Error(), "duplicate crypto_material item id") {
		t.Fatalf("error = %v, want a duplicate crypto_material item id", err)
	}
}

func TestParseV3Document_RejectsShortKeyData(t *testing.T) {
	body := rebuildWithCryptoItems(t, func(items []v3CryptoMaterialItem) []v3CryptoMaterialItem {
		for i := range items {
			if items[i].ID == cryptoMaterialIDHPKE {
				items[i].Data = "abcd"
			}
		}
		return items
	})
	_, err := parseV3Document(body)
	if err == nil || !strings.Contains(err.Error(), "must be 64 hex chars") {
		t.Fatalf("error = %v, want a key length error", err)
	}
}

// rebuildWithCryptoItems rewrites the crypto_material section and restores the
// hash binding, so the resulting document fails only for the reason under test.
func rebuildWithCryptoItems(t *testing.T, edit func([]v3CryptoMaterialItem) []v3CryptoMaterialItem) []byte {
	t.Helper()
	b := newDocBuilder()
	cryptoBytes, _ := b.sections(t)

	var section v3CryptoMaterialSection
	if err := json.Unmarshal(cryptoBytes, &section); err != nil {
		t.Fatalf("unmarshal crypto_material: %v", err)
	}
	section.Items = edit(section.Items)
	edited, err := json.Marshal(section)
	if err != nil {
		t.Fatalf("marshal crypto_material: %v", err)
	}
	hash := sha256.Sum256(edited)

	return b.buildMutated(t, func(m map[string]any) {
		m["crypto_material"] = base64.StdEncoding.EncodeToString(edited)
		m["cpu_evidence"].(map[string]any)["endorsed"].(map[string]any)["crypto_material_hash"] =
			hex.EncodeToString(hash[:])
	})
}

// gpuItem is one GPU evidence item with the builder's nonce.
func gpuItem(b *docBuilder, id string) v3DeviceEvidenceItem {
	ev, err := json.Marshal(nvidiaGPUEvidence{
		Arch: "BLACKWELL", Certificate: "Y2VydA==", Evidence: "ZXZpZGVuY2U=", Nonce: hex.EncodeToString(b.nonce[:]),
	})
	if err != nil {
		panic(err)
	}
	return v3DeviceEvidenceItem{ID: id, Kind: "gpu", Vendor: "nvidia", Format: NvidiaGPUEvidenceV1Format, Evidence: ev}
}

func TestParseV3Document_ReadsGPUEvidence(t *testing.T) {
	b := newDocBuilder()
	b.deviceItems = []v3DeviceEvidenceItem{gpuItem(b, "gpu0"), gpuItem(b, "gpu1")}
	body, _ := b.build(t)
	raw, err := parseV3Document(body)
	if err != nil {
		t.Fatalf("parseV3Document: %v", err)
	}
	var eat nvidiaEAT
	if err := json.Unmarshal([]byte(raw.NvidiaPayload), &eat); err != nil {
		t.Fatalf("NvidiaPayload is not an EAT: %v", err)
	}
	if eat.Nonce != hex.EncodeToString(b.nonce[:]) || eat.Arch != "BLACKWELL" || len(eat.EvidenceList) != 2 ||
		eat.EvidenceList[1].Evidence != "ZXZpZGVuY2U=" {
		t.Errorf("EAT = %+v", eat)
	}
}

// A document with no device evidence carries no NVIDIA payload.
func TestParseV3Document_NoDevices(t *testing.T) {
	body, _ := newDocBuilder().build(t)
	raw, err := parseV3Document(body)
	if err != nil {
		t.Fatalf("parseV3Document: %v", err)
	}
	if raw.NvidiaPayload != "" {
		t.Errorf("NvidiaPayload = %q, want empty", raw.NvidiaPayload)
	}
}

func TestParseV3Document_RejectsDeviceEvidence(t *testing.T) {
	tests := map[string]struct {
		edit func(b *docBuilder, items []v3DeviceEvidenceItem)
		want string
	}{
		"unknown format": {func(_ *docBuilder, it []v3DeviceEvidenceItem) { it[0].Format = "https://tinfoil.sh/format/nvswitch/v1" }, "not evidence teep reads"},
		"other kind":     {func(_ *docBuilder, it []v3DeviceEvidenceItem) { it[0].Kind = "nvswitch" }, "not evidence teep reads"},
		"other vendor":   {func(_ *docBuilder, it []v3DeviceEvidenceItem) { it[0].Vendor = "amd" }, "not evidence teep reads"},
		"repeated id":    {func(_ *docBuilder, it []v3DeviceEvidenceItem) { it[1].ID = it[0].ID }, "empty or repeated"},
		"other nonce": {func(b *docBuilder, it []v3DeviceEvidenceItem) {
			it[1].Evidence = []byte(strings.Replace(string(it[1].Evidence), hex.EncodeToString(b.nonce[:]), strings.Repeat("ab", 32), 1))
		}, "not the challenge nonce"},
		"mixed arch": {func(_ *docBuilder, it []v3DeviceEvidenceItem) {
			it[1].Evidence = []byte(strings.Replace(string(it[1].Evidence), "BLACKWELL", "HOPPER", 1))
		}, "arch"},
		"extra field": {func(_ *docBuilder, it []v3DeviceEvidenceItem) {
			it[0].Evidence = []byte(strings.Replace(string(it[0].Evidence), "{", `{"nvswitch":"x",`, 1))
		}, "schema mismatch"},
		"absent field": {func(_ *docBuilder, it []v3DeviceEvidenceItem) {
			it[0].Evidence = []byte(strings.Replace(string(it[0].Evidence), `"certificate":"Y2VydA==",`, "", 1))
		}, "schema mismatch"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			b := newDocBuilder()
			items := []v3DeviceEvidenceItem{gpuItem(b, "gpu0"), gpuItem(b, "gpu1")}
			tc.edit(b, items)
			b.deviceItems = items
			body, _ := b.build(t)
			_, err := parseV3Document(body)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("parseV3Document err = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestReadReleases(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	entry := func(id, format, repo, tag, digest string) v3Collateral {
		data, err := json.Marshal(v3ReleaseCollateral{Repo: repo, Tag: tag, Digest: digest, SigstoreBundle: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		return v3Collateral{ID: id, Role: roleReferenceValues, Format: format, Data: data}
	}
	code, platform, err := readReleases([]v3Collateral{
		entry("code", sigstoreCodeV1Format, "tinfoilsh/confidential-x", "v0.0.1+b200", digest),
		entry("platform", sigstorePlatformV1Format, PlatformRepo, "platform-v0.1.15", digest),
		{ID: "code-freshness", Role: roleReferenceValues, Format: sigstoreFreshnessV1Format, Data: json.RawMessage(`{"sigstore_bundle":{"b":1}}`)},
		{ID: "platform-freshness", Role: roleReferenceValues, Format: sigstoreFreshnessV1Format, Data: json.RawMessage(`{"sigstore_bundle":{"b":2}}`)},
	})
	if err != nil {
		t.Fatalf("readReleases: %v", err)
	}
	if code.Repo != "tinfoilsh/confidential-x" || code.Tag != "v0.0.1+b200" || platform.Tag != "platform-v0.1.15" {
		t.Errorf("code = %+v, platform = %+v", code, platform)
	}
	if string(code.Freshness) != `{"b":1}` || string(platform.Freshness) != `{"b":2}` {
		t.Errorf("freshness bundles = %s, %s", code.Freshness, platform.Freshness)
	}

	for name, e := range map[string]v3Collateral{
		"bad repo":   entry("code", sigstoreCodeV1Format, "not a repo", "v1.0.0", digest),
		"bad tag":    entry("code", sigstoreCodeV1Format, "tinfoilsh/x", "v1/../x", digest),
		"bad digest": entry("platform", sigstorePlatformV1Format, PlatformRepo, "platform-v1.0.0", "ABCD"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := readReleases([]v3Collateral{e}); err == nil {
				t.Error("readReleases accepted an invalid release")
			}
		})
	}
}

func TestParseV3Document_RejectsOversizeCPUQuote(t *testing.T) {
	b := newDocBuilder()
	b.cpuReport = make([]byte, maxCPUReportSize+1)
	body, _ := b.build(t)
	_, err := parseV3Document(body)
	if err == nil || !strings.Contains(err.Error(), "limit is") {
		t.Fatalf("error = %v, want a cpu quote size error", err)
	}
}

func TestDecodeCanonicalBase64(t *testing.T) {
	raw := []byte{0xde, 0xad, 0xbe, 0xef}
	encoded := base64.StdEncoding.EncodeToString(raw)

	got, err := decodeCanonicalBase64("field", encoded)
	if err != nil {
		t.Fatalf("decodeCanonicalBase64: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("decoded %x, want %x", got, raw)
	}

	// A newline decodes under StdEncoding but is a second spelling of the same
	// bytes, so an endorsed section would have two hashes.
	if _, err := decodeCanonicalBase64("field", encoded+"\n"); err == nil {
		t.Error("decodeCanonicalBase64 accepted a non-canonical spelling")
	}
}

func TestCheckLowerHex(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantLen int
		wantErr bool
	}{
		{name: "valid", value: strings.Repeat("ab", 32), wantLen: 64},
		{name: "uppercase", value: strings.Repeat("AB", 32), wantLen: 64, wantErr: true},
		{name: "wrong length", value: "abcd", wantLen: 64, wantErr: true},
		{name: "not hex", value: strings.Repeat("zz", 32), wantLen: 64, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkLowerHex("field", tt.value, tt.wantLen)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkLowerHex error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
