package chutes

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
)

func TestDefaultMeasurementPolicy(t *testing.T) {
	p := DefaultMeasurementPolicy()

	if !p.HasMRSeamPolicy() {
		t.Error("DefaultMeasurementPolicy should have MRSeamAllow")
	}
	if !p.HasMRTDPolicy() {
		t.Error("DefaultMeasurementPolicy should have MRTDAllow")
	}

	// MRSEAM must include both shared dstack values and chutes-specific values.
	dstackBase := attestation.DstackBaseMeasurementPolicy()
	for h := range dstackBase.MRSeamAllow {
		if _, ok := p.MRSeamAllow[h]; !ok {
			t.Errorf("MRSeamAllow missing shared dstack entry %s...", h[:16])
		}
	}
	for h := range Sek8sMRSEAMAllow {
		if _, ok := p.MRSeamAllow[h]; !ok {
			t.Errorf("MRSeamAllow missing sek8s entry %s...", h[:16])
		}
	}
	if len(p.MRSeamAllow) != len(Sek8sMRSEAMAllow) {
		t.Errorf("MRSeamAllow has %d entries, want %d", len(p.MRSeamAllow), len(Sek8sMRSEAMAllow))
	}

	// MRTD must contain the sek8s OVMF value.
	for h := range Sek8sMRTDAllow {
		if _, ok := p.MRTDAllow[h]; !ok {
			t.Errorf("MRTDAllow missing sek8s entry %s...", h[:16])
		}
	}

	// RTMR0-2 must be configured.
	for i := range 3 {
		if !p.HasRTMRPolicy(i) {
			t.Errorf("DefaultMeasurementPolicy should have RTMR%d policy", i)
		}
	}

	// RTMR3 must not be configured (runtime IMA, validator-side only).
	if p.HasRTMRPolicy(3) {
		t.Error("DefaultMeasurementPolicy should not have RTMR3 policy")
	}
}

// The measurements of a sek8s 1.4.1 instance (8xpro_6000 numa-124c-768g)
// that teep verified live on 2026-11-01 are allowed, and so are both TDX
// modules of that fleet.
func TestDefaultMeasurementPolicyAcceptsSek8s141(t *testing.T) {
	p := DefaultMeasurementPolicy()
	for _, tc := range []struct {
		name  string
		allow map[string]struct{}
		value string
	}{
		{"MRSEAM 1.5.16", p.MRSeamAllow, "7bf063280e94fb051f5dd7b1fc59ce9aac42bb961df8d44b709c9b0ff87a7b4df648657ba6d1189589feab1d5a3c9a9d"},
		{"MRSEAM 1.5.34", p.MRSeamAllow, "ab62561a173acbd18ee50ff37750db44184c6cf5e886df74247cc575e163b04c34b9e18374757c235affa614d4127f6b"},
		{"MRTD", p.MRTDAllow, "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d"},
		{"RTMR0", p.RTMRAllow[0], "bacb4abf7b19aba4a8307ebc7244706745de4fa627e669e7f06fd35c3303eea1903f58dc143d27b557da1a986e0e95f6"},
		{"RTMR1", p.RTMRAllow[1], "d3a862ff47357f374fc72c7f02a480a13790d1805e24aaa8de1f03994256625ce0f593ae35ea8f0c24d09f7df36cb0ed"},
		{"RTMR2", p.RTMRAllow[2], "da23f73e0fddeb8128f706ecfbecbcf8cee34af7e4907d8fbc85e9b216acee27bf6cc3655eaf4d33cab76adea79fa153"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := tc.allow[tc.value]; !ok {
				t.Errorf("%s... is not allowed", tc.value[:16])
			}
		})
	}
}

// The sek8s 1.3.0 measurements of the instance that teep selects in the
// Chutes captures of 2026-05-20, 2026-06-10 and 2026-06-29 are allowed.
func TestDefaultMeasurementPolicyAcceptsSek8s130Captures(t *testing.T) {
	p := DefaultMeasurementPolicy()
	for _, tc := range []struct {
		name  string
		allow map[string]struct{}
		value string
	}{
		{"MRTD", p.MRTDAllow, "ddc6efcdd2309e10837f8a7f64b71272b7ef003b129460410fe715bdfffec38c7c0c1686dddb2a23d4fd623d145e8455"},
		{"RTMR0 8xh200", p.RTMRAllow[0], "2864b11878e8129095d62a5dd7c3e3aae178d3a077606a825617324768f189ad05aed08376947df92d6c75865d915cbf"},
		{"RTMR1", p.RTMRAllow[1], "f858ed2aecba4ecd29084352c6b5c6e403c0bec89b8c852f90fa5a8cee796ffa095518c5cd8b92c25c1856e932a95877"},
		{"RTMR2", p.RTMRAllow[2], "7719f4fde518994a5dd6767a8b8b87a38168cc0f3480e7498d4ace99e49319be6a7fed26c21ad43310d2d488fc68ab1c"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := tc.allow[tc.value]; !ok {
				t.Errorf("%s... is not allowed", tc.value[:16])
			}
		})
	}
}

// Every RTMR0 hardware row of sek8s 1.4.0 and 1.4.1 in the NEAR mirror is
// allowed.
func TestDefaultMeasurementPolicyRTMR0Rows14(t *testing.T) {
	p := DefaultMeasurementPolicy()
	for _, tc := range []struct{ name, value string }{
		{"1.4.0 8xh200 [10.2.1, flat-188c-1128g-nvsw4]", "b72208e4b39593a82bbdbc394569bd6f8395f76bdcff5bce2bc72f4e2ca0b3202238d3b78952b497d725e04999e45435"},
		{"1.4.0 8xh200 [10.2.1, numa-124c-1128g-nvsw-node1]", "5b509103a3bf3c10dbf27a7da030a3d7ba93a81c0c8844de20e5dfee77611644a39cc7236313e9d0a99a8a8a703bbfc9"},
		{"1.4.1 8xb200 [10.2.1, flat-272c-1536g]", "44efeea3a647090c2969cca7f29963dde696d99542c28536a20ad3586a639ef7e230d8d4e325c55f3597dc7b58b30903"},
		{"1.4.1 8xb300 [10.2.1, flat-252c-1944g]", "fc71a5a8edcb1f6d307d59e62ce257365df0f233ae2334691f99d2136832d911f8be975b92f88036db8a4906574519c4"},
		{"1.4.1 8xb300 [10.2.1, numa-flatpci-252c-2304g]", "e861504d4a05ba1e949618ef759d6fbf0c69e4774b667e9fb876b664cb1bb70e3094d2cddc9ac6c52d4b5d352ba2e1d3"},
		{"1.4.1 8xh200 [10.2.1, numa-188c-1128g-nvsw-node0]", "052183ad6cca5ad4aef7e31dc3f6c47be2ba90c288a55420bf432301374f1bd9932ea7d6b5da999c4fecf578c4b0a21a"},
		{"1.4.1 8xh200 [10.2.1, numa-188c-1128g-nvsw-node1]", "ba81dbf034d968fd4be0975c031cbe6451295d63cb509cd857372fc915dada1b24fc4e1b0486db4a276a9efb49d415e6"},
		{"1.4.1 8xh200 [10.2.1, numa-236c-1128g-nvsw-node1]", "a9cac743d296a96c7a0d6348f03be1e1a407f18ec215f0039e3dc1ea4c132eb1e4a5fe3783022ff3d252d4b30f1dbf9f"},
		{"1.4.1 8xpro_6000 [10.2.1, numa-124c-768g] (58443435b208)", "bacb4abf7b19aba4a8307ebc7244706745de4fa627e669e7f06fd35c3303eea1903f58dc143d27b557da1a986e0e95f6"},
		{"1.4.1 8xpro_6000 [10.2.1, numa-124c-768g] (f2ab1d61fa64)", "5e939a6213a6751f162617c6e9a50461786b3f9a6a679ebf7706fa705e7934180825b2fae43a60877ea9117a1e4d4f60"},
		{"1.4.1 8xpro_6000 [10.2.1, numa-204c-768g]", "a5488b5f4cf1484da23001e013a5ad3ff177836bf2cfdbde55dacded21b3eece5de43d4c4a2d5279f8ed8d24b9e072d6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := p.RTMRAllow[0][tc.value]; !ok {
				t.Errorf("RTMR0 %s... is not allowed", tc.value[:16])
			}
		})
	}
}

// Every register value of the Chutes policy is a SHA-384 value: 96
// lowercase hex characters.
func TestDefaultMeasurementPolicyValuesAreSHA384(t *testing.T) {
	p := DefaultMeasurementPolicy()
	registers := map[string]map[string]struct{}{
		"MRSEAM": p.MRSeamAllow,
		"MRTD":   p.MRTDAllow,
		"RTMR0":  p.RTMRAllow[0],
		"RTMR1":  p.RTMRAllow[1],
		"RTMR2":  p.RTMRAllow[2],
	}
	for name, allow := range registers {
		t.Run(name, func(t *testing.T) {
			for v := range allow {
				if len(v) != 96 || strings.Trim(v, "0123456789abcdef") != "" {
					t.Errorf("value %q is not 96 lowercase hex characters", v)
				}
			}
		})
	}
}

// TDX modules 1.5.28 and 1.5.34 are allowed for Chutes only.
func TestChutesOnlyTDXModules(t *testing.T) {
	shared := attestation.DstackBaseMeasurementPolicy().MRSeamAllow
	for _, tc := range []struct{ name, value string }{
		{"1.5.06", "5b38e33a6487958b72c3c12a938eaa5e3fd4510c51aeeab58c7d5ecee41d7c436489d6c8e4f92f160b7cad34207b00c1"},
		{"1.5.28", "346bc77a1846cac214dd2e8edeb9ee4349449d6c3f9ff2c52149a634c27b7fd1bd314c2ef6b973eeebd55742952531a1"},
		{"1.5.34", "ab62561a173acbd18ee50ff37750db44184c6cf5e886df74247cc575e163b04c34b9e18374757c235affa614d4127f6b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := Sek8sMRSEAMAllow[tc.value]; !ok {
				t.Error("not allowed for Chutes")
			}
			if _, ok := shared[tc.value]; ok {
				t.Error("in the shared dstack list")
			}
		})
	}
}

func TestDefaultMeasurementPolicyCopies(t *testing.T) {
	p1 := DefaultMeasurementPolicy()
	p2 := DefaultMeasurementPolicy()
	// Mutating one copy must not affect the other.
	p1.MRSeamAllow["deadbeef"] = struct{}{}
	if _, ok := p2.MRSeamAllow["deadbeef"]; ok {
		t.Error("DefaultMeasurementPolicy returns shared MRSeamAllow maps instead of copies")
	}
	p1.MRTDAllow["deadbeef"] = struct{}{}
	if _, ok := p2.MRTDAllow["deadbeef"]; ok {
		t.Error("DefaultMeasurementPolicy returns shared MRTDAllow maps instead of copies")
	}
}

func TestSek8sMRTDAllow(t *testing.T) {
	if len(Sek8sMRTDAllow) < 1 {
		t.Error("Sek8sMRTDAllow is empty")
	}
	for h := range Sek8sMRTDAllow {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Errorf("invalid hex in Sek8sMRTDAllow: %s", h)
		}
		if len(b) != 48 {
			t.Errorf("Sek8sMRTDAllow entry %q decodes to %d bytes, want 48", h[:16], len(b))
		}
	}
}

func TestDefaultMeasurementPolicyRTMRValues(t *testing.T) {
	p := DefaultMeasurementPolicy()
	for i := range 3 {
		for h := range p.RTMRAllow[i] {
			b, err := hex.DecodeString(h)
			if err != nil {
				t.Errorf("invalid hex in RTMR%d allowlist: %s", i, h)
			}
			if len(b) != 48 {
				t.Errorf("RTMR%d entry %q decodes to %d bytes, want 48", i, h[:16], len(b))
			}
		}
	}
}

func TestDefaultMeasurementPolicyMRTDNotDstack(t *testing.T) {
	p := DefaultMeasurementPolicy()
	dstackBase := attestation.DstackBaseMeasurementPolicy()
	// sek8s MRTD must NOT overlap with dstack MRTD.
	for h := range dstackBase.MRTDAllow {
		if _, ok := p.MRTDAllow[h]; ok {
			t.Errorf("sek8s MRTDAllow unexpectedly contains dstack value %s...", h[:16])
		}
	}
}

func TestSek8sMRSEAMAllow(t *testing.T) {
	dstackBase := attestation.DstackBaseMeasurementPolicy()
	// Must be a strict superset of dstack MRSEAM.
	if len(Sek8sMRSEAMAllow) <= len(dstackBase.MRSeamAllow) {
		t.Errorf("Sek8sMRSEAMAllow (%d) should have more entries than dstack MRSEAM (%d)",
			len(Sek8sMRSEAMAllow), len(dstackBase.MRSeamAllow))
	}
	for h := range dstackBase.MRSeamAllow {
		if _, ok := Sek8sMRSEAMAllow[h]; !ok {
			t.Errorf("Sek8sMRSEAMAllow missing dstack entry %s...", h[:16])
		}
	}
	// Chutes-specific entries must NOT be in the dstack list.
	extra := 0
	for h := range Sek8sMRSEAMAllow {
		if _, ok := dstackBase.MRSeamAllow[h]; !ok {
			extra++
		}
	}
	// 1.5.06, 1.5.28 and 1.5.34.
	if extra != 3 {
		t.Errorf("expected 3 chutes-specific MRSEAM entries, got %d", extra)
	}
}

func TestInapplicableFactors(t *testing.T) {
	factors := InapplicableFactors()
	if factors == nil {
		t.Fatal("expected non-nil factors")
	}
	expected := []string{
		"compose_binding",
		"build_transparency_log",
		"sigstore_verification",
		"event_log_integrity",
		"sigstore_code_verified",
		"nvswitch_binding",
	}
	for _, key := range expected {
		if _, ok := factors[key]; !ok {
			t.Errorf("missing factor %q", key)
		}
	}
}
