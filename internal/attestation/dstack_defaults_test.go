package attestation

import (
	"encoding/hex"
	"testing"
)

func TestDstackMRSEAMAllow(t *testing.T) {
	if len(dstackMRSEAMAllow) != 7 {
		t.Errorf("dstackMRSEAMAllow has %d entries, want 7", len(dstackMRSEAMAllow))
	}
	// TDX modules 1.5.24 and 2.0.18, from Intel's table of module hashes.
	for _, tc := range []struct{ name, value string }{
		{"1.5.24", "489e585f1c54bc5a02066c8c6ec21619ff0334ec6f21e07e2a35202c59183789c8057e7d97dd591bb08314b185819e72"},
		{"2.0.18", "2d2de102461684f14c8d0984a09d895e3e9e15944ce020a03b977e1f114d5e1ed32ef666a47fd19a5851b3800eda3afa"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := dstackMRSEAMAllow[tc.value]; !ok {
				t.Error("not in dstackMRSEAMAllow")
			}
		})
	}
	for h := range dstackMRSEAMAllow {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Errorf("invalid hex in dstackMRSEAMAllow: %s", h)
		}
		if len(b) != 48 {
			t.Errorf("dstackMRSEAMAllow entry %q decodes to %d bytes, want 48", h[:16], len(b))
		}
	}
}

func TestDstackMRTDAllow(t *testing.T) {
	if len(dstackMRTDAllow) != 3 {
		t.Errorf("dstackMRTDAllow has %d entries, want 3", len(dstackMRTDAllow))
	}
	for h := range dstackMRTDAllow {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Errorf("invalid hex in dstackMRTDAllow: %s", h)
		}
		if len(b) != 48 {
			t.Errorf("dstackMRTDAllow entry %q decodes to %d bytes, want 48", h[:16], len(b))
		}
	}
}

func TestDstackBaseMeasurementPolicy(t *testing.T) {
	p := DstackBaseMeasurementPolicy()
	if !p.HasMRSeamPolicy() {
		t.Error("DstackBaseMeasurementPolicy should have MRSeamAllow")
	}
	if !p.HasMRTDPolicy() {
		t.Error("DstackBaseMeasurementPolicy should have MRTDAllow")
	}
	for i := range p.RTMRAllow {
		if p.HasRTMRPolicy(i) {
			t.Errorf("DstackBaseMeasurementPolicy should not have RTMR%d policy", i)
		}
	}
}

func TestDstackBaseMeasurementPolicyCopies(t *testing.T) {
	p1 := DstackBaseMeasurementPolicy()
	p2 := DstackBaseMeasurementPolicy()
	// Mutating one copy must not affect the other.
	p1.MRSeamAllow["deadbeef"] = struct{}{}
	if _, ok := p2.MRSeamAllow["deadbeef"]; ok {
		t.Error("DstackBaseMeasurementPolicy returns shared maps instead of copies")
	}
}
