package attestation

import (
	"encoding/hex"
	"testing"
)

func TestDstackMRSEAMAllow(t *testing.T) {
	if len(dstackMRSEAMAllow) != 4 {
		t.Errorf("dstackMRSEAMAllow has %d entries, want 4", len(dstackMRSEAMAllow))
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
	if len(dstackMRTDAllow) != 2 {
		t.Errorf("dstackMRTDAllow has %d entries, want 2", len(dstackMRTDAllow))
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
