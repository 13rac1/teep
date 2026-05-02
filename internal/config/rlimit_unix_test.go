//go:build unix

package config

import (
	"math"
	"syscall"
	"testing"
)

func TestRlimitCurToSoft_Infinity(t *testing.T) {
	soft, unlimited := rlimitCurToSoft(syscall.RLIM_INFINITY)
	if !unlimited {
		t.Fatal("unlimited = false, want true")
	}
	if soft != 0 {
		t.Fatalf("soft = %d, want 0", soft)
	}
}

func TestRlimitCurToSoft_LargeFinite(t *testing.T) {
	soft, unlimited := rlimitCurToSoft(2_000_000)
	if unlimited {
		t.Fatal("unlimited = true, want false")
	}
	if soft != 2_000_000 {
		t.Fatalf("soft = %d, want 2000000", soft)
	}
}

func TestRlimitCurToSoft_ClampToIntMax(t *testing.T) {
	soft, unlimited := rlimitCurToSoft(uint64(math.MaxInt) + 1)
	if unlimited {
		t.Fatal("unlimited = true, want false")
	}
	if soft != math.MaxInt {
		t.Fatalf("soft = %d, want %d", soft, math.MaxInt)
	}
}
