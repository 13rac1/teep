//go:build unix

package config

import (
	"math"
	"syscall"
	"testing"
)

func testRlimitInfinityValueFromSyscall() uint64 {
	v := any(syscall.RLIM_INFINITY)
	switch n := v.(type) {
	case uint64:
		return n
	case int64:
		return uint64(n)
	case int:
		return uint64(n)
	case uintptr:
		return uint64(n)
	default:
		return ^uint64(0)
	}
}

func TestRlimitInfinityValueMatchesSyscall(t *testing.T) {
	got := rlimitInfinityValue()
	want := testRlimitInfinityValueFromSyscall()
	if got != want {
		t.Fatalf("rlimitInfinityValue() = %d, want %d", got, want)
	}
}

func TestRlimitCurToSoft_Infinity(t *testing.T) {
	soft, unlimited := rlimitCurToSoft(rlimitInfinityValue())
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
