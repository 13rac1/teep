//go:build unix

package config

import "syscall"

// nofileRlimit returns the process's soft RLIMIT_NOFILE (open-file limit).
// Returns unlimited=true when the limit is effectively unbounded.
func nofileRlimit() (soft int, unlimited bool, err error) {
	var rlim syscall.Rlimit
	if err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err != nil {
		return
	}
	// RLIM_INFINITY is MaxUint64 on Linux and MaxInt64 on macOS — both exceed
	// 1_000_000. Guard first so the int() conversion is always safe.
	const maxReasonable = 1_000_000
	if rlim.Cur > maxReasonable {
		return 0, true, nil
	}
	return int(rlim.Cur), false, nil
}
