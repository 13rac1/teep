//go:build !debug

package main

import "github.com/peterbourgon/ff/v4"

// registerForceFlag is a no-op in release builds. The --force flag is only
// available when built with -tags debug.
func registerForceFlag(_ *ff.FlagSet) *bool {
	return nil
}

func forceValue(_ *bool) bool { return false }
