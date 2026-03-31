//go:build !debug

package main

import "flag"

// registerForceFlag is a no-op in release builds. The --force flag is only
// available when built with -tags debug.
func registerForceFlag(_ *flag.FlagSet) *bool {
	return nil
}
