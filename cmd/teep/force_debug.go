//go:build debug

package main

import "github.com/peterbourgon/ff/v4"

// registerForceFlag registers the --force flag, available only in debug builds.
func registerForceFlag(fs *ff.FlagSet) *bool {
	return fs.BoolLong("force", "forward requests even when enforced attestation factors fail (WARNING: reduces security)")
}

func forceValue(p *bool) bool { return p != nil && *p }
