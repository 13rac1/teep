//go:build debug

package main

import "flag"

// registerForceFlag registers the --force flag, available only in debug builds.
func registerForceFlag(fs *flag.FlagSet) *bool {
	return fs.Bool("force", false, "forward requests even when enforced attestation factors fail (WARNING: reduces security)")
}
