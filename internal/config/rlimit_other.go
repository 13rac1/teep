//go:build !unix

package config

// nofileRlimit returns unlimited=true on non-Unix platforms.
func nofileRlimit() (int, bool, error) { return 0, true, nil }
