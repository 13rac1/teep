//go:build !unix

package config

import "errors"

// nofileRlimit reports unsupported on non-Unix platforms so callers do not
// misclassify this as an actual unlimited RLIMIT_NOFILE value.
func nofileRlimit() (int, bool, error) {
	return 0, false, errors.New("RLIMIT_NOFILE unsupported on non-Unix platform")
}
