package nearai

import (
	"github.com/13rac1/teep/internal/tlsct"
)

// CTChecker is a compatibility alias to the shared repository-wide checker.
type CTChecker = tlsct.Checker

// NewCTChecker returns a shared CT checker implementation.
func NewCTChecker() *CTChecker { return tlsct.NewChecker() }
