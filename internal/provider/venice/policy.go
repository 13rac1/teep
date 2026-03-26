package venice

import (
	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/neardirect"
)

// SupplyChainPolicy returns the supply chain policy for Venice.
// Venice uses the same container images as neardirect.
func SupplyChainPolicy() *attestation.SupplyChainPolicy {
	return neardirect.SupplyChainPolicy()
}
