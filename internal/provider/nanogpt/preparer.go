package nanogpt

import (
	"maps"
	"net/http"

	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
)

// Preparer injects the NanoGPT Authorization header and the E2EE v2 headers
// into outgoing requests.
type Preparer struct {
	apiKey string
}

// NewPreparer returns a NanoGPT Preparer configured with the given API key.
func NewPreparer(apiKey string) *Preparer {
	return &Preparer{apiKey: apiKey}
}

// PrepareRequest injects the Authorization header and the E2EE v2 headers
// into req. NanoGPT must forward the E2EE v2 headers and the encrypted fields
// to the gateway unchanged; otherwise the response fails decryption.
func (p *Preparer) PrepareRequest(req *http.Request, e2eeHeaders http.Header, _ *e2ee.ChutesE2EE, _ bool, _ string, _ provider.PreparationData) error {
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	maps.Copy(req.Header, e2eeHeaders)
	return nil
}
