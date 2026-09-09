package nearcloud

import (
	"errors"
	"net/http"

	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/neardirect"
)

// Preparer sends the acquired model key as a gateway routing hint.
// The gateway can ignore the hint; E2EE response authentication remains required.
type Preparer struct{ near *neardirect.Preparer }

// NewPreparer creates a stateless NearCloud request preparer.
func NewPreparer(apiKey string) *Preparer { return &Preparer{near: neardirect.NewPreparer(apiKey)} }

// PrepareRequest canonicalizes the authenticated Ed25519 key and replaces any inbound hint.
func (p *Preparer) PrepareRequest(req *http.Request, headers http.Header, meta *e2ee.ChutesE2EE, stream bool, path string, authenticated provider.PreparationData) error {
	key := authenticated.ModelKey.Hex()
	if key == "" {
		return errors.New("NearCloud requires a validated model routing key")
	}
	if err := p.near.PrepareRequest(req, headers, meta, stream, path, authenticated); err != nil {
		return err
	}
	for name := range req.Header {
		if http.CanonicalHeaderKey(name) == "X-Model-Pub-Key" {
			delete(req.Header, name)
		}
	}
	req.Header.Set("X-Model-Pub-Key", key)
	return nil
}
