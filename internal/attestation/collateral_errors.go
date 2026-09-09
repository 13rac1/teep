package attestation

import (
	"context"
	"errors"
	"sync"

	sevtrust "github.com/google/go-sev-guest/verify/trust"
	tdxtrust "github.com/google/go-tdx-guest/verify/trust"
)

// collateralFailure preserves fetch causes that certificate libraries convert
// to text. Each online verification owns its collector; providers never share it.
type collateralFailure struct {
	mu  sync.Mutex
	err error
}

func (f *collateralFailure) record(err error) {
	if err != nil {
		f.mu.Lock()
		f.err = errors.Join(f.err, err)
		f.mu.Unlock()
	}
}

func (f *collateralFailure) failure() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

type sevEvidenceGetter struct {
	base sevtrust.HTTPSGetter
	collateralFailure
}

func (g *sevEvidenceGetter) Get(url string) ([]byte, error) {
	return g.GetContext(context.Background(), url)
}

func (g *sevEvidenceGetter) GetContext(ctx context.Context, url string) ([]byte, error) {
	body, err := sevtrust.GetWith(ctx, g.base, url)
	g.record(err)
	return body, err
}

type tdxEvidenceGetter struct {
	base tdxtrust.HTTPSGetter
	collateralFailure
}

func (g *tdxEvidenceGetter) Get(url string) (headers map[string][]string, body []byte, err error) {
	return g.GetContext(context.Background(), url)
}

func (g *tdxEvidenceGetter) GetContext(ctx context.Context, url string) (headers map[string][]string, body []byte, err error) {
	headers, body, err = tdxtrust.GetWith(ctx, g.base, url)
	g.record(err)
	return headers, body, err
}
