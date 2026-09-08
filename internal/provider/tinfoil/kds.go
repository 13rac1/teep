package tinfoil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/verify/trust"
)

const kdsProxyHost = "kds-proxy.tinfoil.sh"

type sevCertGetter struct{ remote trust.HTTPSGetter }

// NewSEVCertGetter uses embedded AMD signing chains and Tinfoil's VCEK proxy.
// The shared attestation client requires TLS 1.3, WebPKI and CT, negotiates
// HTTP/2, and owns retries. Retrieval never switches to AMD after a failure.
// AMD chain and report signature verification remain the verifier's job.
func NewSEVCertGetter(client *http.Client) trust.HTTPSGetter {
	return &sevCertGetter{remote: attestation.NewSEVCertGetter(client)}
}

func (g *sevCertGetter) Get(target string) ([]byte, error) {
	return g.GetContext(context.Background(), target)
}

func (g *sevCertGetter) GetContext(ctx context.Context, target string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || u.Host != attestation.AMDKDSHost || u.User != nil || u.Fragment != "" || u.RawPath != "" {
		return nil, errors.New("unexpected Tinfoil KDS certificate URL")
	}
	if strings.HasSuffix(u.Path, "/cert_chain") {
		if u.RawQuery != "" {
			return nil, errors.New("unexpected Tinfoil KDS chain query")
		}
		switch u.Path {
		case "/vcek/v1/Milan/cert_chain":
			return bytes.Clone(trust.AskArkMilanVcekBytes), nil
		case "/vcek/v1/Genoa/cert_chain":
			return bytes.Clone(trust.AskArkGenoaVcekBytes), nil
		case "/vcek/v1/Turin/cert_chain":
			return bytes.Clone(trust.AskArkTurinVcekBytes), nil
		default:
			return nil, fmt.Errorf("unsupported Tinfoil KDS signing chain %q", u.Path)
		}
	}
	if _, err := kds.ParseVCEKCertURL(target); err != nil {
		return nil, err
	}
	u.Host = kdsProxyHost
	return trust.GetWith(ctx, g.remote, u.String())
}
