package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/nearcloud"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/provider/tinfoil"
	"github.com/13rac1/teep/internal/tlsct"
)

func standaloneAttesterForRoute(ctx context.Context, opts *Options, attester provider.Attester, route *provider.ResolvedRoute) (provider.Attester, error) {
	if route.Authority() == "" {
		var err error
		if resolver, ok := attester.(interface {
			ResolveRoute(context.Context, string) (provider.ResolvedRoute, error)
		}); ok {
			*route, err = resolver.ResolveRoute(ctx, opts.ModelName)
		} else {
			origin, repo := opts.Provider.BaseURL, tinfoil.RouterRepo
			if opts.ProviderName == "nearcloud" {
				origin, repo = "https://"+nearcloud.GatewayHost(), ""
			}
			*route, err = provider.NewResolvedRoute(origin, repo)
		}
		if err != nil {
			return nil, err
		}
	}
	if scoped, ok := attester.(provider.RouteAttester); ok {
		return provider.AttesterForRoute(scoped, *route)
	}
	if opts.ProviderName != "tinfoil_v3_cloud" && opts.ProviderName != "nearcloud" {
		return nil, errors.New("dynamic provider has no route attester")
	}
	return attester, nil
}

func runTLSVerification(ctx context.Context, opts *Options, route *provider.ResolvedRoute) (verificationOutcome, error) {
	logical, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	current, err := runEvidence(logical, opts, route)
	if err != nil || opts.Offline || opts.CapturedE2EE != nil || opts.Provider.APIKey == "" || current.report.Blocked() {
		return current, err
	}
	var client *http.Client
	var identity tlsct.TransportIdentity
	defer func() {
		if client != nil {
			client.CloseIdleConnections()
		}
	}()
	refresh := false
	result, err := tlsct.RunInferenceAttempts(logical, func(attemptCtx context.Context) (verificationOutcome, bool, error) {
		if refresh {
			opts.Nonce = attestation.NewNonce()
			current, err = runEvidence(attemptCtx, opts, route)
			if err != nil {
				return current, false, err
			}
		}
		report := current.report
		if report.Blocked() || !report.ReportDataBindingPassed() {
			return current, false, errors.New("attestation does not authorize E2EE")
		}
		selected, identityErr := tlsct.NewTransportIdentity(report.TLSAuthority, report.TLSKeyFP)
		if identityErr != nil || selected.Authority() != route.Authority() {
			return current, false, errors.New("attested identity does not match resolved route")
		}
		if client == nil || !identity.Equal(selected) {
			if client != nil {
				client.CloseIdleConnections()
			}
			client, err = tlsct.NewSPKIPinnedHTTPClientWithTransport(0, tlsct.NewPooledTransport(), selected, !opts.Offline)
			if err != nil {
				return current, false, err
			}
			identity = selected
		}
		expires, present := report.Validity.Expiry()
		bounded, boundCancel := tlsct.InferenceContext(attemptCtx, expires, present)
		defer boundCancel()
		var retry bool
		current.e2ee, retry, err = testStandaloneInference(bounded, opts, *route, current.raw, client)
		if contextErr := bounded.Err(); contextErr != nil {
			err = contextErr
			if current.e2ee != nil {
				current.e2ee.Err = contextErr
			}
		}
		_, refresh = errors.AsType[*standaloneKeyRejectionError](err)
		if current.e2ee != nil {
			current.e2ee.KeyType = current.raw.E2EEKeyType()
		}
		if current.e2ee != nil && current.e2ee.Err != nil {
			err = current.e2ee.Err
		}
		return current, retry, err
	})
	completeTLSInference(&result, err)
	// A failed inference test is represented by the factor report, as in the
	// other standalone verification paths.
	if result.report != nil {
		return result, nil
	}
	return result, err
}

// completeTLSInference stores the same final outcome in the report and capture,
// including failures before an encrypted response is available.
func completeTLSInference(result *verificationOutcome, err error) {
	if result.report == nil {
		return
	}
	if err != nil {
		if result.e2ee == nil {
			result.e2ee = &attestation.E2EETestResult{}
		}
		result.e2ee.Err = fmt.Errorf("E2EE test failed: %w", err)
		if result.raw != nil {
			result.e2ee.KeyType = result.raw.E2EEKeyType()
		}
		result.report.MarkE2EEFailed(result.e2ee.Err.Error())
	} else if result.e2ee != nil && result.e2ee.Attempted {
		result.report.MarkE2EEUsable(result.e2ee.Detail)
	}
}

// testStandaloneInference uses the same encryption, headers, framing, and
// rejection recognition as the proxy, while retaining standalone report output.
func testStandaloneInference(ctx context.Context, opts *Options, route provider.ResolvedRoute, raw *attestation.RawAttestation, client *http.Client) (*attestation.E2EETestResult, bool, error) {
	prov := &provider.Provider{Name: opts.ProviderName, E2EE: true}
	switch opts.ProviderName {
	case "nearcloud", "neardirect":
		prov.Encryptor, prov.Preparer = neardirect.NewE2EE(), neardirect.NewPreparer(opts.Provider.APIKey)
	case "tinfoil_v3_cloud", "tinfoil_v3_direct":
		prov.Encryptor, prov.Preparer = tinfoil.NewE2EE(), tinfoil.NewPreparer(opts.Provider.APIKey)
	default:
		return nil, false, errors.New("unsupported TLS-binding inference provider")
	}
	body, err := json.Marshal(map[string]any{"model": opts.ModelName, "messages": []map[string]string{{"role": "user", "content": "Say hello"}}, "stream": true})
	if err != nil {
		return nil, false, err
	}
	phase := &tlsct.InferenceAttempt{}
	req, encrypted, err := provider.PrepareInference(phase.Context(ctx), prov, route, &provider.InferenceInput{Body: body, SigningKey: raw.SigningKey, Path: "/v1/chat/completions", ContentType: "application/json", Stream: true, Endpoint: e2ee.EndpointChat})
	if err != nil {
		return nil, false, err
	}
	defer e2ee.ZeroSessions(encrypted.Session, encrypted.Chutes, encrypted.EHBP)
	resp, err := client.Do(req)
	if err != nil {
		return nil, phase.RetryConnectionFailure(ctx, err), err
	}
	defer func() { resp.Body.Close() }()
	rejected, err := provider.KeyRejection(resp, opts.ProviderName, "/v1/chat/completions")
	if err != nil {
		return nil, false, err
	}
	if rejected {
		return nil, true, &standaloneKeyRejectionError{}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, standaloneInferenceError(resp, encrypted.EHBP)
	}
	if encrypted.EHBP != nil {
		return verifyEHBPStreamResponse(resp, encrypted.EHBP), false, nil
	}
	return verifyE2EEStreamResponse(resp, encrypted.Session, opts.ProviderName), false, nil
}

func standaloneInferenceError(resp *http.Response, session *e2ee.EHBPSession) error {
	var body io.Reader = resp.Body
	if nonce := resp.Header.Get("Ehbp-Response-Nonce"); session != nil && len(resp.Header.Values("Ehbp-Response-Nonce")) != 0 {
		plain, err := session.DecryptResponse(body, nonce)
		if err != nil {
			return err
		}
		defer plain.Close()
		body = plain
	}
	if _, err := io.Copy(io.Discard, io.LimitReader(body, 64<<10)); err != nil {
		return err
	}
	return fmt.Errorf("upstream returned HTTP %d", resp.StatusCode)
}

type standaloneKeyRejectionError struct{}

func (*standaloneKeyRejectionError) Error() string {
	return "upstream rejected attested encryption key"
}
