package verify

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/nearcloud"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/tlsct"
)

func nearCaptureConfig(name string, cp *config.Provider) (*capture.NearConfig, error) {
	origin := cp.BaseURL
	if name == "nearcloud" {
		origin = "https://" + nearcloud.GatewayHost()
	}
	authority, err := tlsct.HTTPSOriginAuthority(origin)
	if err != nil {
		return nil, err
	}
	return &capture.NearConfig{Origin: "https://" + authority, E2EE: cp.E2EE}, nil
}

func recordNearSelection(opts *Options, attester provider.Attester) error {
	if opts.ProviderName != "neardirect" {
		return nil
	}
	selected, ok := attester.(interface {
		LookupSelection(string) (neardirect.Selection, bool)
	})
	if !ok {
		return errors.New("NearDirect attester does not expose completed selection")
	}
	value, ok := selected.LookupSelection(opts.ModelName)
	if !ok {
		return errors.New("NearDirect route selection was not completed")
	}
	record := &capture.NearRoute{Canonical: value.Canonical, Authority: value.Authority, Mode: value.Mode}
	if value.Mode != "static" {
		record.Index = &value.Index
	}
	opts.nearRoute = record
	return nil
}

func validateNearReplay(manifest *capture.Manifest, cp *config.Provider, entries []capture.RecordedEntry) (provider.ResolvedRoute, error) {
	if manifest.Provider != "neardirect" && manifest.Provider != "nearcloud" {
		return provider.ResolvedRoute{}, nil
	}
	expected, err := nearCaptureConfig(manifest.Provider, cp)
	if err != nil {
		return provider.ResolvedRoute{}, err
	}
	if manifest.NearConfig == nil || *manifest.NearConfig != *expected {
		return provider.ResolvedRoute{}, errors.New("NEAR capture configuration mismatch: effective origin and E2EE mode must match")
	}
	if (cp.E2EE && manifest.TLSInference != nil) || (!cp.E2EE && manifest.E2EE != nil) {
		return provider.ResolvedRoute{}, errors.New("NEAR capture probe outcome contradicts configured inference mode")
	}

	if manifest.Provider != "neardirect" {
		if manifest.NearRoute != nil {
			return provider.ResolvedRoute{}, errors.New("NearCloud capture contains a direct route")
		}
		return provider.ResolvedRoute{}, nil
	}
	recorded := manifest.NearRoute
	if recorded == nil {
		return provider.ResolvedRoute{}, errors.New("NEAR capture has no recorded direct route")
	}
	selection := neardirect.Selection{Canonical: recorded.Canonical, Authority: recorded.Authority, Mode: recorded.Mode}
	if recorded.Mode == "static" {
		if recorded.Index != nil {
			return provider.ResolvedRoute{}, errors.New("static capture route contains an index")
		}
	} else {
		if recorded.Index == nil {
			return provider.ResolvedRoute{}, errors.New("indexed capture route has no index")
		}
		selection.Index = *recorded.Index
	}
	endpoints, count, err := recordedNearMetadata(entries, selection)
	if err != nil {
		return provider.ResolvedRoute{}, err
	}
	route, err := neardirect.ValidateRecordedSelection(manifest.Model, expected.Origin, selection, endpoints, count)
	if err != nil {
		return provider.ResolvedRoute{}, fmt.Errorf("invalid captured NEAR selection: %w", err)
	}
	if err := validateNearEvidenceRoute(entries, route); err != nil {
		return provider.ResolvedRoute{}, err
	}
	return route, nil
}

func recordedNearMetadata(entries []capture.RecordedEntry, selection neardirect.Selection) (endpoints, count []byte, err error) {
	for i := range entries {
		entry := &entries[i]
		parsed, parseErr := url.Parse(entry.URL)
		if parseErr != nil {
			return nil, nil, parseErr
		}
		if parsed.Host != "completions.near.ai" || parsed.Scheme != "https" {
			continue
		}
		switch parsed.Path {
		case "/endpoints":
			if endpoints != nil || entry.Method != http.MethodGet || entry.Status != http.StatusOK || parsed.RawQuery != "" {
				return nil, nil, errors.New("invalid or repeated captured endpoint metadata")
			}
			endpoints = entry.Body
		case "/backends/count":
			if count != nil || entry.Method != http.MethodGet || entry.Status != http.StatusOK || parsed.Query().Get("domain") != selection.Canonical || len(parsed.Query()) != 1 || len(parsed.Query()["domain"]) != 1 {
				return nil, nil, errors.New("invalid or repeated captured count metadata")
			}
			count = entry.Body
		}
	}
	if selection.Mode == "static" && (endpoints != nil || count != nil) {
		return nil, nil, errors.New("static captured route contains discovery metadata")
	}
	if selection.Mode == "explicit" && count != nil {
		return nil, nil, errors.New("explicit indexed capture contains count metadata")
	}
	return endpoints, count, nil
}

func validateNearEvidenceRoute(entries []capture.RecordedEntry, route provider.ResolvedRoute) error {
	found := false
	for i := range entries {
		entry := &entries[i]
		parsed, err := url.Parse(entry.URL)
		if err != nil {
			return err
		}
		if parsed.Path != "/v1/attestation/report" {
			continue
		}
		if found || parsed.Scheme != "https" || parsed.Host != route.Authority() || entry.Method != http.MethodGet || entry.Status != http.StatusOK || entry.TLSVersion != "TLS 1.3" || len(entry.PeerSPKIDER) == 0 {
			return errors.New("captured NEAR attestation URL or peer does not match selected route")
		}
		found = true
	}
	if !found {
		return errors.New("capture has no attestation for selected NEAR route")
	}
	return nil
}
