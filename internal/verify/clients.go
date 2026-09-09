package verify

import (
	"net/http"

	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/tlsct"
)

// initializeClients runs once on Run's private options before evidence or capture.
// Only locally created clients are closed; injected clients remain caller-owned.
func (o *Options) initializeClients() func() {
	var owned []*http.Client
	if o.Client == nil {
		factory := config.NewAttestationClientFactory(o.Offline, tlsct.NewAttestationSocketBudget(tlsct.MaxConnectionsPerHost), nil)
		o.Client = factory.NewClient()
		owned = append(owned, o.Client)
		if o.ProviderName == "neardirect" && o.AttestationClientFactory == nil {
			o.AttestationClientFactory = factory.NewFreshClient
		}
	}
	if o.ProviderName == "neardirect" && o.MetadataClient == nil {
		o.MetadataClient = config.NewAttestationClient(o.Offline)
		owned = append(owned, o.MetadataClient)
	}
	return func() {
		for _, client := range owned {
			client.CloseIdleConnections()
		}
	}
}
