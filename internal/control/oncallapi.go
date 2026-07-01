// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"fmt"
	"net/http"
	"sort"

	"github.com/imfeelingtheagi/probectl/internal/config"
)

var oncallSupportedProviders = []string{"pagerduty", "opsgenie", "slack", "teams", "servicenow", "jira"}

type oncallStatus struct {
	ID                     string                 `json:"id"`
	Name                   string                 `json:"name"`
	Summary                string                 `json:"summary"`
	Configured             bool                   `json:"configured"`
	DispatcherRunning      bool                   `json:"dispatcher_running"`
	OutboundConfigured     bool                   `json:"outbound_configured"`
	InboundConfigured      bool                   `json:"inbound_configured"`
	OutboundConnectorCount int                    `json:"outbound_connector_count"`
	InboundWebhookCount    int                    `json:"inbound_webhook_count"`
	TLSRequired            bool                   `json:"tls_required"`
	SecretsRedacted        bool                   `json:"secrets_redacted"`
	Providers              []oncallProviderStatus `json:"providers"`
	Outbound               []oncallOutboundStatus `json:"outbound"`
	Inbound                []oncallInboundStatus  `json:"inbound"`
	SupportedProviders     []string               `json:"supported_providers"`
}

type oncallProviderStatus struct {
	Provider               string `json:"provider"`
	OutboundConnectorCount int    `json:"outbound_connector_count"`
	InboundWebhookCount    int    `json:"inbound_webhook_count"`
}

type oncallOutboundStatus struct {
	Provider                string `json:"provider"`
	EndpointConfigured      bool   `json:"endpoint_configured"`
	EndpointTLSConfigured   bool   `json:"endpoint_tls_configured"`
	EndpointHost            string `json:"endpoint_host,omitempty"`
	CredentialConfigured    bool   `json:"credential_configured"`
	EndpointSecretsRedacted bool   `json:"endpoint_secrets_redacted"`
}

type oncallInboundStatus struct {
	ID                   string `json:"id"`
	Provider             string `json:"provider"`
	Path                 string `json:"path"`
	CredentialConfigured bool   `json:"credential_configured"`
}

// handleOncallStatus exposes a tenant-scoped, read-only posture view for
// on-call/ITSM integrations. It is intentionally a redacted status surface, not
// a config dump: connector credentials and URL path/query values can contain
// bearer material (Slack/Teams webhook paths, Jira tokens in query strings).
func (s *Server) handleOncallStatus(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, oncallStatusFromConfig(s.cfg, tid, s.dispatcher != nil))
	return nil
}

func oncallStatusFromConfig(cfg *config.Config, tenantID string, dispatcherRunning bool) oncallStatus {
	status := oncallStatus{
		ID:                 "oncall",
		Name:               "On-call + ITSM",
		Summary:            "On-call and ITSM integration is disabled",
		TLSRequired:        true,
		SecretsRedacted:    true,
		Providers:          []oncallProviderStatus{},
		Outbound:           []oncallOutboundStatus{},
		Inbound:            []oncallInboundStatus{},
		SupportedProviders: append([]string(nil), oncallSupportedProviders...),
	}
	if cfg == nil {
		return status
	}

	providers := map[string]*oncallProviderStatus{}
	for _, nc := range cfg.NotifyConnectors {
		if nc.TenantID != tenantID {
			continue
		}
		configured, tlsConfigured, host := siemEndpointPosture(nc.Endpoint)
		status.Outbound = append(status.Outbound, oncallOutboundStatus{
			Provider:                nc.Provider,
			EndpointConfigured:      configured,
			EndpointTLSConfigured:   tlsConfigured,
			EndpointHost:            host,
			CredentialConfigured:    nc.Secret != "",
			EndpointSecretsRedacted: true,
		})
		p := oncallProviderBucket(providers, nc.Provider)
		p.OutboundConnectorCount++
	}
	for id, inbound := range cfg.NotifyInbound {
		if inbound.TenantID != tenantID {
			continue
		}
		status.Inbound = append(status.Inbound, oncallInboundStatus{
			ID:                   id,
			Provider:             inbound.Provider,
			Path:                 fmt.Sprintf("/ingest/itsm/%s/%s", inbound.Provider, id),
			CredentialConfigured: inbound.Secret != "",
		})
		p := oncallProviderBucket(providers, inbound.Provider)
		p.InboundWebhookCount++
	}

	sort.Slice(status.Outbound, func(i, j int) bool {
		if status.Outbound[i].Provider == status.Outbound[j].Provider {
			return status.Outbound[i].EndpointHost < status.Outbound[j].EndpointHost
		}
		return status.Outbound[i].Provider < status.Outbound[j].Provider
	})
	sort.Slice(status.Inbound, func(i, j int) bool { return status.Inbound[i].ID < status.Inbound[j].ID })

	keys := make([]string, 0, len(providers))
	for provider := range providers {
		keys = append(keys, provider)
	}
	sort.Strings(keys)
	for _, provider := range keys {
		status.Providers = append(status.Providers, *providers[provider])
	}

	status.OutboundConnectorCount = len(status.Outbound)
	status.InboundWebhookCount = len(status.Inbound)
	status.OutboundConfigured = status.OutboundConnectorCount > 0
	status.InboundConfigured = status.InboundWebhookCount > 0
	status.DispatcherRunning = dispatcherRunning && status.OutboundConfigured
	status.Configured = status.OutboundConfigured || status.InboundConfigured
	if status.Configured {
		status.Summary = fmt.Sprintf("On-call and ITSM integration is configured with %d outbound connector(s) and %d inbound webhook(s)", status.OutboundConnectorCount, status.InboundWebhookCount)
	}
	return status
}

func oncallProviderBucket(providers map[string]*oncallProviderStatus, provider string) *oncallProviderStatus {
	p, ok := providers[provider]
	if !ok {
		p = &oncallProviderStatus{Provider: provider}
		providers[provider] = p
	}
	return p
}
