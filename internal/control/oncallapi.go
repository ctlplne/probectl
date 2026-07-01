// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/notify"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
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
	ID                      string `json:"id"`
	Provider                string `json:"provider"`
	TenantRouted            bool   `json:"tenant_routed"`
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

type oncallTestRequest struct {
	ConnectorID string `json:"connector_id"`
}

type oncallTestResponse struct {
	Accepted    bool   `json:"accepted"`
	ConnectorID string `json:"connector_id"`
	Provider    string `json:"provider"`
	Status      string `json:"status,omitempty"`
	ExternalRef string `json:"external_ref,omitempty"`
}

type alertChannelTestRequest struct {
	RuleName string            `json:"rule_name"`
	Metric   string            `json:"metric"`
	Channel  alert.ChannelSpec `json:"channel"`
}

type alertChannelTestResponse struct {
	Accepted bool   `json:"accepted"`
	Type     string `json:"type"`
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

func (s *Server) handleOncallTest(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	var req oncallTestRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	nc, ok := findOncallConnector(s.cfg, tid, req.ConnectorID)
	if !ok {
		return apierror.NotFound("on-call connector is not configured for this tenant")
	}
	c, ok := notify.NewConnector(nc.Provider, nc.Endpoint, nc.Secret, nil)
	if !ok {
		return apierror.Validation("unsupported on-call connector provider")
	}
	testID, err := crypto.UUIDv4()
	if err != nil {
		return apierror.Internal("could not generate test incident id").Wrap(err)
	}
	if s.pool != nil {
		if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			return s.recordAudit(ctx, sc, r, "notify.test_delivery", req.ConnectorID,
				map[string]any{"provider": nc.Provider})
		}); err != nil {
			return err
		}
	}
	del, err := c.Open(r.Context(), incident.Incident{
		ID:         "test-" + testID,
		TenantID:   tid,
		Status:     incident.StatusOpen,
		Severity:   incident.SeverityInfo,
		Title:      "probectl test delivery",
		Target:     "notification-routing",
		StartedAt:  time.Now().UTC(),
		LastSeenAt: time.Now().UTC(),
	})
	if err != nil {
		return apierror.Unavailable("on-call test delivery failed").Wrap(err)
	}
	writeJSON(w, http.StatusAccepted, oncallTestResponse{
		Accepted:    true,
		ConnectorID: req.ConnectorID,
		Provider:    nc.Provider,
		Status:      del.Status,
		ExternalRef: del.ExternalRef,
	})
	return nil
}

func (s *Server) handleAlertChannelTest(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	var req alertChannelTestRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	ruleName := strings.TrimSpace(req.RuleName)
	if ruleName == "" {
		ruleName = "probectl test alert"
	}
	metric := strings.TrimSpace(req.Metric)
	if metric == "" {
		metric = "probectl_test_delivery"
	}
	rule := alert.Rule{
		ID:         "test",
		TenantID:   tid,
		Name:       ruleName,
		Enabled:    true,
		Metric:     metric,
		Type:       alert.Threshold,
		Comparison: alert.GT,
		Threshold:  1,
		ForN:       1,
		Severity:   alert.SeverityInfo,
		Channels:   []alert.ChannelSpec{req.Channel},
	}
	if err := rule.Validate(); err != nil {
		return apierror.Validation(err.Error())
	}
	if s.pool != nil {
		if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			return s.recordAudit(ctx, sc, r, "alert.channel_test", ruleName,
				map[string]any{"type": req.Channel.Type})
		}); err != nil {
			return err
		}
	}
	delivered := alert.NewNotifier(alert.ChannelDeps{}, s.log).Deliver(r.Context(), rule, alert.Alert{
		RuleID:     "test",
		RuleName:   ruleName,
		TenantID:   tid,
		State:      alert.StateFiring,
		Severity:   alert.SeverityInfo,
		Metric:     metric,
		Value:      2,
		Threshold:  1,
		Comparison: alert.GT,
		Reason:     "probectl operator-triggered test delivery",
		At:         time.Now().UTC(),
	})
	if delivered == 0 {
		return apierror.Unavailable("alert channel test delivery failed")
	}
	writeJSON(w, http.StatusAccepted, alertChannelTestResponse{Accepted: true, Type: req.Channel.Type})
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
	ordinals := map[string]int{}
	for _, nc := range cfg.NotifyConnectors {
		if nc.TenantID != tenantID {
			continue
		}
		ordinals[nc.Provider]++
		configured, tlsConfigured, host := siemEndpointPosture(nc.Endpoint)
		status.Outbound = append(status.Outbound, oncallOutboundStatus{
			ID:                      oncallConnectorID(nc.Provider, ordinals[nc.Provider]),
			Provider:                nc.Provider,
			TenantRouted:            true,
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

func oncallConnectorID(provider string, ordinal int) string {
	return fmt.Sprintf("%s-%d", strings.ToLower(strings.TrimSpace(provider)), ordinal)
}

func findOncallConnector(cfg *config.Config, tenantID, connectorID string) (config.NotifyConnector, bool) {
	if cfg == nil {
		return config.NotifyConnector{}, false
	}
	ordinals := map[string]int{}
	for _, nc := range cfg.NotifyConnectors {
		if nc.TenantID != tenantID {
			continue
		}
		ordinals[nc.Provider]++
		if oncallConnectorID(nc.Provider, ordinals[nc.Provider]) == connectorID {
			return nc, true
		}
	}
	return config.NotifyConnector{}, false
}
