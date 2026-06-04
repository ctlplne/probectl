package notify

import (
	"context"
	"net/url"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/incident"
)

// --- PagerDuty (Events API v2) ---

// pagerDuty pages on-call via the PagerDuty Events API v2. The secret is the
// integration (routing) key; the endpoint defaults to the v2 enqueue URL.
type pagerDuty struct {
	endpoint   string
	routingKey string
	client     Doer
}

func newPagerDuty(endpoint, secret string, client Doer) *pagerDuty {
	if endpoint == "" {
		endpoint = "https://events.pagerduty.com/v2/enqueue"
	}
	return &pagerDuty{endpoint: endpoint, routingKey: secret, client: clientOr(client)}
}

func (*pagerDuty) Name() string           { return "pagerduty" }
func (*pagerDuty) Capability() Capability { return CapabilityPager }

func (p *pagerDuty) event(action, dedup string, inc incident.Incident) map[string]any {
	m := map[string]any{
		"routing_key":  p.routingKey,
		"event_action": action,
		"dedup_key":    dedup,
	}
	if action == "trigger" {
		m["payload"] = map[string]any{
			"summary":  inc.Title,
			"source":   "probectl",
			"severity": pagerDutySeverity(inc.Severity),
		}
	}
	return m
}

func (p *pagerDuty) Open(ctx context.Context, inc incident.Incident) (Delivery, error) {
	dk := dedupKey(inc.ID)
	if _, err := doJSON(ctx, p.client, "POST", p.endpoint, nil, p.event("trigger", dk, inc)); err != nil {
		return Delivery{}, err
	}
	return Delivery{ExternalRef: dk, Status: "triggered"}, nil
}

func (p *pagerDuty) Resolve(ctx context.Context, inc incident.Incident, ref string) error {
	_, err := doJSON(ctx, p.client, "POST", p.endpoint, nil, p.event("resolve", ref, inc))
	return err
}

// pagerDutySeverity maps to PagerDuty's allowed set (critical|error|warning|info).
func pagerDutySeverity(s incident.Severity) string {
	switch s {
	case incident.SeverityCritical:
		return "critical"
	case incident.SeverityWarning:
		return "warning"
	default:
		return "info"
	}
}

// --- Opsgenie (Alerts API) ---

// opsgenie pages on-call via the Opsgenie Alerts API. The secret is the API key
// (sent as a GenieKey Authorization header); the alias is derived from the
// incident id so create + close target the same alert.
type opsgenie struct {
	endpoint string
	apiKey   string
	client   Doer
}

func newOpsgenie(endpoint, secret string, client Doer) *opsgenie {
	if endpoint == "" {
		endpoint = "https://api.opsgenie.com/v2/alerts"
	}
	return &opsgenie{endpoint: strings.TrimRight(endpoint, "/"), apiKey: secret, client: clientOr(client)}
}

func (*opsgenie) Name() string           { return "opsgenie" }
func (*opsgenie) Capability() Capability { return CapabilityPager }

func (o *opsgenie) auth() map[string]string {
	return map[string]string{"Authorization": "GenieKey " + o.apiKey}
}

func (o *opsgenie) Open(ctx context.Context, inc incident.Incident) (Delivery, error) {
	alias := dedupKey(inc.ID)
	payload := map[string]any{
		"message":  inc.Title,
		"alias":    alias,
		"priority": opsgeniePriority(inc.Severity),
	}
	if _, err := doJSON(ctx, o.client, "POST", o.endpoint, o.auth(), payload); err != nil {
		return Delivery{}, err
	}
	return Delivery{ExternalRef: alias, Status: "open"}, nil
}

func (o *opsgenie) Resolve(ctx context.Context, _ incident.Incident, ref string) error {
	closeURL := o.endpoint + "/" + url.PathEscape(ref) + "/close?identifierType=alias"
	_, err := doJSON(ctx, o.client, "POST", closeURL, o.auth(), map[string]any{"note": "resolved by probectl"})
	return err
}

// opsgeniePriority maps severity to Opsgenie P1..P5.
func opsgeniePriority(s incident.Severity) string {
	switch s {
	case incident.SeverityCritical:
		return "P1"
	case incident.SeverityWarning:
		return "P3"
	default:
		return "P5"
	}
}
