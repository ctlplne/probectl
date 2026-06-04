package alert

import "time"

// State is the lifecycle state carried by a notification.
type State string

const (
	StateFiring   State = "firing"
	StateResolved State = "resolved"
)

// Alert is a fired (or resolved) alert for one rule + series.
type Alert struct {
	RuleID     string
	RuleName   string
	TenantID   string
	State      State
	Severity   Severity
	Metric     string
	Labels     map[string]string
	Value      float64
	Threshold  float64
	Comparison Comparison
	Reason     string
	At         time.Time
}

// WebhookPayloadVersion identifies the outbound webhook schema.
const WebhookPayloadVersion = "probectl.alert.v1"

// ruleRef is the rule identity embedded in a webhook payload.
type ruleRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// WebhookPayload is the JSON document POSTed to a webhook channel — the stable
// outbound contract (signed with HMAC-SHA256 in the X-Probectl-Signature header
// when the channel has a secret).
type WebhookPayload struct {
	Version    string            `json:"version"`
	State      string            `json:"state"`
	Rule       ruleRef           `json:"rule"`
	TenantID   string            `json:"tenant_id"`
	Severity   string            `json:"severity"`
	Metric     string            `json:"metric"`
	Labels     map[string]string `json:"labels,omitempty"`
	Value      float64           `json:"value"`
	Threshold  float64           `json:"threshold,omitempty"`
	Comparison string            `json:"comparison,omitempty"`
	Reason     string            `json:"reason"`
	FiredAt    string            `json:"fired_at"`
}

// Payload renders the alert as its webhook schema.
func (a Alert) Payload() WebhookPayload {
	return WebhookPayload{
		Version:    WebhookPayloadVersion,
		State:      string(a.State),
		Rule:       ruleRef{ID: a.RuleID, Name: a.RuleName},
		TenantID:   a.TenantID,
		Severity:   string(a.Severity),
		Metric:     a.Metric,
		Labels:     a.Labels,
		Value:      a.Value,
		Threshold:  a.Threshold,
		Comparison: string(a.Comparison),
		Reason:     a.Reason,
		FiredAt:    a.At.UTC().Format(time.RFC3339),
	}
}
