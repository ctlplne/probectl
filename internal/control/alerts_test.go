package control

import (
	"testing"

	"github.com/imfeelingtheagi/netctl/internal/alert"
)

func TestAlertRequestToRuleDefaults(t *testing.T) {
	req := alertRequest{
		Name: "loss-high", Metric: "netctl_probe_loss_ratio",
		Type: "threshold", Comparison: "gt", Threshold: 0.5,
	}
	r, err := req.toRule()
	if err != nil {
		t.Fatal(err)
	}
	if !r.Enabled {
		t.Error("enabled should default to true")
	}
	if r.Severity != alert.SeverityWarning {
		t.Errorf("severity = %q, want default warning", r.Severity)
	}
	if r.Type != alert.Threshold || r.Comparison != alert.GT {
		t.Errorf("type/comparison = %q/%q", r.Type, r.Comparison)
	}
}

func TestAlertRequestValidationRejected(t *testing.T) {
	bad := []alertRequest{
		{Name: "", Metric: "m", Type: "threshold", Comparison: "gt"},
		{Name: "n", Metric: "", Type: "threshold", Comparison: "gt"},
		{Name: "n", Metric: "m", Type: "threshold", Comparison: "nonsense"},
		{Name: "n", Metric: "m", Type: "baseline", Window: 1, Sensitivity: 3},
	}
	for i, req := range bad {
		if _, err := req.toRule(); err == nil {
			t.Errorf("request %d should fail validation", i)
		}
	}
}

func TestRedactRuleBlanksSecretsButKeepsOriginal(t *testing.T) {
	r := &alert.Rule{Channels: []alert.ChannelSpec{
		{Type: "webhook", URL: "https://h/a", Secret: "topsecret"},
		{Type: "email", Recipients: []string{"ops@example.com"}},
	}}
	out := redactRule(r)

	if out.Channels[0].Secret != "***" {
		t.Errorf("webhook secret not redacted: %q", out.Channels[0].Secret)
	}
	if out.Channels[0].URL != "https://h/a" {
		t.Error("redaction should not alter the URL")
	}
	if r.Channels[0].Secret != "topsecret" {
		t.Error("redaction must not mutate the original rule")
	}
}
