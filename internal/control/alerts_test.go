// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"testing"

	"github.com/ctlplne/probectl/internal/alert"
)

func TestAlertRequestToRuleDefaults(t *testing.T) {
	req := alertRequest{
		Name: "loss-high", Metric: "probectl_probe_loss_ratio",
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

// TestRejectUnresolvedRedactedWebhookSecret proves WEB-09: a redacted "***"
// webhook secret that preserveRedactedAlertSecrets cannot carry forward (the
// channel URL changed, or there is no prior channel on create) is refused rather
// than stored verbatim and signed with. A same-URL edit still preserves the
// stored secret.
func TestRejectUnresolvedRedactedWebhookSecret(t *testing.T) {
	stored := &alert.Rule{Channels: []alert.ChannelSpec{
		{Type: "webhook", URL: "https://hooks.example/a", Secret: "real-hmac-key"},
	}}

	// 1) Same URL + redacted secret: preserve restores the stored secret, so the
	// write is accepted and never signed with "***".
	sameURL := &alert.Rule{Channels: []alert.ChannelSpec{
		{Type: "webhook", URL: "https://hooks.example/a", Secret: redactedAlertSecret},
	}}
	preserveRedactedAlertSecrets(sameURL, stored)
	if err := rejectUnresolvedRedactedSecrets(sameURL); err != nil {
		t.Fatalf("same-URL redacted secret should be preserved and accepted, got: %v", err)
	}
	if sameURL.Channels[0].Secret != "real-hmac-key" {
		t.Fatalf("stored secret not preserved on same-URL edit: %q", sameURL.Channels[0].Secret)
	}

	// 2) Changed URL + redacted secret: preserve cannot carry it forward, so the
	// literal "***" would otherwise be stored and signed with. Must be refused.
	changedURL := &alert.Rule{Channels: []alert.ChannelSpec{
		{Type: "webhook", URL: "https://hooks.example/b", Secret: redactedAlertSecret},
	}}
	preserveRedactedAlertSecrets(changedURL, stored)
	if changedURL.Channels[0].Secret != redactedAlertSecret {
		t.Fatalf("precondition: changed-URL secret should remain redacted, got %q", changedURL.Channels[0].Secret)
	}
	if err := rejectUnresolvedRedactedSecrets(changedURL); err == nil {
		t.Fatal(`WEB-09: a changed-URL redacted secret must be refused, not stored as "***"`)
	}

	// 3) Create (no prior rule) + redacted secret: nothing to resolve -> refused.
	created := &alert.Rule{Channels: []alert.ChannelSpec{
		{Type: "webhook", URL: "https://hooks.example/c", Secret: redactedAlertSecret},
	}}
	if err := rejectUnresolvedRedactedSecrets(created); err == nil {
		t.Fatal("WEB-09: a redacted secret on create must be refused")
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
