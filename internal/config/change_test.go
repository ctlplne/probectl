// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/change"
)

func TestChangeWebhooksConfig(t *testing.T) {
	cfg, err := Load(envFunc(map[string]string{
		// Secrets are >= 32 bytes (AUTHZ-19 floor); the last field still keeps its colons.
		"PROBECTL_CHANGE_WEBHOOKS":           "wh1:11111111-1111-1111-1111-111111111111:generic:sec:ret:colons:padded:to:thirty:two:bytes,wh2:22222222-2222-2222-2222-222222222222:github:abcdefghijklmnopqrstuvwxyz012345",
		"PROBECTL_CHANGE_CORRELATION_WINDOW": "12h",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.ChangeWebhooks) != 2 {
		t.Fatalf("ChangeWebhooks = %+v, want 2", cfg.ChangeWebhooks)
	}
	// the secret is the last field, so it may contain ':'
	if w := cfg.ChangeWebhooks["wh1"]; w.Provider != "generic" || w.Secret != "sec:ret:colons:padded:to:thirty:two:bytes" ||
		w.TenantID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("wh1 = %+v (secret should keep its colons)", w)
	}
	if cfg.ChangeWebhooks["wh2"].Provider != "github" {
		t.Errorf("wh2 = %+v", cfg.ChangeWebhooks["wh2"])
	}
	if cfg.ChangeCorrelationWindow != 12*time.Hour {
		t.Errorf("ChangeCorrelationWindow = %s, want 12h", cfg.ChangeCorrelationWindow)
	}

	// malformed entries fail closed at startup (a load error, not a silent skip)
	if _, err := Load(envFunc(map[string]string{"PROBECTL_CHANGE_WEBHOOKS": "bad-entry"})); err == nil {
		t.Error("a malformed webhook entry should be a load error")
	}
	if _, err := Load(envFunc(map[string]string{"PROBECTL_CHANGE_WEBHOOKS": "id:11111111-1111-1111-1111-111111111111:bogus:abcdefghijklmnopqrstuvwxyz012345"})); err == nil {
		t.Error("an unknown provider should be a load error")
	}
	// AUTHZ-19: a secret under the 32-byte floor fails closed at load.
	if _, err := Load(envFunc(map[string]string{"PROBECTL_CHANGE_WEBHOOKS": "wh:11111111-1111-1111-1111-111111111111:generic:tooshort"})); err == nil {
		t.Error("a webhook secret under 32 bytes should be a load error")
	}
	// Exactly 32 bytes is accepted.
	if _, err := Load(envFunc(map[string]string{"PROBECTL_CHANGE_WEBHOOKS": "wh:11111111-1111-1111-1111-111111111111:generic:abcdefghijklmnopqrstuvwxyz012345"})); err != nil {
		t.Errorf("a 32-byte webhook secret should load: %v", err)
	}
}

// The config provider allowlist must stay in sync with the change registry.
func TestChangeProviderAllowlistMatchesRegistry(t *testing.T) {
	if len(knownChangeProviders) != len(change.ProviderNames()) {
		t.Fatalf("allowlist (%d) and registry (%d) differ", len(knownChangeProviders), len(change.ProviderNames()))
	}
	for _, n := range change.ProviderNames() {
		if !knownChangeProviders[n] {
			t.Errorf("change provider %q missing from config allowlist", n)
		}
	}
}
