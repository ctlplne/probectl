package config

import (
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/change"
)

func TestChangeWebhooksConfig(t *testing.T) {
	cfg, err := Load(envFunc(map[string]string{
		"PROBECTL_CHANGE_WEBHOOKS":           "wh1:11111111-1111-1111-1111-111111111111:generic:sec:ret:colons,wh2:22222222-2222-2222-2222-222222222222:github:abc",
		"PROBECTL_CHANGE_CORRELATION_WINDOW": "12h",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.ChangeWebhooks) != 2 {
		t.Fatalf("ChangeWebhooks = %+v, want 2", cfg.ChangeWebhooks)
	}
	// the secret is the last field, so it may contain ':'
	if w := cfg.ChangeWebhooks["wh1"]; w.Provider != "generic" || w.Secret != "sec:ret:colons" ||
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
	if _, err := Load(envFunc(map[string]string{"PROBECTL_CHANGE_WEBHOOKS": "id:tenant:bogus:secret"})); err == nil {
		t.Error("an unknown provider should be a load error")
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
