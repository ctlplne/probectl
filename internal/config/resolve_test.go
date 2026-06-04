package config

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestResolveSecretRefs(t *testing.T) {
	resolve := func(_ context.Context, raw string) (string, error) {
		switch raw {
		case "vault:kv/sso#client_secret":
			return "oidc-resolved", nil
		case "aws:prod/cmdb#password":
			return "cmdb-resolved", nil
		case "vault:kv/hooks#hmac":
			return "hook-resolved", nil
		default:
			return raw, nil // literals pass through
		}
	}
	c := &Config{
		OIDCClientSecret: "vault:kv/sso#client_secret",
		CMDBSecret:       "aws:prod/cmdb#password",
		AIModelToken:     "plain-token", // literal stays as-is
		ChangeWebhooks: map[string]ChangeWebhook{
			"gh": {TenantID: "t1", Provider: "github", Secret: "vault:kv/hooks#hmac"},
		},
		NotifyConnectors: []NotifyConnector{
			{TenantID: "t1", Provider: "pagerduty", Secret: "vault:kv/hooks#hmac"},
		},
		NotifyInbound: map[string]NotifyInbound{
			"snow": {TenantID: "t1", Provider: "servicenow", Secret: "vault:kv/hooks#hmac"},
		},
	}
	if err := c.ResolveSecretRefs(context.Background(), resolve); err != nil {
		t.Fatal(err)
	}
	if c.OIDCClientSecret != "oidc-resolved" || c.CMDBSecret != "cmdb-resolved" {
		t.Fatalf("scalar fields not resolved: oidc=%q cmdb=%q", c.OIDCClientSecret, c.CMDBSecret)
	}
	if c.AIModelToken != "plain-token" {
		t.Fatalf("literal mutated: %q", c.AIModelToken)
	}
	if c.ChangeWebhooks["gh"].Secret != "hook-resolved" ||
		c.NotifyConnectors[0].Secret != "hook-resolved" ||
		c.NotifyInbound["snow"].Secret != "hook-resolved" {
		t.Fatalf("collection secrets not resolved: %+v %+v %+v",
			c.ChangeWebhooks["gh"], c.NotifyConnectors[0], c.NotifyInbound["snow"])
	}
}

func TestResolveSecretRefsFailsClosed(t *testing.T) {
	resolve := func(_ context.Context, raw string) (string, error) {
		return "", fmt.Errorf("secrets: resolve vault:kv/sso#…: backend unavailable")
	}
	c := &Config{SIEMToken: "vault:kv/siem#token"}
	err := c.ResolveSecretRefs(context.Background(), resolve)
	if err == nil {
		t.Fatal("backend failure must abort startup (fail closed)")
	}
	// The error names the FIELD, never the secret; the ref fragment stays redacted.
	if !strings.Contains(err.Error(), "PROBECTL_SIEM_TOKEN") || strings.Contains(err.Error(), "#token") {
		t.Fatalf("error shape: %v", err)
	}
}
