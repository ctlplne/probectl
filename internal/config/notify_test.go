// SPDX-License-Identifier: LicenseRef-probectl-TBD

package config

import (
	"strings"
	"testing"
)

func TestNotifyConnectorsConfig(t *testing.T) {
	cfg, err := Load(envFunc(map[string]string{
		// pipe-delimited (the endpoint is a URL with ':'); the secret is the last
		// field and may itself contain '|'. A chat connector may have an empty secret.
		"PROBECTL_NOTIFY_CONNECTORS": "11111111-1111-1111-1111-111111111111|pagerduty|https://events.pagerduty.com/v2/enqueue|rk|with|pipes," +
			"11111111-1111-1111-1111-111111111111|jira|https://jira.test/rest/api/2/issue?project=OPS&resolve_transition=41|email:token," +
			"22222222-2222-2222-2222-222222222222|slack|https://hooks.slack.test/x|",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.NotifyConnectors) != 3 {
		t.Fatalf("NotifyConnectors = %+v, want 3", cfg.NotifyConnectors)
	}
	pd := cfg.NotifyConnectors[0]
	if pd.Provider != "pagerduty" || pd.TenantID != "11111111-1111-1111-1111-111111111111" ||
		pd.Endpoint != "https://events.pagerduty.com/v2/enqueue" || pd.Secret != "rk|with|pipes" {
		t.Errorf("pagerduty connector = %+v (secret should keep its pipes)", pd)
	}
	jira := cfg.NotifyConnectors[1]
	if jira.Provider != "jira" || jira.Secret != "email:token" ||
		jira.Endpoint != "https://jira.test/rest/api/2/issue?project=OPS&resolve_transition=41" {
		t.Errorf("jira connector = %+v (endpoint colons/query must survive)", jira)
	}
	if slack := cfg.NotifyConnectors[2]; slack.Provider != "slack" || slack.Secret != "" {
		t.Errorf("slack connector = %+v (an empty secret is allowed for chat)", slack)
	}

	// Malformed / unknown entries fail closed at startup (a load error).
	if _, err := Load(envFunc(map[string]string{"PROBECTL_NOTIFY_CONNECTORS": "no-pipes-here"})); err == nil {
		t.Error("a connector without the 4 pipe fields should be a load error")
	}
	if _, err := Load(envFunc(map[string]string{"PROBECTL_NOTIFY_CONNECTORS": "t|bogus|https://x|sec"})); err == nil {
		t.Error("an unknown connector provider should be a load error")
	}
	if _, err := Load(envFunc(map[string]string{"PROBECTL_NOTIFY_CONNECTORS": "t|pagerduty||sec"})); err == nil {
		t.Error("an empty endpoint should be a load error")
	}
}

func TestNotifyConnectorsRejectPlaintextRemoteEndpoints(t *testing.T) {
	const key = "PROBECTL_NOTIFY_CONNECTORS"

	remotePlaintext := "11111111-1111-1111-1111-111111111111|servicenow|http://snow.example/api/now/table/incident|user:token"
	if _, err := Load(envFunc(map[string]string{key: remotePlaintext})); err == nil ||
		!strings.Contains(err.Error(), "notify connector endpoint must be https://") {
		t.Fatalf("remote plaintext connector should fail closed, got %v", err)
	}

	loopbackPlaintext := "11111111-1111-1111-1111-111111111111|jira|http://127.0.0.1:8080/rest/api/2/issue?project=OPS|email:token," +
		"11111111-1111-1111-1111-111111111111|slack|http://localhost:9000/hook|"
	if cfg, err := Load(envFunc(map[string]string{key: loopbackPlaintext})); err != nil {
		t.Fatalf("loopback plaintext connector should remain available for dev/test: %v", err)
	} else if len(cfg.NotifyConnectors) != 2 {
		t.Fatalf("loopback connectors = %+v, want 2", cfg.NotifyConnectors)
	}

	badScheme := "11111111-1111-1111-1111-111111111111|pagerduty|ftp://events.example/enqueue|rk"
	if _, err := Load(envFunc(map[string]string{key: badScheme})); err == nil ||
		!strings.Contains(err.Error(), "must be an http(s) URL with a host") {
		t.Fatalf("unsupported connector scheme should fail closed, got %v", err)
	}
}

func TestNotifyInboundConfig(t *testing.T) {
	cfg, err := Load(envFunc(map[string]string{
		// colon form (no endpoint); the secret is last and may contain ':'.
		"PROBECTL_NOTIFY_INBOUND": "snow1:11111111-1111-1111-1111-111111111111:servicenow:sh:h:secret," +
			"jira1:22222222-2222-2222-2222-222222222222:jira:tok",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.NotifyInbound) != 2 {
		t.Fatalf("NotifyInbound = %+v, want 2", cfg.NotifyInbound)
	}
	if w := cfg.NotifyInbound["snow1"]; w.Provider != "servicenow" || w.Secret != "sh:h:secret" ||
		w.TenantID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("snow1 = %+v (secret should keep its colons)", w)
	}
	if cfg.NotifyInbound["jira1"].Provider != "jira" {
		t.Errorf("jira1 = %+v", cfg.NotifyInbound["jira1"])
	}

	if _, err := Load(envFunc(map[string]string{"PROBECTL_NOTIFY_INBOUND": "bad-entry"})); err == nil {
		t.Error("a malformed inbound entry should be a load error")
	}
	if _, err := Load(envFunc(map[string]string{"PROBECTL_NOTIFY_INBOUND": "id:tenant:bogus:secret"})); err == nil {
		t.Error("an unknown inbound provider should be a load error")
	}
}

func TestNotifyEmptyByDefault(t *testing.T) {
	cfg, err := Load(envFunc(map[string]string{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.NotifyConnectors != nil || cfg.NotifyInbound != nil {
		t.Errorf("notify config should be nil when unset: connectors=%v inbound=%v",
			cfg.NotifyConnectors, cfg.NotifyInbound)
	}
}
