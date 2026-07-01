// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

func TestOncallStatusIsTenantScopedAndRedacted(t *testing.T) {
	tenantA := tenancy.DefaultTenantID.String()
	tenantB := "00000000-0000-0000-0000-000000000002"
	srv := testServer(fakePinger{})
	srv.cfg.NotifyConnectors = []config.NotifyConnector{
		{
			TenantID: tenantA,
			Provider: "pagerduty",
			Endpoint: "https://events.pagerduty.com/v2/enqueue?routing_key=leaky",
			Secret:   "pd-secret",
		},
		{
			TenantID: tenantA,
			Provider: "slack",
			Endpoint: "https://hooks.slack.com/services/T000/B000/token",
		},
		{
			TenantID: tenantB,
			Provider: "jira",
			Endpoint: "https://tenant-b.atlassian.net/rest/api/2/issue?project=OPS",
			Secret:   "jira-secret",
		},
	}
	srv.cfg.NotifyInbound = map[string]config.NotifyInbound{
		"snow-a": {TenantID: tenantA, Provider: "servicenow", Secret: "snow-secret"},
		"jira-b": {TenantID: tenantB, Provider: "jira", Secret: "tenant-b-secret"},
	}

	rec := do(srv, http.MethodGet, "/v1/oncall/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, forbidden := range []string{
		"pd-secret",
		"snow-secret",
		"routing_key=leaky",
		"/services/T000/B000/token",
		"tenant-b.atlassian.net",
		"jira-b",
		"tenant-b-secret",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("oncall status leaked %q in body: %s", forbidden, body)
		}
	}

	var resp oncallStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Configured || resp.OutboundConnectorCount != 2 || resp.InboundWebhookCount != 1 {
		t.Fatalf("default tenant response = %+v", resp)
	}
	if len(resp.Outbound) != 2 || resp.Outbound[0].EndpointHost == "" || resp.Outbound[1].EndpointHost == "" {
		t.Fatalf("outbound posture missing sanitized hosts: %+v", resp.Outbound)
	}
	if resp.Outbound[0].ID == "" || !resp.Outbound[0].TenantRouted {
		t.Fatalf("outbound posture missing connector id / tenant routing: %+v", resp.Outbound)
	}
	if len(resp.Inbound) != 1 || resp.Inbound[0].ID != "snow-a" || resp.Inbound[0].Path != "/ingest/itsm/servicenow/snow-a" {
		t.Fatalf("inbound posture = %+v", resp.Inbound)
	}

	recB := httptest.NewRecorder()
	reqB := httptest.NewRequest(http.MethodGet, "/v1/oncall/status", nil)
	reqB.Header.Set("X-Probectl-Tenant", tenantB)
	srv.Handler().ServeHTTP(recB, reqB)
	if recB.Code != http.StatusOK {
		t.Fatalf("tenant B status = %d body=%s", recB.Code, recB.Body.String())
	}
	bodyB := recB.Body.String()
	if strings.Contains(bodyB, "events.pagerduty.com") || strings.Contains(bodyB, "snow-a") || !strings.Contains(bodyB, "tenant-b.atlassian.net") || !strings.Contains(bodyB, "jira-b") {
		t.Fatalf("tenant B response not scoped correctly: %s", bodyB)
	}

	tenantC := "00000000-0000-0000-0000-000000000003"
	empty := oncallStatusFromConfig(srv.cfg, tenantC, true)
	if empty.Configured || empty.DispatcherRunning || empty.OutboundConnectorCount != 0 || empty.InboundWebhookCount != 0 {
		t.Fatalf("tenant C leaked global integration state: %+v", empty)
	}
}

func TestNotificationRoutingTestDelivery(t *testing.T) {
	var oncallHit bool
	oncallSink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oncallHit = true
		if r.URL.RawQuery != "" {
			t.Fatalf("connector test leaked query into request URL: %s", r.URL.String())
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer oncallSink.Close()

	srv := testServer(fakePinger{})
	srv.cfg.NotifyConnectors = []config.NotifyConnector{{
		TenantID: tenancy.DefaultTenantID.String(),
		Provider: "slack",
		Endpoint: oncallSink.URL,
		Secret:   "not-returned",
	}}

	req := httptest.NewRequest(http.MethodPost, "/v1/oncall/test", strings.NewReader(`{"connector_id":"slack-1"}`))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("oncall test status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !oncallHit {
		t.Fatal("on-call connector test did not deliver")
	}
	if strings.Contains(rec.Body.String(), "not-returned") {
		t.Fatalf("on-call test response leaked secret: %s", rec.Body.String())
	}
}

func TestAlertChannelTestDeliverySignsWebhookAndRedactsSecret(t *testing.T) {
	var signature string
	alertSink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signature = r.Header.Get("X-Probectl-Signature")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer alertSink.Close()

	srv := testServer(fakePinger{})
	body := `{"rule_name":"latency smoke","metric":"probectl_result_rtt_ms","channel":{"type":"webhook","url":"` + alertSink.URL + `","secret":"sign-me"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/alerts/test-channel", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("alert channel test status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.HasPrefix(signature, "sha256=") {
		t.Fatalf("webhook signature missing: %q", signature)
	}
	if strings.Contains(rec.Body.String(), "sign-me") {
		t.Fatalf("alert channel test response leaked secret: %s", rec.Body.String())
	}
}

func TestNotificationRoutingRoutesPermissions(t *testing.T) {
	want := map[string]string{
		http.MethodGet + " /v1/oncall/status":        permIncidentRead,
		http.MethodPost + " /v1/oncall/test":         permIncidentWrite,
		http.MethodPost + " /v1/alerts/test-channel": permAlertWrite,
	}
	for _, rt := range testServer(fakePinger{}).apiRoutes() {
		key := rt.Method + " " + rt.Pattern
		if perm, ok := want[key]; ok {
			if rt.Permission != perm {
				t.Fatalf("%s permission = %q, want %q", key, rt.Permission, perm)
			}
			delete(want, key)
		}
	}
	if len(want) != 0 {
		t.Fatalf("routes not registered: %+v", want)
	}
}
