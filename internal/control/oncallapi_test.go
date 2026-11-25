// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/tenancy"
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
	type delivery struct {
		path, query string
		payload     struct {
			Text   string
			Blocks []struct {
				Elements []struct{ Text string }
			}
		}
	}
	deliveries := make(chan delivery, 2)
	oncallSink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := delivery{path: r.URL.Path, query: r.URL.RawQuery}
		if err := json.NewDecoder(r.Body).Decode(&got.payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		deliveries <- got
		w.WriteHeader(http.StatusAccepted)
	}))
	defer oncallSink.Close()

	customers := []struct{ tenant, brand, otherBrand, path string }{
		{mappedBrandTenant, "Northstar", "Riverside", "/north"},
		{siblingBrandTenant, "Riverside", "Northstar", "/south"},
	}
	srv := testServer(fakePinger{}).WithCustomerBranding(fixtureBrandResolver{})
	for _, customer := range customers {
		srv.cfg.NotifyConnectors = append(srv.cfg.NotifyConnectors, config.NotifyConnector{
			TenantID: customer.tenant,
			Provider: "slack",
			Endpoint: oncallSink.URL + customer.path,
			Secret:   "not-returned",
		})
	}
	handler := srv.Handler()
	for _, customer := range customers {
		t.Run(customer.brand, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/oncall/test", strings.NewReader(`{"connector_id":"slack-1"}`))
			req.Header.Set("X-Probectl-Tenant", customer.tenant)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusAccepted {
				t.Fatalf("oncall test status = %d body=%s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "not-returned") {
				t.Fatalf("on-call test response leaked secret: %s", rec.Body.String())
			}
			select {
			case got := <-deliveries:
				if got.path != customer.path || got.query != "" {
					t.Fatalf("connector test reached the wrong destination: %q?%s", got.path, got.query)
				}
				if !strings.Contains(got.payload.Text, customer.brand) ||
					strings.Contains(got.payload.Text, customer.otherBrand) ||
					!strings.Contains(got.payload.Text, "Powered by probectl (https://probectl.com)") {
					t.Fatalf("on-call test delivery lost its own brand or fixed attribution: %q", got.payload.Text)
				}
				var attributionLinked bool
				for _, block := range got.payload.Blocks {
					for _, element := range block.Elements {
						attributionLinked = attributionLinked || element.Text == "<https://probectl.com|Powered by probectl>"
					}
				}
				if !attributionLinked {
					t.Fatal("on-call test delivery lost the clickable probectl attribution")
				}
			default:
				t.Fatal("on-call connector test did not deliver")
			}
		})
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
	// INJ-01: the test-channel endpoint is tenant-controlled and must not be an
	// SSRF oracle. The sink here is a loopback httptest server, so the guarded
	// client refuses delivery; the endpoint reports failure and must still not
	// echo the secret, and no request must reach the loopback sink.
	if rec.Code == http.StatusAccepted {
		t.Fatalf("test-channel delivered to a loopback target (SSRF): status %d", rec.Code)
	}
	if signature != "" {
		t.Fatal("test-channel opened a request to the loopback sink")
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

type recordingMailSender struct {
	mu   sync.Mutex
	to   []string
	subj string
	body string
}

func (m *recordingMailSender) Send(_ context.Context, to []string, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.to = append([]string(nil), to...)
	m.subj = subject
	m.body = body
	return nil
}

func TestAlertChannelTestDeliversEmailThroughConfiguredSender(t *testing.T) {
	mail := &recordingMailSender{}
	srv := testServer(fakePinger{}).WithAlertChannelDeps(alert.ChannelDeps{Mail: mail})
	body := `{"rule_name":"latency smoke","metric":"probectl_result_rtt_ms","channel":{"type":"email","recipients":["oncall@example.test"]}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/alerts/test-channel", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("email channel test status = %d body=%s", rec.Code, rec.Body.String())
	}
	mail.mu.Lock()
	defer mail.mu.Unlock()
	if len(mail.to) != 1 || mail.to[0] != "oncall@example.test" ||
		!strings.Contains(mail.subj, "latency smoke") {
		t.Fatalf("email not delivered through the configured sender: to=%v subj=%q", mail.to, mail.subj)
	}
}

func TestAlertChannelTestEmailWithoutSenderStaysHonest(t *testing.T) {
	srv := testServer(fakePinger{}) // no ChannelDeps: email must fail, not pretend
	body := `{"rule_name":"r","metric":"m","channel":{"type":"email","recipients":["oncall@example.test"]}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/alerts/test-channel", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured email channel test = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}
