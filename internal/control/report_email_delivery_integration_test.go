// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type reportMailReceipt struct {
	body      []byte
	messageID string
}
type reportMailProbe struct {
	fail     map[string]bool
	attempts map[string][]string
	sent     map[string][]reportMailReceipt
}

func (*reportMailProbe) Send(context.Context, []string, string, string) error {
	return errors.New("report must use an attachment")
}
func (m *reportMailProbe) SendAttachment(ctx context.Context, to []string, _ string, attachment alert.MailAttachment) error {
	if _, ok := tenancy.FromContext(ctx); !ok {
		return errors.New("mail lost tenant context")
	}
	body, err := io.ReadAll(attachment.Body)
	if err != nil {
		return err
	}
	if int64(len(body)) != attachment.Bytes {
		return errors.New("mail lost complete report")
	}
	address := to[0]
	m.attempts[address] = append(m.attempts[address], attachment.MessageID)
	if m.fail[address] {
		m.fail[address] = false
		return errors.New("modeled SMTP failure before acceptance")
	}
	m.sent[address] = append(m.sent[address], reportMailReceipt{body, attachment.MessageID})
	return nil
}
func TestReportEmailRetainsRetryTenantAndCurrentSourceAuthority(t *testing.T) {
	d := seedDependencyRoutingFixture(t)
	f := d.f
	f.server.WithFlowStore(flowstore.NewMemory()).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	mailer := &reportMailProbe{fail: map[string]bool{"client-a@example.test": true}, attempts: map[string][]string{}, sent: map[string][]reportMailReceipt{}}
	f.server.WithAlertChannelDeps(alert.ChannelDeps{Mail: mailer})
	f.server.cfg.ReportEmailDestinations = []config.ReportEmailDestination{
		{TenantID: f.tenants[0], ID: "monthly", Name: "Client A", Recipients: []string{"client-a@example.test"}},
		{TenantID: f.tenants[1], ID: "monthly", Name: "Client B", Recipients: []string{"client-b@example.test"}},
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	defer socket.Close()
	call := func(tenant, method, path string, input any, credentials ...string) (int, []byte) {
		t.Helper()
		var body io.Reader
		if input != nil {
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			body = bytes.NewReader(raw)
		}
		req, err := http.NewRequestWithContext(t.Context(), method, socket.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		token := f.tokens[tenant]
		if len(credentials) > 0 {
			token = credentials[0]
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		response, err := socket.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, raw
	}
	views := map[string]string{}
	destinations := map[string]string{}
	now := time.Now().UTC()
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permMetricsWrite, permTestRead, permChangeRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
		code, raw := call(tenant, http.MethodGet, "/v1/dashboard-report-schedules", nil)
		if code != http.StatusOK {
			t.Fatal("report destinations unavailable", code)
		}
		var list struct {
			Destinations []reportDestination `json:"destinations"`
		}
		if err := json.Unmarshal(raw, &list); err != nil {
			t.Fatal(err)
		}
		if len(list.Destinations) != 2 || list.Destinations[1].Kind != "email" || !list.Destinations[1].Ready {
			t.Fatal("configured destination missing or foreign route exposed")
		}
		destinations[tenant] = list.Destinations[1].ID
		definition := reporting.DashboardDefinition{ClientReport: &reporting.ClientReportDefinition{CapacityTargets: []reporting.ClientReportCapacityTarget{}}, Provenance: []string{"retained monthly originals"}, RedactionState: "metadata", CoverageLimitations: []string{"empty modeled history"}}
		code, raw = call(tenant, http.MethodPost, "/v1/dashboards", reporting.DashboardCreateInput{Name: "Client monthly", Preset: "operator", Definition: definition})
		if code != http.StatusCreated {
			t.Fatal("monthly profile create failed", code)
		}
		var view store.DashboardView
		if err := json.Unmarshal(raw, &view); err != nil {
			t.Fatal(err)
		}
		views[tenant] = view.ID
	}
	schedule := func(tenant, destination string) store.ReportSchedule {
		t.Helper()
		code, raw := call(tenant, http.MethodPost, "/v1/dashboard-report-schedules", reporting.ReportScheduleInput{DashboardID: views[tenant], Name: "Monthly email", Cadence: "monthly", Format: "csv", DestinationID: destination, FirstRunAt: now})
		if code != http.StatusCreated {
			t.Fatalf("monthly email schedule refused %d: %s", code, raw)
		}
		var result store.ReportSchedule
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	a, b := f.tenants[0], f.tenants[1]
	if code, _ := call(a, http.MethodPost, "/v1/dashboard-report-schedules", reporting.ReportScheduleInput{DashboardID: views[a], Name: "Foreign email", Cadence: "monthly", Format: "csv", DestinationID: destinations[b], FirstRunAt: now}); code != http.StatusUnprocessableEntity {
		t.Fatal("another tenant's destination accepted", code)
	}
	supervisor, _ := BuildDashboardReportSupervisor(f.pool, time.Minute, f.server.log)
	supervisor.WithReportSources(f.server)
	for _, tenant := range f.tenants {
		schedule(tenant, destinations[tenant])
		if err := supervisor.materializeTenantReports(t.Context(), tenant, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if err := supervisor.deliverTenantReportEmails(t.Context(), a, now.Add(2*time.Second)); err == nil {
		t.Fatal("modeled transport failure was hidden")
	}
	if err := supervisor.deliverTenantReportEmails(t.Context(), b, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(mailer.sent["client-a@example.test"]) != 0 || len(mailer.sent["client-b@example.test"]) != 1 {
		t.Fatal("failed tenant blocked or changed sibling delivery")
	}
	recovered, _ := BuildDashboardReportSupervisor(f.pool, time.Minute, f.server.log)
	recovered.WithReportSources(f.server)
	if err := recovered.deliverTenantReportEmails(t.Context(), a, now.Add(2*time.Minute)); err != nil {
		t.Fatal("retained retry failed after supervisor reconstruction", err)
	}
	for _, tenant := range f.tenants {
		if err := recovered.deliverTenantReportEmails(t.Context(), tenant, now.Add(3*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	for index, address := range []string{"client-a@example.test", "client-b@example.test"} {
		receipts := mailer.sent[address]
		if len(receipts) != 1 {
			t.Fatal("normal retry duplicated tenant packs")
		}
		if !bytes.Contains(receipts[0].body, []byte(f.tenants[index])) || bytes.Contains(receipts[0].body, []byte(f.tenants[1-index])) {
			t.Fatal("email body escaped tenant isolation")
		}
		for _, id := range mailer.attempts[address] {
			if id != receipts[0].messageID {
				t.Fatal("retry changed stable mail identity")
			}
		}
		code, raw := call(f.tenants[index], http.MethodGet, "/v1/dashboard-report-artifacts", nil)
		if code != http.StatusOK || !bytes.Contains(raw, []byte(`"state":"sent"`)) {
			t.Fatal("tenant inbox lost delivery status", code)
		}
	}
	// The new state columns never grant mutation of report content or digests.
	err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(a)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE dashboard_report_artifacts SET content='changed' WHERE tenant_id=$1`, a)
		return err
	})
	var permission *pgconn.PgError
	if !errors.As(err, &permission) || permission.Code != "42501" {
		t.Fatal("email state granted report body mutation", err)
	}
	lateSchedules := map[string]store.ReportSchedule{}
	for _, tenant := range f.tenants {
		lateSchedules[tenant] = schedule(tenant, destinations[tenant])
		if err := recovered.materializeTenantReports(t.Context(), tenant, now.Add(4*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permTestRead)
		return err
	})
	if err := recovered.deliverTenantReportEmails(t.Context(), a, now.Add(5*time.Second)); err == nil {
		t.Fatal("pending email borrowed withdrawn source permission")
	}
	if err := recovered.deliverTenantReportEmails(t.Context(), b, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(mailer.sent["client-a@example.test"]) != 1 || len(mailer.sent["client-b@example.test"]) != 2 {
		t.Fatal("source withdrawal leaked a body or blocked a sibling")
	}
	token, err := auth.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewMCPTokens(f.pool).CreateWithLifetime(t.Context(), a, f.users[a], "report-revoke-only", crypto.Hash([]byte(token)), time.Now().Add(time.Hour), []string{permMetricsWrite}); err != nil {
		t.Fatal(err)
	}
	if code, _ := call(a, http.MethodPatch, "/v1/dashboard-report-schedules/"+lateSchedules[a].ID, map[string]string{"destination_id": reportInboxDestination}, token); code != http.StatusOK {
		t.Fatal("owner cannot withdraw pending mail after losing source reads", code)
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifacts WHERE tenant_id=$1 AND schedule_id=$2 AND email_state='withdrawn'`, a, lateSchedules[a].ID).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return errors.New("destination revocation did not withdraw pending mail")
		}
		return nil
	})
	if !strings.HasPrefix(destinations[a], "email/") || destinations[a] == destinations[b] {
		t.Fatal("tenant destination binding lost")
	}
	t.Log("real-integration PG/RLS and HTTPS: paired configured routes, immutable complete bodies, retained retry/stable ID, reconstruction, current-source refusal and sibling survival; email delivery and historical inputs modeled; standalone transport test uses real TLS SMTP")
}
