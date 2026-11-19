// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/pem"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestScheduledFieldEditorAndReceiptServedInBothThemes(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	queries := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	rows, metrics := flowstore.NewMemory(), tsdb.NewMemory()
	gate := fairness.NewGate(fairness.DefaultPolicy(), nil)
	f.server.WithTSDB(metrics).WithFlowStore(rows).WithFlowQueryViews(queries).WithFairness(gate)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "scheduled-field-browser-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	windows, err := anomaly.FlowFieldCompletedWindows(time.Now(), anomaly.FlowFieldCompleteWeek, 0)
	if err != nil {
		t.Fatal(err)
	}
	names := [2]string{"First tenant field source", "Second tenant field source"}
	themes := [2]string{"light", "dark"}
	for lane, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		view, err := queries.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: fieldComparisonViewDefinition(names[lane])})
		if err != nil {
			t.Fatal(err)
		}
		seedScheduledFieldRows(t, rows, tenant, windows, lane == 0)
		cookie := seasonalFlowBrowserCookie(t, f, tenant)
		for _, theme := range themes {
			name := names[lane] + " " + theme
			t.Run(name+" editor", func(t *testing.T) {
				renderScheduledFieldEditor(t, socket.URL, ca, cookie, theme, name, names[1-lane], view.ID)
			})
		}
		evaluator, ok := BuildAlertEvaluator(f.pool, metrics, alert.ChannelDeps{}, time.Minute, tenancy.ID(tenant), nil, f.server.log,
			AlertTagDependencies{Gate: gate, Queries: f.server, IncidentWindow: time.Minute})
		if !ok {
			t.Fatal("field evaluator is unavailable")
		}
		if err := evaluator.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return verifyScheduledFieldBrowserRules(ctx, t, sc, tenant, names[lane], themes, view)
		})
		if lane != 0 {
			continue
		}
		for _, theme := range themes {
			name := names[lane] + " " + theme
			var incidentID string
			f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
				return sc.Q.QueryRow(ctx, `SELECT incident_id::text FROM incident_signals WHERE tenant_id=$1 AND title=$2 AND kind='alert.field_change'`, tenant, name).Scan(&incidentID)
			})
			t.Run(name+" receipt", func(t *testing.T) {
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL: socket.URL + "/ui/incidents?incident=" + url.QueryEscape(incidentID), Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
					TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 60000,
					Expect: []string{"alert.field_change"}, Absent: []string{names[1-lane]},
					Steps: []testsupport.RenderStep{
						{Click: name, Within: "table:has-text('alert.field_change')", Expect: []string{"Field comparison receipt"}},
						{Click: "Show exact field evidence", Expect: []string{"Entered top set", scheduledFieldAmount, "Outside top set", "First excluded amount 10", windows.Before.Start.Format(time.RFC3339)}},
					},
				})
			})
		}
	}
}

func renderScheduledFieldEditor(t *testing.T, origin, ca, cookie, theme, name, sibling, view string) {
	t.Helper()
	const dialog = "[role=dialog]"
	const create = "Create query alert"
	field := func(label, tag string) string { return dialog + " label:text-is('" + label + "') + div " + tag }
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL: origin + "/ui/alerts", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
		TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 60000,
		Expect: []string{"Alert rules", create}, Absent: []string{sibling},
		Steps: []testsupport.RenderStep{
			{Click: create, ExpectWithin: dialog, Expect: []string{"Saved query", "Condition"}, Absent: []string{sibling}},
			{Fill: field("Rule name", "input"), Value: name},
			{Select: field("Saved query", "select"), Value: view},
			{Select: field("Condition", "select"), Value: "field_change"},
			{Fill: field("Top keys", "input"), Value: "2"},
			{Fill: field("Minimum traffic amount", "input"), Value: "50"},
			{Click: create, Within: dialog, Gone: true, Expect: []string{name}},
			{Click: "Saved query source", Within: "tr:has-text('" + name + "')", ExpectWithin: dialog, Expect: []string{"Load current source"}},
			{Click: "Load current source", Within: dialog, Expect: []string{"Bound revision", "Top keys"}},
		},
		Controls: []testsupport.RenderControl{{Role: "combobox", Name: "Saved query", Within: dialog}, {Role: "combobox", Name: "Condition", Within: dialog}},
	})
}

func verifyScheduledFieldBrowserRules(ctx context.Context, t *testing.T, sc tenancy.Scope, tenant, name string, themes [2]string, view flow.SavedQueryView) error {
	t.Helper()
	rules, err := (store.AlertRules{}).List(ctx, sc)
	if err != nil {
		return err
	}
	for _, theme := range themes {
		found := false
		for _, rule := range rules {
			if rule.Name != name+" "+theme {
				continue
			}
			source, err := (store.AlertRules{}).GetQuerySource(ctx, sc, rule.ID, rule.UpdatedAt, 1<<20)
			if err != nil {
				return err
			}
			if rule.TenantID != tenant || source == nil || source.Source.ViewID != view.ID || source.Source.ViewVersion != view.Version ||
				source.Source.Condition.Field == nil || source.Source.Condition.Field.TopKeys != 2 || source.Source.EverySeconds != 86400 || !source.State.Initialized {
				t.Fatal("the browser did not commit the owned scheduled field source")
			}
			found = true
		}
		if !found {
			t.Fatal("the browser did not create the themed scheduled rule")
		}
	}
	return nil
}
