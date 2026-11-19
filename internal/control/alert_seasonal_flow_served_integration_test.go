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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestSeasonalFlowEditorServedKeepsBothTenantsAndThemes(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	views := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	f.server.WithFlowStore(flowstore.NewMemory()).WithFlowQueryViews(views)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "seasonal-flow-browser-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	labels := [2]string{"Red retained protocol volumes", "Blue retained protocol volumes"}
	var sources [2]flow.SavedQueryView
	for lane, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		source := seedSeasonalFlowView(ctx, t, views, tenant, f.users[tenant], time.Now().UTC().Truncate(time.Hour))
		definition := source.Definition
		definition.Name = labels[lane]
		var err error
		sources[lane], err = views.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{ID: source.ID, Version: source.Version, Definition: definition})
		if err != nil {
			t.Fatal(err)
		}
	}
	for lane, tenant := range f.tenants {
		cookie := seasonalFlowBrowserCookie(t, f, tenant)
		cadence := []anomaly.SeasonalCadence{anomaly.SeasonalDaily, anomaly.SeasonalWeeklyEarly}[lane]
		for _, theme := range []string{"light", "dark"} {
			name := labels[lane] + " " + theme
			t.Run(name, func(t *testing.T) {
				renderSeasonalFlowEditor(t, socket.URL, ca, cookie, theme, name, sources[lane], labels[1-lane], cadence)
				checkServedSeasonalFlowSource(t, f, tenant, name, sources[lane], cadence)
			})
		}
	}
}

func seasonalFlowBrowserCookie(t *testing.T, f *roleExplanationAPIFixture, tenant string) string {
	t.Helper()
	var grants []auth.PermissionGrant
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		grants, err = (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[tenant])
		return err
	})
	cookie, err := f.server.sessions.Issue(t.Context(), auth.Session{TenantID: tenant, UserID: f.users[tenant], Email: "weekly-flow@local.invalid",
		DisplayName: "Alert operator", MFASatisfied: true, AuthorizationHash: auth.PermissionGrantFingerprint(grants)})
	if err != nil {
		t.Fatal(err)
	}
	return cookie
}

func renderSeasonalFlowEditor(t *testing.T, origin, ca, cookie, theme, name string, source flow.SavedQueryView, sibling string, cadence anomaly.SeasonalCadence) {
	t.Helper()
	const dialog = "[role=dialog]"
	const create = "Create seasonal flow alert"
	field := func(label, tag string) string { return dialog + " label:text-is('" + label + "') + div " + tag }
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL: origin + "/ui/alerts", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
		TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 60000,
		Expect: []string{"Active alerts", create}, Absent: []string{sibling},
		Steps: []testsupport.RenderStep{
			{Click: create, ExpectWithin: dialog, Expect: []string{"Find saved flow views", "Flow measure"}, Absent: []string{sibling}},
			{Fill: field("Name", "input"), Value: name},
			{Select: field("Saved flow view", "select"), Value: source.ID},
			{Select: field("Flow measure", "select"), Value: "bytes:total"},
			{Select: field("Learning cadence", "select"), Value: string(cadence)},
			{Fill: field("Minimum change", "input"), Value: "1.5"},
			{Click: create, Within: dialog, Gone: true, Expect: []string{name, "Seasonal baseline (set)"}},
			{Click: "Seasonal baseline for " + name, ExpectWithin: dialog, Expect: []string{"Saved view revision " + source.Version, "Clear seasonal baseline"}, Absent: []string{sibling}},
		},
		Controls: []testsupport.RenderControl{{Role: "combobox", Name: "Saved flow view", Within: dialog},
			{Role: "combobox", Name: "Flow measure", Within: dialog}, {Role: "spinbutton", Name: "Minimum change", Within: dialog}},
	})
}

func checkServedSeasonalFlowSource(t *testing.T, f *roleExplanationAPIFixture, tenant, name string, view flow.SavedQueryView, cadence anomaly.SeasonalCadence) {
	t.Helper()
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		rules, err := (store.AlertRules{}).List(ctx, sc)
		if err != nil {
			return err
		}
		for _, rule := range rules {
			if rule.Name != name {
				continue
			}
			source, err := (store.AlertRules{}).GetSeasonalSource(ctx, sc, rule.ID, rule.UpdatedAt, 1<<20)
			if err != nil {
				return err
			}
			if rule.Metric != alert.SeasonalFlowMetric || source == nil || source.Config.Flow == nil ||
				source.Config.Flow.ViewID != view.ID || source.Config.Flow.ViewVersion != view.Version ||
				source.Config.Flow.Measure != "bytes:total" || source.Config.MinimumChange != 1.5 || source.Config.Cadence != cadence {
				t.Fatal("the browser did not commit the exact tenant view and measure")
			}
			return nil
		}
		t.Fatal("the browser did not commit the owned seasonal flow rule")
		return nil
	})
}
