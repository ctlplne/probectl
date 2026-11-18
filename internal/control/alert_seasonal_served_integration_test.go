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

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestSeasonalEditorServedKeepsBothTenantsAndThemes(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "served-seasonal-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	names := []string{"Alpha private circuit rate", "Beta private circuit rate"}
	zones := []string{"America/New_York", "Europe/London"}
	holidays := []string{"2026-11-26", "2026-12-25"}
	for lane, tenant := range f.tenants {
		var grants []auth.PermissionGrant
		var ruleID string
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permAlertRead, permAlertWrite, "test.read"} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			rule, err := (store.AlertRules{}).Create(ctx, sc, alert.Rule{Name: names[lane], Enabled: true, Type: alert.Baseline,
				Metric: "owned_circuit_bps", Window: 20, Sensitivity: 3, Comparison: alert.GTE, Severity: alert.SeverityWarning, ForN: 1})
			if err != nil {
				return err
			}
			ruleID = rule.ID
			grants, err = (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[tenant])
			return err
		})
		cookie, err := f.server.sessions.Issue(t.Context(), auth.Session{TenantID: tenant, UserID: f.users[tenant], Email: "seasonal@local.invalid",
			DisplayName: "Alert operator", MFASatisfied: true, AuthorizationHash: auth.PermissionGrantFingerprint(grants)})
		if err != nil {
			t.Fatal(err)
		}
		for _, theme := range []string{"light", "dark"} {
			t.Run(names[lane]+"/"+theme, func(t *testing.T) {
				selector := "[role=dialog]"
				open := "Weekly baseline for " + names[lane]
				modal := "Weekly seasonal baseline for " + names[lane]
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL: socket.URL + "/ui/alerts", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
					TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 60000,
					Expect: []string{"Active alerts", names[lane]}, Absent: []string{names[1-lane]},
					Steps: []testsupport.RenderStep{
						{Click: open, ExpectWithin: selector, Expect: []string{modal, "Timezone", "Minimum change", "Holiday dates"}},
						{Fill: selector + " label:text-is('Timezone') + div input", Value: zones[lane]},
						{Fill: selector + " label:text-is('Minimum change') + div input", Value: "1000.5"},
						{Fill: selector + " label:text-is('Holiday dates') + div textarea", Value: holidays[lane]},
						{Click: "Save weekly baseline", Within: selector, Gone: true, Expect: []string{"Weekly baseline (set)"}},
						{Click: open, ExpectWithin: selector, Expect: []string{"Clear weekly baseline"}},
					},
					Controls: []testsupport.RenderControl{{Role: "textbox", Name: "Timezone", Within: selector},
						{Role: "spinbutton", Name: "Minimum change", Within: selector}, {Role: "textbox", Name: "Holiday dates", Within: selector}},
				})
				f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
					rules := store.AlertRules{}
					rule, err := rules.Get(ctx, sc, ruleID)
					if err != nil {
						return err
					}
					source, err := rules.GetSeasonalSource(ctx, sc, ruleID, rule.UpdatedAt, 1<<20)
					if err == nil && (source == nil || source.Config.Timezone != zones[lane] || source.Config.MinimumChange != 1000.5 ||
						len(source.Config.Holidays) != 1 || source.Config.Holidays[0] != holidays[lane]) {
						t.Fatal("served form did not store the tenant's own weekly calendar")
					}
					return err
				})
			})
		}
	}
}
