// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"encoding/pem"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestDDoSAssessmentServedKeepsBothTenantsAndThemes(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	queries := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	rows := flowstore.NewMemory()
	f.server.WithFlowStore(rows).WithFlowQueryViews(queries).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "flow-assessment-browser-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	const period = 5 * time.Minute
	names := [2]string{"First tenant traffic assessment", "Second tenant traffic assessment"}
	for lane, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		definition := fieldComparisonViewDefinition(names[lane])
		definition.Time.LookbackSeconds = 300
		definition.Plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{
			{Field: "exporter", Op: flow.QueryEqual, Values: []string{"203.0.113.15"}},
		}}
		view, err := queries.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: definition})
		if err != nil {
			t.Fatal(err)
		}
		// Chromium runs use wall-clock completed windows. Seed consecutive
		// modeled pairs so the assertions still hold across a UTC boundary.
		now := time.Now()
		for window := range 3 {
			windows, err := anomaly.FlowFieldCompletedWindows(now.Add(time.Duration(window)*period), anomaly.FlowFieldPreviousWeek, int(period/time.Second))
			if err != nil {
				t.Fatal(err)
			}
			seedDDoSAssessmentRows(t, rows, tenant, windows, lane == 0)
		}
		cookie := seasonalFlowBrowserCookie(t, f, tenant)
		for _, theme := range []string{"light", "dark"} {
			t.Run(names[lane]+" "+theme, func(t *testing.T) {
				expect := []string{"Latest completed window", "Sampling corrected"}
				absent := []string{names[1-lane]}
				if lane == 0 {
					expect = append(expect, "TCP SYN pressure", "Corroborating measurements", ddosFixtureAmount+" bytes")
				} else {
					expect = append(expect, "No detection met the thresholds")
					absent = append(absent, "TCP SYN pressure", ddosFixtureAmount)
				}
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL:            socket.URL + "/ui/explore?native_flow=1&flow_view=" + url.QueryEscape(view.ID),
					Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
					TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 60000,
					Expect: []string{names[lane], "DDoS assessment", "Assess traffic"}, Absent: absent,
					Steps: []testsupport.RenderStep{
						{Fill: "label:text-is('Protected prefix') + div input", Value: "192.0.2.0/24"},
						{Fill: "label:text-is('Minimum bytes per window') + div input", Value: "10000000000000000"},
						{Fill: "label:text-is('Minimum packets per window') + div input", Value: "2500"},
						{Click: "Assess traffic", Expect: expect, Absent: absent},
					},
					Controls: []testsupport.RenderControl{{Role: "combobox", Name: "Observed direction"}, {Role: "button", Name: "Assess traffic"}},
				})
			})
		}
	}
}
