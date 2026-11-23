// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestFastDDoSAssessmentServedSeparatesMixedPressureFromSteadyTraffic(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	views := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	f.server.WithFlowQueryViews(views).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	names := [2]string{"Protected mixed-vector listener", "Protected steady listener"}
	outcomes := [2]string{"Mixed network vector pressure", "No detection met the thresholds"}
	exporters := [2]string{"203.0.113.15", "203.0.113.16"}
	const period = 10
	const width = period * time.Second
	for lane, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		definition := fieldComparisonViewDefinition(names[lane])
		definition.Time.LookbackSeconds = 60
		definition.Plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{
			{Field: "exporter", Op: flow.QueryIn, Values: exporters[:]},
		}}
		view, err := views.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: definition})
		if err != nil {
			t.Fatal(err)
		}
		cookie := seasonalFlowBrowserCookie(t, f, tenant)
		for _, theme := range []string{"light", "dark"} {
			t.Run(names[lane]+" "+theme, func(t *testing.T) {
				rows := flowstore.NewMemory()
				center := time.Now().UTC().Truncate(width)
				// Each pair covers two distinct adjacent windows. Seed enough
				// pairs for Chromium to cross a wall-clock window boundary.
				for pair := range 4 {
					clocks, err := ddosClocks(center.Add(time.Duration(pair)*2*width), period)
					if err != nil {
						t.Fatal(err)
					}
					for index, owner := range f.tenants {
						seedDDoSEdgeRedistribution(t, rows, owner, exporters, clocks, index == 0, false, ddosEdgeMixedNetwork)
					}
				}
				f.server.WithFlowStore(rows)
				socket, ca := serveDDoSBrowserFixture(t, f)
				expect := []string{outcomes[lane], "Latest completed window", "Required exporters observed · 2"}
				absent := []string{names[1-lane], outcomes[1-lane]}
				if lane == 0 {
					expect = append(expect, "Tentative evidence", "7200 contributing packets")
				} else {
					absent = append(absent, "7200 contributing packets")
				}
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL:            socket.URL + "/ui/explore?native_flow=1&flow_view=" + url.QueryEscape(view.ID),
					Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
					TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 60000,
					Expect: []string{names[lane], "DDoS assessment"}, Absent: []string{names[1-lane]},
					Steps: []testsupport.RenderStep{
						{Select: "label:text-is('Observation window') + div select", Value: "10"},
						{Fill: "label:text-is('Protected prefix') + div input", Value: "192.0.2.1/32"},
						{Fill: "label:text-is('Minimum bytes per window') + div input", Value: "200000"},
						{Fill: "label:text-is('Minimum packets per window') + div input", Value: "2500"},
						{Fill: "label:text-is('Required exporter IPs') + div input", Value: strings.Join(exporters[:], ", ")},
						{Click: "Assess traffic", Expect: expect, Absent: absent},
					},
				})
			})
		}
	}
}
