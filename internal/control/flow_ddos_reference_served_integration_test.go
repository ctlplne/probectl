// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"net/url"
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

func TestWeeklyDDoSReferenceServedUsesRepresentativeClock(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	views := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	rows := flowstore.NewMemory()
	f.server.WithFlowStore(rows).WithFlowQueryViews(views).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	socket, ca := serveDDoSBrowserFixture(t, f)
	const width = 5 * time.Second
	center := time.Now().UTC().Truncate(width)
	names := [2]string{"Weekly protected service", "Weekly quiet service"}
	var viewIDs [2]string
	for lane, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		definition := fieldComparisonViewDefinition(names[lane])
		definition.Time.LookbackSeconds = 60
		view, err := views.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: definition})
		if err != nil {
			t.Fatal(err)
		}
		viewIDs[lane] = view.ID
		var population []flowstore.Row
		for week := 0; week <= 4; week++ {
			for offset := -3; offset <= 16; offset++ {
				at := center.AddDate(0, 0, -7*week).Add(time.Duration(offset)*width - 2*time.Second)
				population = append(population, delayFixtureFlow(tenant, at, lane == 0 && week <= 1))
			}
		}
		if err := rows.Insert(ctx, population); err != nil {
			t.Fatal(err)
		}
	}
	outcomes := [2]string{"TCP SYN pressure", "No detection met the thresholds"}
	for lane, theme := range []string{"light", "dark"} {
		t.Run(names[lane]+" "+theme, func(t *testing.T) {
			cookie := seasonalFlowBrowserCookie(t, f, f.tenants[lane])
			testsupport.RenderUI(t, testsupport.RenderSpec{
				URL:            socket.URL + "/ui/explore?native_flow=1&flow_view=" + url.QueryEscape(viewIDs[lane]),
				Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
				TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 60000,
				Expect: []string{names[lane], "DDoS assessment"}, Absent: []string{names[1-lane]},
				Steps: []testsupport.RenderStep{
					{Select: "label:text-is('Traffic reference') + div select", Value: "weekly_representative"},
					{Select: "label:text-is('Observation window') + div select", Value: "5"},
					{Fill: "label:text-is('Protected prefix') + div input", Value: "192.0.2.1/32"},
					{Fill: "label:text-is('Minimum bytes per window') + div input", Value: "200000"},
					{Fill: "label:text-is('Minimum packets per window') + div input", Value: "2500"},
					{Fill: "label:text-is('Minimum observed flow records') + div input", Value: "1"},
					{Click: "Assess traffic", Expect: []string{"Representative original window", outcomes[lane]}, Absent: []string{outcomes[1-lane]}},
				},
				Controls: []testsupport.RenderControl{{Role: "combobox", Name: "Traffic reference"}},
			})
		})
	}
}
