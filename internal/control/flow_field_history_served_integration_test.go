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

func TestFieldHourlyHistoryServedInBothThemes(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	queries := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	rows := flowstore.NewMemory()
	f.server.WithFlowStore(rows).WithFlowQueryViews(queries).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "hourly-field-comparison-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	clocks, err := anomaly.FlowFieldCompletedWindows(time.Now(), anomaly.FlowFieldHourlyMonth, 3600)
	if err != nil {
		t.Fatal(err)
	}
	names := [2]string{"First tenant hourly baseline", "Second tenant hourly baseline"}
	for lane, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		definition := fieldHourlyPlanDefinition(names[lane])
		view, err := queries.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: definition})
		if err != nil {
			t.Fatal(err)
		}
		seedFieldHourlyPlanRows(t, rows, tenant, clocks, lane == 0)
		cookie := seasonalFlowBrowserCookie(t, f, tenant)
		for _, theme := range []string{"light", "dark"} {
			t.Run(names[lane]+" "+theme, func(t *testing.T) {
				want := []string{"672 completed hours", clocks.History.Start.Format(time.RFC3339)}
				absent := []string{names[1-lane]}
				if lane == 0 {
					want = append(want, "Entered top set", "9007199254740993", "Last included amount 700")
				} else {
					want = append(want, "No field changes met the comparison thresholds.")
					absent = append(absent, "Entered top set", "9007199254740993")
				}
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL:            socket.URL + "/ui/explore?native_flow=1&flow_view=" + url.QueryEscape(view.ID),
					Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
					TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 60000,
					Expect: []string{names[lane], "Historical baseline", "Compare fields"}, Absent: absent,
					Steps: []testsupport.RenderStep{
						{Select: "label:text-is('Historical baseline') + div select", Value: "hourly_4w"},
						{Fill: "label:text-is('Top keys') + div input", Value: "300"},
						{Click: "Compare fields", Expect: want, Absent: absent},
					},
					Controls: []testsupport.RenderControl{{Role: "combobox", Name: "Historical baseline"}, {Role: "spinbutton", Name: "Top keys"}},
				})
			})
		}
	}
}
