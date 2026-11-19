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

func TestFieldComparisonServedKeepsBothTenantsAndThemes(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	queries := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	rows := flowstore.NewMemory()
	f.server.WithFlowStore(rows).WithFlowQueryViews(queries).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "field-comparison-browser-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	windows, err := anomaly.FlowFieldCompletedWindows(time.Now(), anomaly.FlowFieldCompleteWeek, 0)
	if err != nil {
		t.Fatal(err)
	}
	names := [2]string{"First tenant port ranks", "Second tenant port ranks"}
	var views [2]flow.SavedQueryView
	for lane, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		view, err := queries.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: fieldComparisonViewDefinition(names[lane])})
		if err != nil {
			t.Fatal(err)
		}
		views[lane] = view
		seedFieldComparisonRows(t, rows, tenant, windows, lane == 0)
	}
	for lane, tenant := range f.tenants {
		cookie := seasonalFlowBrowserCookie(t, f, tenant)
		for _, theme := range []string{"light", "dark"} {
			t.Run(names[lane]+" "+theme, func(t *testing.T) {
				expected := []string{"No field changes met the comparison thresholds."}
				absent := []string{names[1-lane]}
				if lane == 0 {
					expected = []string{"Entered top set", "Left top set", "9007199254740993", "Outside top set"}
				} else {
					absent = append(absent, "Entered top set", "Left top set")
				}
				expected = append(expected, "Last included amount 9007199254740993", "First excluded amount 9007199254740992")
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL:            socket.URL + "/ui/explore?native_flow=1&flow_view=" + url.QueryEscape(views[lane].ID),
					Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
					TrustCertFiles: []string{ca},
					CAFile:         ca,
					Theme:          theme,
					Accessibility:  true,
					TimeoutMs:      60000,
					Expect:         []string{names[lane], "Field changes", "Compare fields"},
					Absent:         absent,
					Steps: []testsupport.RenderStep{
						{Fill: "label:text-is('Top keys') + div input", Value: "300"},
						{Click: "Compare fields", Expect: expected, Absent: absent},
					},
					Controls: []testsupport.RenderControl{{Role: "combobox", Name: "Change type"},
						{Role: "spinbutton", Name: "Top keys"}, {Role: "button", Name: "Compare fields"}},
				})
			})
		}
	}
}
