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
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/pkg/sdk"
)

// Actual TLS PG/RLS, current session authentication and served production SPA
// in real Chromium/axe, both tenants/themes. Counter/receipt history is modeled;
// this is not the separate physical SNMP/issued-sender acceptance.
// Its name deliberately avoids the pre-web-build early integration roots.
func TestCapacityMeasuredSurfacesRealTLSPostgresAndPairedThemes(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	f.server.cfg.FlowQueryLibraryBytes = 256 << 20
	f.server.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	memory := flowstore.NewMemory()
	f.server.flowStore = memory
	from, to := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	names := []string{"Capacity alpha private terms", "Capacity beta private terms"}
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permFlowRead, permFlowAgreementsRead, permFlowAgreementsWrite} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
		seedCapacityBillingMonth(f, memory, tenant, from, to)
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "served-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range f.tenants {
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		_, err := client.CreateCapacityAgreement(t.Context(), sdk.CreateCapacityAgreementRequest{Body: &sdk.CapacityAgreementInput{Definition: sdk.CapacityAgreementDefinition{Name: names[lane], Reference: "operator terms", ValidFrom: from.Format(time.RFC3339Nano), Target: sdk.CapacityTarget{Kind: "interface", ContextId: f.contextID, InterfaceId: f.interfaceID}, BillingDay: 1, Timezone: "UTC", Direction: "in", Currency: "USD", CommitBps: "1000", UnitBps: "1000", UnitPrice: "0.250000000000000001"}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	for lane, tenant := range f.tenants {
		for _, theme := range []string{"light", "dark"} {
			t.Run(strconv.Itoa(lane)+"/"+theme, func(t *testing.T) {
				var grants []auth.PermissionGrant
				f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
					var err error
					grants, err = (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[tenant])
					return err
				})
				cookie, err := f.server.sessions.Issue(t.Context(), auth.Session{TenantID: tenant, UserID: f.users[tenant], Email: "capacity@local.invalid", DisplayName: "Capacity reader", MFASatisfied: true, AuthorizationHash: auth.PermissionGrantFingerprint(grants)})
				if err != nil {
					t.Fatal(err)
				}
				const bill = "[data-capacity-bill]"
				const forecast = "[data-capacity-forecast]"
				steps := []testsupport.RenderStep{{Click: "Open " + names[lane], Expect: []string{"Measured bill check", names[lane]}, Absent: []string{names[1-lane]}}}
				for i, value := range []string{"2026-10-15T12:00:00Z", "5m", "3.8000000000000000152", f.contextID, f.interfaceID, "1000000"} {
					steps = append(steps, testsupport.RenderStep{Fill: bill + " input >> nth=" + strconv.Itoa(i), Value: value})
				}
				steps = append(steps, testsupport.RenderStep{Click: "Check measured bill", Within: bill, ExpectWithin: "[aria-label='Measured billing result']", Expect: []string{"15200 / 1", "4750000000000000019 / 1250000000000000000", "8928 / 8928 / 0", f.interfaceID}, Absent: []string{names[1-lane]}})
				for i, value := range []string{f.contextID, f.interfaceID, from.Format(time.RFC3339Nano), from.Add(14 * 24 * time.Hour).Format(time.RFC3339Nano), from.Add(20 * 24 * time.Hour).Format(time.RFC3339Nano), "1000000", "5m", f.contextID, f.interfaceID, "1000000"} {
					steps = append(steps, testsupport.RenderStep{Fill: forecast + " input >> nth=" + strconv.Itoa(i), Value: value})
				}
				steps = append(steps, testsupport.RenderStep{Click: "Forecast runout", Within: forecast, ExpectWithin: "[aria-label='Measured forecast result']", Expect: []string{"4032 / 4032", "in_sample_residual_envelope", "1000000 / 1", f.interfaceID}, Absent: []string{names[1-lane]}})
				testsupport.RenderUI(t, testsupport.RenderSpec{URL: socket.URL + "/ui/capacity", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}}, TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 90000, Expect: []string{"Capacity planning", names[lane]}, Absent: []string{names[1-lane]}, Steps: steps, Controls: []testsupport.RenderControl{{Role: "button", Name: "Check measured bill"}, {Role: "button", Name: "Forecast runout"}}})
			})
		}
	}
}
