// SPDX-License-Identifier: BUSL-1.1
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
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestProspectEngagementServedInBothThemes(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	mail := &reportMailProbe{attempts: make(map[string][]string)}
	f.server.WithAlertChannelDeps(alert.ChannelDeps{Mail: mail})
	var views [2]*store.DashboardView
	var slugs, destinations [2]string
	themes := [2]string{"light", "dark"}
	names := [2]string{"North prospect report", "South prospect report"}
	for lane, tenant := range f.tenants {
		slug, _, _, err := f.server.tenantSlugAndMeta(t.Context(), tenant)
		if err != nil {
			t.Fatal(err)
		}
		slugs[lane] = slug
		delivery := config.ReportEmailDestination{TenantID: tenant, ID: "assessment", Name: "Configured assessment archive",
			Recipients: []string{"prospect@" + tenant + ".invalid"}}
		f.server.cfg.ReportEmailDestinations = append(f.server.cfg.ReportEmailDestinations, delivery)
		destinations[lane] = reportEmailDestinationID(delivery)
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permLifecycleErase, permLifecycleExp} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			view, err := (store.DashboardReports{}).CreateView(ctx, sc, store.DashboardViewInput{ID: "prospect-" + themes[lane],
				OwnerID: f.users[tenant], Name: names[lane], Preset: "operator", Definition: []byte(`{"client_report":{"timezone":"UTC"}}`)})
			views[lane] = view
			return err
		})
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "prospect-browser-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	end := time.Now().UTC().AddDate(0, 0, 14).Truncate(time.Minute)
	for lane, tenant := range f.tenants {
		t.Run(themes[lane], func(t *testing.T) {
			cookie := auditorTestSession(t, f, tenant)
			const card = "[data-prospect-engagement]"
			spec := testsupport.RenderSpec{URL: socket.URL + "/ui/admin", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
				TrustCertFiles: []string{ca}, CAFile: ca, Theme: themes[lane], Accessibility: true, TimeoutMs: 90000,
				Expect: []string{"Prospect engagement", "Assessment report"}, Absent: []string{names[1-lane]},
				Controls: []testsupport.RenderControl{{Role: "combobox", Name: "Assessment report", Count: 1,
					Within: card + ":has(option[value='" + views[lane].ID + "']):not(:has(option[value='" + views[1-lane].ID + "']))"}}}
			testsupport.RenderUI(t, spec)
			spec.Controls = nil
			spec.Steps = []testsupport.RenderStep{
				{Select: card + " label:text-is('Assessment report') + div select", Value: views[lane].ID},
				{Fill: card + " label:text-is('Assessment preparer') + div input", Value: names[lane] + " MSP"},
				{Fill: card + " label:text-is('Engagement end in UTC') + div input", Value: end.Format("2006-01-02T15:04")},
				{Click: "Authorize verifiable deletion after the completed assessment is delivered", Role: "checkbox", Within: card,
					Expect: []string{"Delivery destination", "Confirm tenant slug"}},
				{Select: card + " label:text-is('Delivery destination') + div select", Value: destinations[lane]},
				{Fill: card + " label:text-is('Confirm tenant slug') + div input", Value: slugs[lane]},
				{Click: "Start prospect engagement", Within: card, ExpectWithin: card, Expect: []string{"Scheduled erasure consent recorded"}},
			}
			testsupport.RenderUI(t, spec)
			f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
				engagement, err := (store.ProspectEngagements{}).Get(ctx, sc)
				if err == nil && (engagement.OwnerID != f.users[tenant] || engagement.AssessmentViewID != views[lane].ID ||
					!engagement.AssessmentAt.Equal(views[lane].UpdatedAt) || !engagement.EndsAt.Equal(end) || engagement.DestinationID != destinations[lane] ||
					!engagement.HasCurrentDeliveryConsent() || engagement.TenantSlug != slugs[lane]) {
					t.Fatal("the served engagement lost its exact consent or retained report revision")
				}
				return err
			})
			decision, outcome := "Withdraw scheduled erasure", "Scheduled erasure consent withdrawn"
			if lane == 1 {
				decision, outcome = "Convert to client", "Converted to client"
			}
			spec.Steps = []testsupport.RenderStep{{Click: decision, Within: card, ExpectWithin: card, Expect: []string{outcome}}}
			spec.Expect = []string{"Prospect engagement", "Scheduled erasure consent recorded"}
			testsupport.RenderUI(t, spec)
			f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
				engagement, err := (store.ProspectEngagements{}).Get(ctx, sc)
				if err == nil && (engagement.Revision != 2 || engagement.ConsentRevokedAt == nil || (engagement.ConvertedAt != nil) != (lane == 1)) {
					t.Fatal("the served action did not use the original tenant's current revision")
				}
				return err
			})
		})
	}
	if len(mail.attempts) != 0 {
		t.Fatal("recording or withdrawing future consent initiated delivery")
	}
}
