// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestProviderProspectOperationsRequireCurrentTenantGrant(t *testing.T) {
	proveProviderProspects(t, false)
}

func TestProviderProspectOperationsServeBothThemes(t *testing.T) {
	proveProviderProspects(t, true)
}

func proveProviderProspects(t *testing.T, render bool) {
	t.Helper()
	fixture := newSepStack(t, func(core *control.Server) {
		core.WithFlowStore(flowstore.NewMemory()).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	})
	admin := fixture.seedAdminOperator(t)
	operator := fixture.createOperator(t, admin, RoleOperator)
	provider := &http.Cookie{Name: SessionCookie, Value: operator.token}
	socket := httptest.NewTLSServer(fixture.h)
	t.Cleanup(socket.Close)

	call := func(cookie *http.Cookie, method, route string, input any, want int) []byte {
		t.Helper()
		var body io.Reader
		if input != nil {
			encoded, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			body = bytes.NewReader(encoded)
		}
		request, err := http.NewRequestWithContext(t.Context(), method, socket.URL+route, body)
		if err != nil {
			t.Fatal(err)
		}
		request.AddCookie(cookie)
		request.Header.Set("Content-Type", "application/json")
		response, err := socket.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != want {
			t.Fatalf("%s %s = %d, want %d: %.300s (%v)", method, route, response.StatusCode, want, raw, err)
		}
		return raw
	}

	const engagement = "/v1/lifecycle/prospect"
	const grantRoute = engagement + "/provider-access"
	const preparer = "Owned prospect preparer"
	tenants := [2]string{}
	users := [2]*sepTenantUser{}
	plans := [2]store.ProspectEngagement{}
	unique := strings.ReplaceAll(fixture.suffix, ".", "-")
	for i, name := range []string{"prospect-a-", "prospect-b-"} {
		tenants[i] = fixture.provisionTenant(t, admin, name+unique)
		users[i] = fixture.tenantAdmin(t, tenants[i], name+fixture.suffix+"@example.test")
		cookie := users[i].cookie
		var view store.DashboardView
		dashboard := reporting.DashboardCreateInput{Name: name, Preset: "operator", Definition: reporting.DashboardDefinition{
			RedactionState:      "tenant report policy",
			Provenance:          []string{"Owned prospect fixture"},
			CoverageLimitations: []string{"Controlled assessment configuration"},
			ClientReport:        &reporting.ClientReportDefinition{Timezone: "UTC"},
		}}
		sepJSON(t, call(cookie, http.MethodPost, "/v1/dashboards", dashboard, http.StatusCreated), &view)
		sepJSON(t, call(cookie, http.MethodPost, engagement, map[string]any{
			"assessment_view_id": view.ID, "assessment_view_revision": view.UpdatedAt, "preparer": preparer,
			"ends_at": time.Now().UTC().Add(2 * time.Hour),
		}, http.StatusCreated), &plans[i])
	}
	providerPath := func(tenant string) string { return "/provider/v1/tenants/" + tenant + "/prospect-report" }
	access := func(lane int, revision int64, allow bool, expected int) {
		t.Helper()
		call(users[lane].cookie, http.MethodPost, grantRoute, map[string]any{
			"engagement_revision": plans[lane].Revision, "access_revision": revision, "allowed": allow,
		}, expected)
	}
	newRequest := func() string {
		t.Helper()
		id, err := crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	request := newRequest()
	alpha, beta := providerPath(tenants[0]), providerPath(tenants[1])
	requestBody := func(lane int, id string, revision int64) reporting.ProspectProviderRequest {
		return reporting.ProspectProviderRequest{ID: id, EngagementRevision: plans[lane].Revision, AccessRevision: revision}
	}
	for lane, path := range []string{alpha, beta} {
		call(provider, http.MethodGet, path, nil, http.StatusNotFound)
		call(provider, http.MethodPost, path, requestBody(lane, request, 1), http.StatusNotFound)
	}
	call(users[1].cookie, http.MethodGet, alpha, nil, http.StatusUnauthorized)
	custodian := fixture.tenantAdmin(t, tenants[0], "prospect-custodian-"+fixture.suffix+"@example.test")
	call(custodian.cookie, http.MethodPost, grantRoute, map[string]any{
		"engagement_revision": plans[0].Revision, "access_revision": 0, "allowed": true,
	}, http.StatusConflict)
	access(0, 0, true, http.StatusOK)
	access(0, 0, false, http.StatusConflict)
	checkStatus := func(path, tenant, phase string, pending bool, receipt, method string, input any, expected int) {
		t.Helper()
		raw := call(provider, method, path, input, expected)
		var status reporting.ProspectProviderStatus
		var fields map[string]json.RawMessage
		sepJSON(t, raw, &status)
		sepJSON(t, raw, &fields)
		fieldCount := 6
		if receipt != "" {
			fieldCount++
		}
		if len(fields) != fieldCount || status.TenantID != tenant || status.Phase != phase ||
			status.Pending != pending || status.RequestID != receipt || status.EngagementRevision < 1 ||
			status.AccessRevision < 1 || bytes.Contains(raw, []byte(preparer)) {
			t.Fatalf("wrong scoped operational response: %s", raw)
		}
	}
	checkStatus(alpha, tenants[0], "collecting", false, "", http.MethodPost, requestBody(0, request, 1), http.StatusAccepted)
	call(provider, http.MethodGet, beta, nil, http.StatusNotFound)
	for i, tenant := range tenants {
		if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), fixture.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE prospect_engagements
				SET starts_at=clock_timestamp()-interval '2 hours', ends_at=clock_timestamp()-interval '1 hour'
				WHERE tenant_id=$1 AND revision=$2`, tenant, plans[i].Revision)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	checkStatus(alpha, tenants[0], "due", true, request, http.MethodPost, requestBody(0, request, 1), http.StatusAccepted)
	checkStatus(alpha, tenants[0], "due", true, request, http.MethodPost, requestBody(0, request, 1), http.StatusAccepted)
	otherOperator := &http.Cookie{Name: SessionCookie, Value: admin.token}
	call(otherOperator, http.MethodPost, alpha, requestBody(0, request, 1), http.StatusNotFound)
	checkStatus(alpha, tenants[0], "due", true, "", http.MethodPost, requestBody(0, newRequest(), 1), http.StatusAccepted)
	call(provider, http.MethodPost, beta, requestBody(1, request, 1), http.StatusNotFound)
	access(1, 0, true, http.StatusOK)
	second := newRequest()
	checkStatus(beta, tenants[1], "due", true, second, http.MethodPost, requestBody(1, second, 1), http.StatusAccepted)

	var custodianView store.ProspectProviderAccess
	sepJSON(t, call(custodian.cookie, http.MethodGet, grantRoute, nil, http.StatusOK), &custodianView)
	if !custodianView.Allowed || custodianView.CanGrant || custodianView.Revision != 1 {
		t.Fatal("delegated withdrawal lost the exact current grant or gained grant authority")
	}
	call(custodian.cookie, http.MethodPost, grantRoute, map[string]any{
		"engagement_revision": custodianView.EngagementRevision, "access_revision": custodianView.Revision, "allowed": false,
	}, http.StatusOK)
	call(provider, http.MethodGet, alpha, nil, http.StatusNotFound)
	call(provider, http.MethodPost, alpha, requestBody(0, request, 1), http.StatusNotFound)
	access(0, 2, true, http.StatusOK)
	call(provider, http.MethodPost, alpha, requestBody(0, request, 1), http.StatusNotFound)
	checkStatus(alpha, tenants[0], "due", false, "", http.MethodGet, nil, http.StatusOK)
	call(users[1].cookie, http.MethodPost, engagement+"/convert", map[string]int64{"revision": plans[1].Revision}, http.StatusOK)
	call(provider, http.MethodPost, beta, requestBody(1, second, 1), http.StatusNotFound)
	for i, tenant := range tenants {
		raw := call(users[i].cookie, http.MethodGet, engagement, nil, http.StatusOK)
		var retained store.ProspectEngagement
		sepJSON(t, raw, &retained)
		if retained.Preparer != preparer || retained.AssessmentViewID != plans[i].AssessmentViewID ||
			retained.ConsentedAt != nil || (i == 0 && retained.Revision != plans[i].Revision) {
			t.Fatalf("provider grant changed the tenant's engagement terms: %s", tenant)
		}
	}
	if render {
		var inventory struct {
			Items []Tenant `json:"items"`
		}
		sepJSON(t, call(provider, http.MethodGet, "/provider/v1/tenants", nil, http.StatusOK), &inventory)
		assertProviderProspectConsole(t, socket, provider, tenants, inventory.Items, preparer)
		checkStatus(alpha, tenants[0], "due", true, "", http.MethodGet, nil, http.StatusOK)
		call(provider, http.MethodGet, beta, nil, http.StatusNotFound)
	}
}

func assertProviderProspectConsole(t *testing.T, socket *httptest.Server, cookie *http.Cookie, tenants [2]string, inventory []Tenant, preparer string) {
	t.Helper()
	ca := filepath.Join(t.TempDir(), "provider-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	steps := []testsupport.RenderStep{{
		Select: "label:text-is('Report family') + div select", Value: "prospect", Expect: []string{"Prospect assessments"},
	}}
	page, position, found := 0, 0, 0
	for _, tenant := range inventory {
		if tenant.Status != "active" {
			continue
		}
		if tenant.ID == tenants[0] || tenant.ID == tenants[1] {
			for page < position/100 {
				steps = append(steps, testsupport.RenderStep{Click: "Next report tenants"})
				page++
			}
			steps = append(steps, testsupport.RenderStep{Click: "Select " + tenant.Name, Role: "checkbox"})
			found++
		}
		position++
	}
	if found != len(tenants) {
		t.Fatal("the paired prospects are absent from the provider roster")
	}
	for _, theme := range []string{"light", "dark"} {
		action := "Request due assessments"
		if theme == "dark" {
			action = "Refresh report progress"
		}
		actions := slices.Clone(steps)
		actions = append(actions, testsupport.RenderStep{Click: action, Expect: []string{
			"2 operational responses", "due · retry requested", "Prospect assessment unavailable",
		}})
		testsupport.RenderUI(t, testsupport.RenderSpec{
			URL: socket.URL + "/ui/provider", Cookies: []testsupport.RenderCookie{{Name: cookie.Name, Value: cookie.Value}},
			CAFile: ca, TrustCertFiles: []string{ca}, Theme: theme, Accessibility: true, TimeoutMs: 90000,
			Expect: []string{"Monthly client reports", "Tenant consent required"}, Steps: actions, Absent: []string{preparer},
		})
	}
}
