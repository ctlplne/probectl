// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

type fakeIsolationRouter struct {
	targets tenancy.Targets
	err     error
	asked   []string
}

func (f *fakeIsolationRouter) TargetsFor(_ context.Context, tenantID string) (tenancy.Targets, error) {
	f.asked = append(f.asked, tenantID)
	return f.targets, f.err
}

func (f *fakeIsolationRouter) BusNamespaces(context.Context) ([]string, error) {
	return nil, nil
}

func (f *fakeIsolationRouter) BusNamespaceTenants(context.Context) (map[string]string, error) {
	return nil, nil
}

func TestIsolationStatusPoollessDefault(t *testing.T) {
	tenancy.SetRouter(nil)
	defer tenancy.SetRouter(nil)
	const tenantID = "11111111-1111-1111-1111-111111111111"
	rec := doAsTenant(testServer(fakePinger{}), http.MethodGet, "/v1/isolation/status", tenantID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var got isolationStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, rec.Body.String())
	}
	if got.TenantID != tenantID {
		t.Fatalf("tenant_id = %q, want %q", got.TenantID, tenantID)
	}
	if got.EffectiveModel != "pooled" || got.LaneNamespace.Mode != "shared_tenant_tagged" {
		t.Fatalf("unexpected pooled posture: %+v", got)
	}
	if got.RLS.DatabaseConfigured {
		t.Fatalf("poolless server should report rls.database_configured=false: %+v", got.RLS)
	}
}

func TestIsolationStatusUsesCallerTenantOnly(t *testing.T) {
	const tenantID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	router := &fakeIsolationRouter{targets: tenancy.Targets{
		Model:        tenancy.IsolationSiloed,
		PGSchema:     "t_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CHDatabase:   "probectl_t_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CHBaseURL:    "https://ch-eu.internal",
		BusNamespace: "t-acme",
		ObjectPrefix: "silo/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		Residency:    "eu",
	}}
	tenancy.SetRouter(router)
	defer tenancy.SetRouter(nil)

	rec := doAsTenant(testServer(fakePinger{}), http.MethodGet, "/v1/isolation/status", tenantID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var got isolationStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, rec.Body.String())
	}
	if len(router.asked) != 1 || router.asked[0] != tenantID {
		t.Fatalf("router asked = %v, want only caller tenant %s", router.asked, tenantID)
	}
	if got.EffectiveModel != "siloed" || got.Residency != "eu" {
		t.Fatalf("effective posture = model %q residency %q", got.EffectiveModel, got.Residency)
	}
	if got.LaneNamespace.Namespace != "t-acme" || got.LaneNamespace.TopicExample != "probectl.t-acme.network.results" {
		t.Fatalf("lane namespace = %+v", got.LaneNamespace)
	}
	if !got.SiloRouting.Enabled || !got.SiloRouting.ClickHouseResidencyPlaneConfigured {
		t.Fatalf("silo routing = %+v", got.SiloRouting)
	}
	if strings.Contains(rec.Body.String(), "ch-eu.internal") {
		t.Fatalf("status leaked internal data-plane URL:\n%s", rec.Body.String())
	}
}

func TestIsolationStatusSanitizesRouterErrors(t *testing.T) {
	router := &fakeIsolationRouter{err: errors.New("registry failure while loading 22222222-2222-2222-2222-222222222222")}
	tenancy.SetRouter(router)
	defer tenancy.SetRouter(nil)

	rec := do(testServer(fakePinger{}), http.MethodGet, "/v1/isolation/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "22222222-2222-2222-2222-222222222222") ||
		strings.Contains(rec.Body.String(), "registry failure") {
		t.Fatalf("status leaked raw router error:\n%s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "isolation router could not resolve this tenant") {
		t.Fatalf("status missing sanitized router error:\n%s", rec.Body.String())
	}
}
