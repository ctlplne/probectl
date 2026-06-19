// SPDX-License-Identifier: LicenseRef-probectl-Commercial-TBD

// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package provider

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/license"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// fakeSilo records provisioning/teardown calls (the S-T2 SiloOps seam).
type fakeSilo struct {
	mu          sync.Mutex
	provisioned []string // "tenantID|model|residency"
	tornDown    []string
	planes      []string
	failNext    bool
}

func (f *fakeSilo) Provision(_ context.Context, tenantID, residency string, model tenancy.IsolationModel) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext {
		f.failNext = false
		return context.DeadlineExceeded
	}
	f.provisioned = append(f.provisioned, tenantID+"|"+string(model)+"|"+residency)
	return nil
}

func (f *fakeSilo) Teardown(_ context.Context, tenantID, residency string, model tenancy.IsolationModel) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tornDown = append(f.tornDown, tenantID+"|"+string(model)+"|"+residency)
	return nil
}

func (f *fakeSilo) ValidResidency(name string) bool {
	if name == "" {
		return true
	}
	for _, p := range f.planes {
		if p == name {
			return true
		}
	}
	return false
}

func (f *fakeSilo) Planes() []string { return f.planes }

// TestSiloedProvisioningLifecycle is the S-T2 lifecycle suite at the API:
// pooled needs nothing; siloed/hybrid require the capability + a valid
// residency, provision the silo BEFORE success, and offboard tears it down.
func TestSiloedProvisioningLifecycle(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour))
	silo := &fakeSilo{planes: []string{"eu"}}
	invalidated := 0
	f.svc.WithSilo(silo, func() { invalidated++ })
	token := f.bootstrapAndLoginFast(t)

	// Pooled: provisions with no silo call, default model recorded.
	rec := f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants",
		map[string]string{"slug": "pool-co", "name": "Pool Co"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("pooled provision: %d %s", rec.Code, rec.Body.String())
	}
	var pooled Tenant
	mustDecode(t, rec, &pooled)
	if pooled.IsolationModel != "pooled" || len(silo.provisioned) != 0 {
		t.Fatalf("pooled tenant: %+v silo=%v", pooled, silo.provisioned)
	}
	// Residency without a silo model is refused (claims must be real).
	rec = f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants",
		map[string]string{"slug": "pin-co", "name": "x", "residency": "eu"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("pooled+residency: %d", rec.Code)
	}

	// Siloed on a configured plane: silo provisioned with the right args.
	rec = f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants",
		map[string]string{"slug": "silo-co", "name": "Silo Co", "isolation_model": "siloed", "residency": "eu"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("siloed provision: %d %s", rec.Code, rec.Body.String())
	}
	var siloed Tenant
	mustDecode(t, rec, &siloed)
	if siloed.IsolationModel != "siloed" || siloed.Residency != "eu" {
		t.Fatalf("siloed tenant record: %+v", siloed)
	}
	if len(silo.provisioned) != 1 || silo.provisioned[0] != siloed.ID+"|siloed|eu" {
		t.Fatalf("silo provision calls: %v", silo.provisioned)
	}
	// An unknown residency is refused, with the configured planes named.
	rec = f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants",
		map[string]string{"slug": "mars-co", "name": "x", "isolation_model": "hybrid", "residency": "mars"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "eu") {
		t.Fatalf("unknown residency: %d %s", rec.Code, rec.Body.String())
	}
	// An invalid model is refused.
	rec = f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants",
		map[string]string{"slug": "odd-co", "name": "x", "isolation_model": "physical"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid model: %d", rec.Code)
	}

	// A failed silo provision fails the call loudly (and is re-runnable).
	silo.failNext = true
	rec = f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants",
		map[string]string{"slug": "retry-co", "name": "x", "isolation_model": "hybrid"})
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "re-run provision") {
		t.Fatalf("failed silo provision: %d %s", rec.Code, rec.Body.String())
	}

	// Offboarding the siloed tenant tears its stores down + audits it.
	rec = f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants/"+siloed.ID+"/offboard", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("offboard: %d %s", rec.Code, rec.Body.String())
	}
	if len(silo.tornDown) != 1 || silo.tornDown[0] != siloed.ID+"|siloed|eu" {
		t.Fatalf("teardown calls: %v", silo.tornDown)
	}
	if f.audit.count("provider.tenant_silo_teardown") != 1 {
		t.Fatal("silo teardown must be audited")
	}
	// Offboarding the POOLED tenant calls no teardown (nothing siloed exists).
	rec = f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants/"+pooled.ID+"/offboard", nil)
	if rec.Code != http.StatusOK || len(silo.tornDown) != 1 {
		t.Fatalf("pooled offboard: %d teardown=%v", rec.Code, silo.tornDown)
	}

	// Lifecycle changes invalidated the isolation router cache.
	if invalidated < 3 {
		t.Fatalf("router invalidations: %d", invalidated)
	}
}

// TestSiloRequiresLicenseCapability: without the SiloOps capability (the
// seam attaches it only when siloed_isolation is licensed), siloed/hybrid
// provisioning is refused and pooled still works.
func TestSiloRequiresLicenseCapability(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour))
	token := f.bootstrapAndLoginFast(t) // NO WithSilo

	rec := f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants",
		map[string]string{"slug": "silo-co", "name": "x", "isolation_model": "siloed"})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "siloed_isolation") {
		t.Fatalf("unlicensed siloed provision: %d %s", rec.Code, rec.Body.String())
	}
	if rec = f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants",
		map[string]string{"slug": "pool-co", "name": "x"}); rec.Code != http.StatusCreated {
		t.Fatalf("pooled must still provision: %d", rec.Code)
	}
}

// TestPooledSiloedHandlerParity is the parity property at the API surface:
// the SAME lifecycle operations behave identically for a pooled and a siloed
// tenant — same routes, same status transitions, same payload shape — only
// the isolation fields differ. (The storage-level parity test runs against
// real Postgres in the integration suite.)
func TestPooledSiloedHandlerParity(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour))
	f.svc.WithSilo(&fakeSilo{}, nil)
	token := f.bootstrapAndLoginFast(t)

	ids := map[string]string{}
	for slug, model := range map[string]string{"pool-co": "pooled", "silo-co": "siloed"} {
		rec := f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants",
			map[string]string{"slug": slug, "name": slug, "isolation_model": model})
		if rec.Code != http.StatusCreated {
			t.Fatalf("%s provision: %d", model, rec.Code)
		}
		var tn Tenant
		mustDecode(t, rec, &tn)
		ids[model] = tn.ID
	}
	for _, model := range []string{"pooled", "siloed"} {
		id := ids[model]
		for _, step := range []struct{ action, want string }{
			{"suspend", "suspended"}, {"resume", "active"},
		} {
			rec := f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants/"+id+"/"+step.action, nil)
			var tn Tenant
			mustDecode(t, rec, &tn)
			if rec.Code != http.StatusOK || tn.Status != step.want {
				t.Fatalf("parity broken: %s %s -> %d %s", model, step.action, rec.Code, tn.Status)
			}
		}
		rec := f.doAuthed(t, token, http.MethodPatch, "/provider/v1/tenants/"+id, map[string]string{"name": "Renamed"})
		var tn Tenant
		mustDecode(t, rec, &tn)
		if rec.Code != http.StatusOK || tn.Name != "Renamed" {
			t.Fatalf("parity broken: %s configure -> %d %+v", model, rec.Code, tn)
		}
	}
}
