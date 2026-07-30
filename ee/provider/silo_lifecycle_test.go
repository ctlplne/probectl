// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package provider

import (
	"context"
	"errors"
	"fmt"
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
	attempted   []string // includes failed idempotent attempts
	provisioned []string // "tenantID|model|residency"
	tornDown    []string
	planes      []string
	failNext    bool
	failErr     error
}

func (f *fakeSilo) Provision(_ context.Context, tenantID, residency string, model tenancy.IsolationModel) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := tenantID + "|" + string(model) + "|" + residency
	f.attempted = append(f.attempted, call)
	if f.failNext {
		f.failNext = false
		if f.failErr != nil {
			return f.failErr
		}
		return context.DeadlineExceeded
	}
	f.provisioned = append(f.provisioned, call)
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

type barrierSilo struct {
	entered chan string
	release chan struct{}
}

func newBarrierSilo() *barrierSilo {
	return &barrierSilo{entered: make(chan string, 2), release: make(chan struct{})}
}

func (s *barrierSilo) Provision(
	ctx context.Context,
	tenantID, residency string,
	model tenancy.IsolationModel,
) error {
	select {
	case s.entered <- tenantID + "|" + string(model) + "|" + residency:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (*barrierSilo) Teardown(context.Context, string, string, tenancy.IsolationModel) error {
	return nil
}
func (*barrierSilo) ValidResidency(string) bool { return true }
func (*barrierSilo) Planes() []string           { return nil }

type completeProvisionFailureStore struct {
	Store
	err error
}

func (s completeProvisionFailureStore) WithAuditedMutation(
	ctx context.Context,
	sink AuditSink,
	fn AuditedMutation,
) error {
	return s.Store.WithAuditedMutation(ctx, sink, func(ctx context.Context, store MutationStore, audit AuditSink) error {
		return fn(ctx, completeProvisionFailureMutation{MutationStore: store, err: s.err}, audit)
	})
}

type completeProvisionFailureMutation struct {
	MutationStore
	err error
}

func (m completeProvisionFailureMutation) CompleteTenantProvision(
	context.Context,
	string,
	int,
) (Tenant, bool, error) {
	return Tenant{}, false, m.err
}

func TestSiloConcurrentCompletionHonorsTenantBand(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 1, 90*24*time.Hour))
	silo := newBarrierSilo()
	invalidated := 0
	f.svc.WithSilo(silo, func() { invalidated++ })

	type result struct {
		tenant Tenant
		err    error
	}
	results := make(chan result, 2)
	for _, slug := range []string{"band-race-a", "band-race-b"} {
		go func(slug string) {
			tenant, err := f.svc.Provision(
				context.Background(), "operator@msp.example", slug, slug, "siloed", "",
			)
			results <- result{tenant: tenant, err: err}
		}(slug)
	}
	for range 2 {
		select {
		case <-silo.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for both isolated tenants to reach external provisioning")
		}
	}
	close(silo.release)

	successes, bandFailures := 0, 0
	for range 2 {
		select {
		case got := <-results:
			switch {
			case got.err == nil:
				successes++
				if got.tenant.Status != "active" {
					t.Fatalf("successful tenant = %+v, want active", got.tenant)
				}
			case errors.Is(got.err, ErrBandExhausted):
				bandFailures++
			default:
				t.Fatalf("concurrent provision error = %v", got.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for concurrent provisioning results")
		}
	}
	if successes != 1 || bandFailures != 1 {
		t.Fatalf("concurrent results: success=%d band_exhausted=%d, want 1/1", successes, bandFailures)
	}
	if active, err := f.store.CountActiveTenants(t.Context()); err != nil {
		t.Fatal(err)
	} else if active != 1 {
		t.Fatalf("active tenant band usage = %d, want 1", active)
	}
	tenants, err := f.store.ListTenants(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	statuses := map[string]int{}
	for _, tenant := range tenants {
		statuses[tenant.Status]++
	}
	if statuses["active"] != 1 || statuses["provisioning"] != 1 {
		t.Fatalf("tenant publication states = %v, want active=1 provisioning=1", statuses)
	}
	if invalidated != 1 {
		t.Fatalf("router invalidations = %d, want only the published tenant", invalidated)
	}
	if f.audit.count("provider.tenant_provision_attempt") != 2 ||
		f.audit.count("provider.tenant_provision_failure") != 1 ||
		f.audit.count("provider.tenant_provision") != 1 {
		t.Fatalf("concurrent provision audit transitions = %+v", f.audit.events)
	}
	if got := f.audit.lastData("provider.tenant_provision_failure")["error_category"]; got != "tenant_band_exhausted" {
		t.Fatalf("tenant-band failure category = %#v, want tenant_band_exhausted", got)
	}
}

func TestTenantProvisionFailureAuditCategoryMatchesPhase(t *testing.T) {
	const backendDetail = "backend DDL failed for secret-db.internal"
	for _, tc := range []struct {
		name string
		want string
		wire func(*fixture)
	}{
		{
			name: "silo provisioning",
			want: "silo_provision_failed",
			wire: func(f *fixture) {
				f.svc.WithSilo(&fakeSilo{
					failNext: true,
					failErr:  errors.New(backendDetail),
				}, nil)
			},
		},
		{
			name: "registry publication",
			want: "registry_publish_failed",
			wire: func(f *fixture) {
				f.svc.WithSilo(&fakeSilo{}, nil)
				f.svc.store = completeProvisionFailureStore{
					Store: f.store,
					err:   errors.New(backendDetail),
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
			tc.wire(f)

			if _, err := f.svc.Provision(
				t.Context(),
				"operator@msp.example",
				"phase-"+strings.ReplaceAll(tc.name, " ", "-"),
				"Phase Correct",
				"siloed",
				"",
			); err == nil {
				t.Fatal("injected provisioning failure returned nil")
			}
			data := f.audit.lastData("provider.tenant_provision_failure")
			if got := data["error_category"]; got != tc.want {
				t.Fatalf("failure category = %#v, want %q", got, tc.want)
			}
			if _, ok := data["error"]; ok {
				t.Fatalf("failure audit contains raw error field: %+v", data)
			}
			if strings.Contains(strings.ToLower(fmt.Sprint(data)), "secret-db") {
				t.Fatalf("failure audit leaked backend detail: %+v", data)
			}
		})
	}
}

func TestSiloProvisionFailureIsResumable(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 1, 90*24*time.Hour))
	silo := &fakeSilo{planes: []string{"eu"}, failNext: true}
	invalidated := 0
	f.svc.WithSilo(silo, func() { invalidated++ })
	token := f.bootstrapAndLoginFast(t)
	body := map[string]string{
		"slug": "resumable-co", "name": "Resumable Co",
		"isolation_model": "siloed", "residency": "eu",
	}

	first := f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants", body)
	if first.Code != http.StatusInternalServerError {
		t.Fatalf("failed first provision = %d %s, want 500", first.Code, first.Body.String())
	}
	tenants, err := f.store.ListTenants(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(tenants) != 1 || tenants[0].Status != "provisioning" {
		t.Fatalf("failed provision inventory = %+v, want one provisioning tenant", tenants)
	}
	pendingID := tenants[0].ID
	if active, err := f.store.CountActiveTenants(t.Context()); err != nil {
		t.Fatal(err)
	} else if active != 0 {
		t.Fatalf("active tenant band usage after failed provision = %d, want 0", active)
	}
	f.store.mu.Lock()
	routable := len(f.store.tenants)
	f.store.mu.Unlock()
	if routable != 0 {
		t.Fatalf("routable registry rows after failed provision = %d, want 0", routable)
	}
	if fleet, err := f.store.FleetSummary(t.Context()); err != nil {
		t.Fatal(err)
	} else if len(fleet) != 0 {
		t.Fatalf("published fleet rows after failed provision = %+v, want none", fleet)
	}
	if invalidated != 0 {
		t.Fatalf("router invalidations after failed provision = %d, want 0", invalidated)
	}
	if f.audit.count("provider.tenant_provision_attempt") != 1 ||
		f.audit.count("provider.tenant_provision_failure") != 1 ||
		f.audit.count("provider.tenant_provision") != 0 {
		t.Fatalf("failed provision audit transitions = %+v", f.audit.events)
	}
	failureData := f.audit.lastData("provider.tenant_provision_failure")
	if failureData["error_category"] != "deadline_exceeded" {
		t.Fatalf("failure audit category = %#v, want deadline_exceeded", failureData["error_category"])
	}
	if _, hasRawError := failureData["error"]; hasRawError {
		t.Fatalf("failure audit leaked a raw external error: %+v", failureData)
	}

	// A retry cannot silently change the incomplete isolated tenant into a
	// pooled tenant with the same slug.
	fallback := f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants",
		map[string]string{"slug": "resumable-co", "name": "Resumable Co"})
	if fallback.Code != http.StatusConflict {
		t.Fatalf("pooled fallback = %d %s, want 409", fallback.Code, fallback.Body.String())
	}

	retry := f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants", body)
	if retry.Code != http.StatusCreated {
		t.Fatalf("retry provision = %d %s, want 201", retry.Code, retry.Body.String())
	}
	var completed Tenant
	mustDecode(t, retry, &completed)
	if completed.ID != pendingID || completed.Status != "active" {
		t.Fatalf("completed tenant = %+v, want same id %q active", completed, pendingID)
	}
	if len(silo.attempted) != 2 || silo.attempted[0] != silo.attempted[1] {
		t.Fatalf("silo attempts = %v, want same tenant target twice", silo.attempted)
	}
	if active, err := f.store.CountActiveTenants(t.Context()); err != nil {
		t.Fatal(err)
	} else if active != 1 {
		t.Fatalf("active tenant band usage after completion = %d, want 1", active)
	}
	if invalidated != 1 {
		t.Fatalf("router invalidations after completion = %d, want 1", invalidated)
	}
	if f.audit.count("provider.tenant_provision_attempt") != 2 ||
		f.audit.count("provider.tenant_provision_failure") != 1 ||
		f.audit.count("provider.tenant_provision") != 1 {
		t.Fatalf("completed provision audit transitions = %+v", f.audit.events)
	}
}

// TestSiloedProvisioningLifecycle is the S-T2 lifecycle suite at the API:
// pooled needs nothing; siloed/hybrid require the capability + a valid
// residency, provision the silo BEFORE success, and keep offboard
// non-destructive so the separate verified erase flow can retain IR evidence.
func TestSiloLifecycle(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
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
	if rec.Code != http.StatusInternalServerError ||
		!strings.Contains(rec.Body.String(), `"message":"internal error"`) ||
		strings.Contains(rec.Body.String(), "re-run provision") {
		t.Fatalf("failed silo provision: %d %s", rec.Code, rec.Body.String())
	}

	// Offboarding the siloed tenant is status-only. It must not destroy the
	// sidecar or any other store before the slug-confirmed erase flow.
	rec = f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants/"+siloed.ID+"/offboard", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("offboard: %d %s", rec.Code, rec.Body.String())
	}
	if len(silo.tornDown) != 0 {
		t.Fatalf("offboard destroyed silo before verified erase: %v", silo.tornDown)
	}
	if f.audit.count("provider.tenant_silo_teardown") != 0 {
		t.Fatal("offboard claimed a silo teardown that did not occur")
	}
	// Offboarding the POOLED tenant calls no teardown (nothing siloed exists).
	rec = f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants/"+pooled.ID+"/offboard", nil)
	if rec.Code != http.StatusOK || len(silo.tornDown) != 0 {
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
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
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
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
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
