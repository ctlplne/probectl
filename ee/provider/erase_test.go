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
	"github.com/imfeelingtheagi/probectl/internal/tenantlife"
)

// fakeLifecycle records erase calls (the core engine seam).
type fakeLifecycle struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeLifecycle) Erase(_ context.Context, tenantID, slug, actor string) (tenantlife.Attestation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, tenantID+"|"+slug+"|"+actor)
	return tenantlife.Attestation{
		FormatVersion: 1, TenantID: tenantID, TenantSlug: slug, Actor: actor,
		Complete: true, ReportSHA256: "deadbeef",
		Stores: []tenantlife.StoreResult{{Store: "postgres", VerifiedZero: true}},
	}, nil
}

// TestProviderErase: the operator-facing S-T5 trigger — admin SoD,
// slug-confirmed, audited, attestation returned.
func TestProviderErase(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour))
	life := &fakeLifecycle{}
	f.h.WithLifecycle(life)
	admin := f.bootstrapAndLoginFast(t)

	// Provision a tenant to erase.
	rec := f.doAuthed(t, admin, http.MethodPost, "/provider/v1/tenants",
		map[string]string{"slug": "doomed-co", "name": "Doomed Co"})
	var tn Tenant
	mustDecode(t, rec, &tn)

	// A wrong confirm string is refused — erasure is irreversible.
	rec = f.doAuthed(t, admin, http.MethodPost, "/provider/v1/tenants/"+tn.ID+"/erase",
		map[string]string{"confirm": "wrong-slug"})
	if rec.Code != http.StatusBadRequest || len(life.calls) != 0 {
		t.Fatalf("wrong confirm: %d calls=%v", rec.Code, life.calls)
	}
	// An unknown tenant is not_found before anything runs.
	if rec = f.doAuthed(t, admin, http.MethodPost, "/provider/v1/tenants/tn_ghost/erase",
		map[string]string{"confirm": "x"}); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown tenant: %d", rec.Code)
	}

	// The confirmed erase runs the core engine and returns the attestation.
	rec = f.doAuthed(t, admin, http.MethodPost, "/provider/v1/tenants/"+tn.ID+"/erase",
		map[string]string{"confirm": "doomed-co"})
	if rec.Code != http.StatusOK {
		t.Fatalf("erase: %d %s", rec.Code, rec.Body.String())
	}
	var att tenantlife.Attestation
	mustDecode(t, rec, &att)
	if !att.Complete || att.TenantSlug != "doomed-co" || att.ReportSHA256 == "" {
		t.Fatalf("attestation: %+v", att)
	}
	if len(life.calls) != 1 || !strings.HasPrefix(life.calls[0], tn.ID+"|doomed-co|operator:root@msp.example") {
		t.Fatalf("engine call: %v", life.calls)
	}
	if f.audit.count("provider.tenant_erase") != 1 {
		t.Fatal("provider-side erase must be audited")
	}

	// SoD: a plain operator cannot erase.
	rec2 := f.doAuthed(t, admin, http.MethodPost, "/provider/v1/operators",
		map[string]string{"email": "op@msp.example", "name": "Op", "role": "operator"})
	var created struct {
		Operator    Operator `json:"operator"`
		EnrollToken string   `json:"enroll_token"`
	}
	mustDecode(t, rec2, &created)
	op := f.activateAndIssue(t, created.Operator)
	if rec = f.doAuthed(t, op, http.MethodPost, "/provider/v1/tenants/"+tn.ID+"/erase",
		map[string]string{"confirm": "doomed-co"}); rec.Code != http.StatusForbidden {
		t.Fatalf("SoD: operator erased a tenant: %d", rec.Code)
	}

	// Without the engine attached (pool-less test server) the route is 503.
	bare := newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour))
	tok := bare.bootstrapAndLoginFast(t)
	if rec = bare.doAuthed(t, tok, http.MethodPost, "/provider/v1/tenants/x/erase",
		map[string]string{"confirm": "x"}); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("engine-less erase: %d", rec.Code)
	}
}
