// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package provider

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// D-62: a consented, live break-glass grant still reads nothing of a
// quarantined tenant; the refused attempt consumes no use. The provider
// plane answers 409 tenant_quarantined.
func TestBreakGlassRefusesAQuarantinedTenant(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	telemetry := &countingTelemetry{}
	now := time.Now().UTC()
	svc, err := NewService(store, &memAudit{}, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour),
		telemetry, testEnvelope(t), 4*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	svc.withClock(func() time.Time { return now })
	op, err := store.CreateOperator(ctx, Operator{Email: "operator@msp.example", Name: "Operator", Role: RoleOperator},
		crypto.Hash([]byte("enrollment-token")))
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := store.CreateTenant(ctx, "quarantined", "Quarantined", "pooled", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	consentedAt := now.Add(-time.Minute)
	grant, err := store.CreateGrant(ctx, Grant{OperatorID: op.ID, TenantID: tenant.ID, Reason: "incident response",
		Scope: "read", GrantedBy: op.Email, GrantedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(time.Hour),
		ConsentedBy: "tenant-admin@example.test", ConsentedAt: &consentedAt})
	if err != nil {
		t.Fatal(err)
	}

	prev := tenancy.CurrentQuarantine()
	t.Cleanup(func() { tenancy.SetQuarantine(prev) })
	q := tenancy.NewQuarantine()
	tenancy.SetQuarantine(q)
	q.Enter(tenancy.QuarantineEntry{TenantID: tenant.ID, Reason: tenancy.QuarantinePlaneUnreachable, Plane: "eu"})

	_, err = svc.BreakGlassResults(ctx, op, grant.ID)
	if !errors.Is(err, tenancy.ErrTenantQuarantined) || telemetry.calls != 0 {
		t.Fatalf("BreakGlassResults = %v (telemetry reads %d); want the quarantine refusal and no read", err, telemetry.calls)
	}
	if got, _ := store.GetGrant(ctx, grant.ID); got.UseCount != 0 {
		t.Fatalf("a refused access consumed a use: %d", got.UseCount)
	}
	rec := httptest.NewRecorder()
	(&Handler{}).writeErr(rec, err)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "tenant_quarantined") {
		t.Fatalf("provider error = %d %s, want 409 tenant_quarantined", rec.Code, rec.Body.String())
	}

	q.Release(tenant.ID)
	if _, err := svc.BreakGlassResults(ctx, op, grant.ID); err != nil || telemetry.calls != 1 {
		t.Fatalf("after release: %v (reads %d)", err, telemetry.calls)
	}
}
