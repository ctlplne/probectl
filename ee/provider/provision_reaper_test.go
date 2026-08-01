// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

// See ee/doc.go for the boundary rules every ee/ file observes.

package provider

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/license"
)

// TestReapStrandedProvisionsIsBoundedAndAudited proves the sweeper this
// finding requires (S-fadcec95). Before it, an abandoned attempt became a
// PERMANENT staging row: the only cleanup was the success path, there was no
// sweeper, and no way to find one.
func TestReapStrandedProvisionsIsBoundedAndAudited(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	sink := &memAudit{}
	lic := licenseManager(t, license.TierMSP, 100, time.Hour)
	svc, err := NewService(store, sink, lic, fakeTelemetry{byTenant: map[string][]string{}}, testEnvelope(t), 4*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 4; i++ {
		if _, err := store.CreateTenantProvision(ctx,
			fmt.Sprintf("stranded-%d", i), fmt.Sprintf("Stranded %d", i), "siloed", ""); err != nil {
			t.Fatal(err)
		}
	}

	// A non-positive age is refused: it would abandon work still in flight.
	if _, err := svc.ReapStrandedProvisions(ctx, "op@msp", 0, 10); err == nil {
		t.Fatal("reaping with a non-positive age must be refused")
	}
	// Nothing is old enough yet.
	if n, err := svc.ReapStrandedProvisions(ctx, "op@msp", time.Hour, 10); err != nil || n != 0 {
		t.Fatalf("fresh attempts must not be reaped: n=%d err=%v", n, err)
	}
	// Everything qualifies, but the run is BOUNDED to max.
	n, err := svc.ReapStrandedProvisions(ctx, "op@msp", time.Nanosecond, 2)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("reaped %d, want the max of 2 — the sweep is not bounded", n)
	}
	remaining, err := svc.ListStrandedProvisions(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 2 {
		t.Fatalf("%d attempts remain, want 2", len(remaining))
	}
	if got := sink.count("provider.tenant_provision_abandoned"); got != 2 {
		t.Fatalf("each abandonment must be audited, got %d events", got)
	}
}

// TestStrandedProvisionsCarryTheirStepLedger: the console must be able to show
// what happened, which is the difference between an informed retry and a guess.
func TestStrandedProvisionsCarryTheirStepLedger(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	sink := &memAudit{}
	lic := licenseManager(t, license.TierMSP, 100, time.Hour)
	svc, err := NewService(store, sink, lic, fakeTelemetry{byTenant: map[string][]string{}}, testEnvelope(t), 4*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tn, err := store.CreateTenantProvision(ctx, "ledger-a", "Ledger A", "siloed", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordProvisionAttempt(ctx, tn.ID, "silo", "injected ebpf plane failure"); err != nil {
		t.Fatal(err)
	}
	items, err := svc.ListStrandedProvisions(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected the stranded attempt to be listed, got %d", len(items))
	}
	if items[0].LastStep != "silo" || items[0].LastError == "" {
		t.Fatalf("stranded attempt lost its step ledger: %+v", items[0])
	}
	if items[0].Slug != "ledger-a" {
		t.Fatalf("stranded attempt lost its identity: %+v", items[0])
	}
}
