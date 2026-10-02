// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package tenantlife

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// seedDeviceTables inserts one row into each durable, tenant-owned device table
// added by WEB-26 (migrations 0104/0105): device_configs, device_syslog, and
// inventory_saved_views. They carry tenant_id + FORCE RLS, so they must be
// covered by a full-tenant erase like every other tenant-owned store.
func seedDeviceTables(t *testing.T, pool *pgxpool.Pool, tenantID, label string) {
	t.Helper()
	tctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenantID))
	err := tenancy.InTenant(tctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx,
			`INSERT INTO device_syslog (tenant_id, device, message)
			 VALUES ($1, $2, $3)`,
			tenantID, "edge-router-"+label, "link down on ge-0/0/1"); err != nil {
			return fmt.Errorf("seed device_syslog: %w", err)
		}
		if _, err := sc.Q.Exec(ctx,
			`INSERT INTO device_configs (tenant_id, device, version, content_hash)
			 VALUES ($1, $2, 1, $3)`,
			tenantID, "edge-router-"+label, "sha256:"+label); err != nil {
			return fmt.Errorf("seed device_configs: %w", err)
		}
		if _, err := sc.Q.Exec(ctx,
			`INSERT INTO inventory_saved_views (tenant_id, owner_id, surface, name)
			 VALUES ($1, $2, 'inventory', $3)`,
			tenantID, "operator-"+label, "my-"+label+"-view"); err != nil {
			return fmt.Errorf("seed inventory_saved_views: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed device tables (%s): %v", label, err)
	}
}

func countDeviceRows(t *testing.T, pool *pgxpool.Pool, tenantID string) (syslog, configs, views int64) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`SELECT
		   (SELECT count(*) FROM device_syslog          WHERE tenant_id = $1::uuid),
		   (SELECT count(*) FROM device_configs         WHERE tenant_id = $1::uuid),
		   (SELECT count(*) FROM inventory_saved_views  WHERE tenant_id = $1::uuid)`,
		tenantID,
	).Scan(&syslog, &configs, &views); err != nil {
		t.Fatalf("count device rows: %v", err)
	}
	return syslog, configs, views
}

// TestFullTenantEraseCompletesWithoutProviderPlane is the VER-01 regression: on
// a DB-backed deployment with NO provider plane / NO IR crypto-shred lifecycle
// — the state of BOTH a core (no license) and an Enterprise build, because
// FeatureProviderPlane is MSP-only (internal/license tierFeatures) so neither
// wires WithIRAttributionLifecycle — a full-tenant erase must COMPLETE, empty
// every tenant-scoped store (including the WEB-26 device tables), leave a
// bystander intact, and return a recomputable attestation that verifies on the
// provider chain.
func TestFullTenantEraseCompletesWithoutProviderPlane(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	victim := mkTenant(t, pool, "it-ver01-victim-"+stamp)
	bystander := mkTenant(t, pool, "it-ver01-bystander-"+stamp)
	t.Cleanup(func() {
		// Tenant FKs cascade device/test rows; the victim tombstone also goes.
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM tenants WHERE id = $1 OR id = $2`, victim, bystander); err != nil {
			t.Errorf("cleanup ver01 tenants: %v", err)
		}
	})

	seedTenant(t, pool, victim, "ver01-victim-probe")
	seedTenant(t, pool, bystander, "ver01-bystander-probe")
	seedDeviceTables(t, pool, victim, "victim")
	seedDeviceTables(t, pool, bystander, "bystander")

	// Precondition: device rows exist for both tenants.
	if s, c, v := countDeviceRows(t, pool, victim); s != 1 || c != 1 || v != 1 {
		t.Fatalf("victim device rows pre-erase = syslog:%d configs:%d views:%d, want 1/1/1", s, c, v)
	}

	flows := flowstore.NewMemory()
	_ = flows.Insert(ctx, []flowstore.Row{
		{TenantID: victim, TS: time.Now(), Bytes: 1},
		{TenantID: bystander, TS: time.Now(), Bytes: 2},
	})
	mem := tsdb.NewMemory()
	sink := func(ctx context.Context, actor, action, target string, data map[string]any) error {
		_, err := audit.ProviderAppend(ctx, pool, actor, action, target, data)
		return err
	}
	// NO WithIRAttributionLifecycle: irAttribution stays nil, exactly as on a
	// core or Enterprise build.
	e := New(pool, flows, nil, mem, sink, "backups expire after 14 days (it)", log)

	providerHead, err := audit.ProviderHeadSeq(ctx, pool)
	if err != nil {
		t.Fatalf("provider head: %v", err)
	}

	att, err := e.Erase(ctx, victim, "it-ver01-victim-"+stamp, "privacy-admin")
	if err != nil {
		t.Fatalf("Erase must complete without the provider plane: %v", err)
	}
	if !att.Complete {
		t.Fatalf("attestation incomplete: %+v", att.Stores)
	}

	// Every tenant-scoped store empty for the victim, including device tables.
	if n := countTests(t, pool, victim); n != 0 {
		t.Fatalf("victim tests remaining: %d", n)
	}
	if s, c, v := countDeviceRows(t, pool, victim); s != 0 || c != 0 || v != 0 {
		t.Fatalf("victim device rows after erase = syslog:%d configs:%d views:%d, want 0/0/0", s, c, v)
	}
	// Bystander fully intact.
	if n := countTests(t, pool, bystander); n != 1 {
		t.Fatalf("bystander tests must be untouched: %d", n)
	}
	if s, c, v := countDeviceRows(t, pool, bystander); s != 1 || c != 1 || v != 1 {
		t.Fatalf("bystander device rows after victim erase = syslog:%d configs:%d views:%d, want 1/1/1", s, c, v)
	}

	// Tenant tombstoned.
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM tenants WHERE id = $1`, victim).Scan(&status); err != nil {
		t.Fatalf("read victim status: %v", err)
	}
	if status != "deleted" {
		t.Fatalf("victim tombstone status = %q, want deleted", status)
	}

	// The attestation honestly records that no IR sidecar was deployed, and the
	// report digest recomputes (recomputable attestation).
	var sawIRNote bool
	for _, s := range att.Stores {
		if s.Store == "ir_attribution_keys" {
			sawIRNote = true
			if !s.VerifiedZero {
				t.Fatalf("ir_attribution_keys result not verified-zero: %+v", s)
			}
		}
	}
	if !sawIRNote {
		t.Fatal("attestation missing the ir_attribution_keys result for the no-sidecar case")
	}
	if att.ReportSHA256 == "" || att.ReportSHA256 != att.hash() {
		t.Fatalf("attestation digest does not recompute: stored=%q recomputed=%q", att.ReportSHA256, att.hash())
	}
	// The attestation rode the provider audit chain and its suffix verifies.
	if err := audit.ProviderVerifyFrom(ctx, pool, providerHead); err != nil {
		t.Fatalf("provider chain must verify after the attestation: %v", err)
	}
}

// TestProviderPlaneEraseValidatesCapabilityBeforeFence is the RTT-04
// regression: on a provider-plane control whose IR key-destruction capability
// is NOT mounted (e.g. PROBECTL_IR_PRIVATE_KEY_DIR unset, so the destroyer is
// nil), the precondition failure must be reported BEFORE any irreversible
// audit-write fence, leaving the tenant active, unfenced, retryable, and with
// its data intact.
func TestProviderPlaneEraseValidatesCapabilityBeforeFence(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()

	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantID := mkTenant(t, pool, "it-rtt04-"+stamp)
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM tenants WHERE id = $1`, tenantID); err != nil {
			t.Errorf("cleanup rtt04 tenant: %v", err)
		}
	})
	seedTenant(t, pool, tenantID, "rtt04-probe")

	events := []string{}
	flows := &irLifecycleFlowStore{
		Store:  flowstore.NewMemory(),
		events: &events,
		rows:   map[string]bool{tenantID: true},
	}
	// A provider-plane lifecycle whose Plan fails exactly as the real
	// IRKeyLifecycle.Plan does when no key-destruction capability is mounted
	// (internal/audit/ir_key_shred.go: "capability is not mounted").
	lifecycle := &irLifecycleFake{
		events:  &events,
		planID:  "rtt04-plan",
		planErr: errors.New("audit: IR key destruction capability is not mounted"),
		keys:    map[string]bool{tenantID: true},
	}
	e := New(pool, flows, nil, nil, nil, "test backups", testLog()).
		WithIRAttributionLifecycle(lifecycle)

	att, err := e.Erase(ctx, tenantID, "rtt04-slug", "investigator")
	if err == nil {
		t.Fatal("Erase must fail fast when the IR key-destruction capability is not mounted")
	}
	if att.Complete {
		t.Fatalf("capability failure returned Complete=true: %+v", att)
	}

	// The capability was validated BEFORE the fence: only Plan was attempted,
	// nothing destructive ran, and the tenant store data is untouched.
	if len(events) != 1 || events[0] != "plan:"+tenantID {
		t.Fatalf("calls after capability failure = %v, want [plan:%s]", events, tenantID)
	}
	if !flows.rows[tenantID] {
		t.Fatal("capability failure reached the destructive flow store")
	}
	if n := countTests(t, pool, tenantID); n != 1 {
		t.Fatalf("tenant test rows after failed erase = %d, want 1", n)
	}

	// The tenant remains USABLE: still active, and never fenced (RTT-04). A
	// baseline that fenced before validating the capability would leave
	// status=offboarding with audit_write_fenced_at set.
	var status string
	var fenced bool
	if err := pool.QueryRow(ctx,
		`SELECT status, audit_write_fenced_at IS NOT NULL
		   FROM tenants WHERE id = $1`, tenantID,
	).Scan(&status, &fenced); err != nil {
		t.Fatalf("read tenant fence state: %v", err)
	}
	if status != "active" || fenced {
		t.Fatalf("tenant bricked by premature fence: status=%q fenced=%t, want active/false", status, fenced)
	}

	// Retryable: once the capability is mounted (Plan succeeds and stores are
	// clean), the same tenant erases cleanly with no leftover fence state.
	lifecycle.planErr = nil
	att, err = e.Erase(ctx, tenantID, "rtt04-slug", "investigator")
	if err != nil {
		t.Fatalf("retry after mounting the capability must succeed: %v", err)
	}
	if !att.Complete {
		t.Fatalf("retry attestation incomplete: %+v", att.Stores)
	}
	if n := countTests(t, pool, tenantID); n != 0 {
		t.Fatalf("tenant test rows after successful retry = %d, want 0", n)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM tenants WHERE id = $1`, tenantID).Scan(&status); err != nil {
		t.Fatalf("read tenant status after retry: %v", err)
	}
	if status != "deleted" {
		t.Fatalf("tenant status after successful retry = %q, want deleted", status)
	}
}
