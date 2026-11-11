// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantlife"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func TestCapacityAgreementsPostgresRealRevisionsIsolationRetirementAndAudit(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, testsupport.PostgresDSN())
	if err != nil {
		testsupport.SkipOrFatal(t, "capacity agreement PostgreSQL configuration unavailable")
		return
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "capacity agreement PostgreSQL unavailable")
		return
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		t.Fatal(err)
	}
	newID := func() string {
		id, err := crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	area, router, iface, shared := newID(), newID(), newID(), newID()
	service := flow.NewPostgresCapacityAgreements(pool, 1<<30, 32<<20, 32<<20, audit.TenantRecord)
	var tenants [2]string
	var heads [2]flow.CapacityAgreement
	for i := range tenants {
		tenant, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("capacity-agreement-%d-%d", i, time.Now().UnixNano()), "capacity agreement")
		if err != nil {
			t.Fatal(err)
		}
		tenants[i] = tenant.ID
		t.Cleanup(func() {
			if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.ID); err != nil {
				t.Error(err)
			}
		})
		bound := tenancy.WithTenant(ctx, tenancy.ID(tenant.ID))
		if err := tenancy.InTenant(bound, pool, func(ctx context.Context, scope tenancy.Scope) error {
			if _, err := scope.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'same site','same VRF')`, tenant.ID, area, newID(), newID()); err != nil {
				return err
			}
			if _, err := scope.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','same router')`, tenant.ID, area, router); err != nil {
				return err
			}
			_, err := scope.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label,parent_entity_id,interface_index) VALUES($1,$2,$3,'interface','same port',$4,7)`, tenant.ID, area, iface, router)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		definition := flow.CapacityAgreementDefinition{Name: "WAN agreement", Reference: "operator recorded", ValidFrom: "2026-11-01T00:00:00.123456789Z", Target: flow.CapacityTarget{Kind: "interface", ContextID: area, InterfaceID: iface}, BillingDay: 31, Timezone: "UTC", Direction: "max_directional_percentiles", Currency: "USD", CommitBPS: "1000000000", UnitBPS: "1000000", UnitPrice: fmt.Sprintf("1.%d00000000000000001", i)}
		heads[i], err = service.SaveCapacityAgreement(bound, "operator", flow.SaveCapacityAgreement{Definition: definition})
		if err != nil || !heads[i].TargetPresent || heads[i].Version != "1" || heads[i].Definition.UnitPrice != definition.UnitPrice {
			t.Fatal("complete tenant agreement was not persisted exactly", heads[i], err)
		}
		// Reuse the same agreement UUID under both tenants and prove the
		// storage layer permits that without sharing either body's terms.
		if err := tenancy.InTenant(bound, pool, func(ctx context.Context, scope tenancy.Scope) error {
			if _, err := scope.Q.Exec(ctx, `INSERT INTO flow_capacity_agreements(tenant_id,id,version) VALUES($1,$2,1)`, tenant.ID, shared); err != nil {
				return err
			}
			_, err := scope.Q.Exec(ctx, `INSERT INTO flow_capacity_agreement_revisions(tenant_id,agreement_id,version,definition,valid_from_nanos)
 SELECT tenant_id,$2,version,definition,valid_from_nanos FROM flow_capacity_agreement_revisions WHERE tenant_id=$1 AND agreement_id=$3`, tenant.ID, shared, heads[i].ID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	for i, tenant := range tenants {
		bound := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		got, err := service.GetCapacityAgreement(bound, "operator", shared, "")
		if err != nil || got.TenantID != tenant || got.Definition.UnitPrice != heads[i].Definition.UnitPrice {
			t.Fatal("same agreement UUID crossed storage tenant scope", got, err)
		}
		if _, err := service.GetCapacityAgreement(bound, "operator", heads[1-i].ID, ""); !errors.Is(err, flow.ErrCapacityAgreementNotFound) {
			t.Fatal("agreement lookup exposed another tenant", err)
		}
		if err := tenancy.InTenant(bound, pool, func(ctx context.Context, scope tenancy.Scope) error {
			var own, foreign int
			if err := scope.Q.QueryRow(ctx, `SELECT count(*) FROM flow_capacity_agreement_revisions`).Scan(&own); err != nil {
				return err
			}
			if err := scope.Q.QueryRow(ctx, `SELECT count(*) FROM flow_capacity_agreement_revisions WHERE tenant_id=$1`, tenants[1-i]).Scan(&foreign); err != nil {
				return err
			}
			if own != 2 || foreign != 0 {
				return fmt.Errorf("unfiltered agreement RLS counts %d/%d", own, foreign)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	red := tenancy.WithTenant(ctx, tenancy.ID(tenants[0]))
	foreignInterface := newID()
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenants[1])), pool, func(ctx context.Context, scope tenancy.Scope) error {
		_, err := scope.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label,parent_entity_id,interface_index) VALUES($1,$2,$3,'interface','foreign-only port',$4,8)`, tenants[1], area, foreignInterface, router)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	foreign := heads[0].Definition
	foreign.Target.InterfaceID = foreignInterface
	if _, err := service.SaveCapacityAgreement(red, "operator", flow.SaveCapacityAgreement{Definition: foreign}); !errors.Is(err, flow.ErrCapacityAgreementNotFound) {
		t.Fatal("agreement admitted a target without the tenant-owned storage FK", err)
	}
	withoutAudit := flow.NewPostgresCapacityAgreements(pool, 1<<30, 32<<20, 32<<20, nil)
	if _, err := withoutAudit.SaveCapacityAgreement(red, "operator", flow.SaveCapacityAgreement{Definition: heads[0].Definition}); err == nil {
		t.Fatal("agreement committed without its atomic configuration audit")
	}
	if err := tenancy.InTenant(red, pool, func(ctx context.Context, scope tenancy.Scope) error {
		var count int
		if err := scope.Q.QueryRow(ctx, `SELECT count(*) FROM flow_capacity_agreements`).Scan(&count); err != nil {
			return err
		}
		if count != 2 {
			return fmt.Errorf("failed foreign/audit save retained %d agreement headers", count)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	changed := heads[0].Definition
	changed.UnitPrice = "-1.250000000000000001"
	changed.ValidFrom = "2026-12-01T00:00:00.123456790Z"
	current, err := service.SaveCapacityAgreement(red, "another operator", flow.SaveCapacityAgreement{ID: heads[0].ID, Version: "1", Definition: changed})
	if err != nil || current.Version != "2" {
		t.Fatal("recorded revision failed", current, err)
	}
	old, err := service.GetCapacityAgreement(red, "operator", heads[0].ID, "1")
	if err != nil || old.Definition.UnitPrice != heads[0].Definition.UnitPrice || old.CurrentVersion != "2" {
		t.Fatal("editing terms overwrote the old recorded agreement", old, err)
	}
	before, _ := time.Parse(time.RFC3339Nano, "2026-12-01T00:00:00.123456789Z")
	after := before.Add(time.Nanosecond)
	for _, scenario := range []struct {
		at      time.Time
		version string
	}{{before, "1"}, {after, "2"}} {
		got, err := service.CapacityAgreementAt(red, "operator", heads[0].ID, scenario.at)
		if err != nil || got.Version != scenario.version {
			t.Fatal("effective terms rounded original nanosecond boundaries", got, err)
		}
	}
	if _, err := service.SaveCapacityAgreement(red, "operator", flow.SaveCapacityAgreement{ID: heads[0].ID, Version: "1", Definition: changed}); !errors.Is(err, flow.ErrCapacityAgreementConflict) {
		t.Fatal("stale edit rewrote recorded terms", err)
	}
	if err := tenancy.InTenant(red, pool, func(ctx context.Context, scope tenancy.Scope) error {
		_, err := scope.Q.Exec(ctx, `UPDATE flow_capacity_agreement_revisions SET definition='{}' WHERE tenant_id=$1`, tenants[0])
		return err
	}); err == nil {
		t.Fatal("application role could mutate recorded revisions")
	}
	proveCapacityAgreementSubjectLifecycle(t, ctx, pool, service, tenants, heads)
	if err := tenancy.InTenant(red, pool, func(ctx context.Context, scope tenancy.Scope) error {
		_, err := scope.Q.Exec(ctx, `DELETE FROM entities WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, tenants[0], area, iface)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	retired, err := service.GetCapacityAgreement(red, "operator", heads[0].ID, "1")
	if err != nil || retired.TargetPresent || retired.Definition.UnitPrice != old.Definition.UnitPrice {
		t.Fatal("inventory retirement destroyed recorded financial terms", retired, err)
	}
	if sibling, err := service.GetCapacityAgreement(tenancy.WithTenant(ctx, tenancy.ID(tenants[1])), "operator", heads[1].ID, ""); err != nil || !sibling.TargetPresent {
		t.Fatal("retirement changed sibling references", sibling, err)
	}
	if err := service.DeleteCapacityAgreement(red, "operator", heads[0].ID, "2"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetCapacityAgreement(red, "operator", heads[0].ID, "1"); !errors.Is(err, flow.ErrCapacityAgreementNotFound) {
		t.Fatal("explicit agreement deletion retained a financial revision", err)
	}
	t.Log("real-integration: PostgreSQL app-role FORCE-RLS, reused tenant-owned IDs, exact terms/effective nanos, immutable revisions/CAS and inventory retirement without financial data loss; telemetry/source/surface proof remains separate")
}

func proveCapacityAgreementSubjectLifecycle(t *testing.T, ctx context.Context, pool *pgxpool.Pool, service *flow.PostgresCapacityAgreements, tenants [2]string, heads [2]flow.CapacityAgreement) {
	t.Helper()
	var agreements [2]flow.CapacityAgreement
	for i, tenant := range tenants {
		definition := heads[i].Definition
		definition.Reference = "alice@example.test"
		var err error
		agreements[i], err = service.SaveCapacityAgreement(tenancy.WithTenant(ctx, tenancy.ID(tenant)), "operator", flow.SaveCapacityAgreement{Definition: definition})
		if err != nil {
			t.Fatal(err)
		}
	}
	red := tenancy.WithTenant(ctx, tenancy.ID(tenants[0]))
	definition := agreements[0].Definition
	definition.Reference = "bob@example.test"
	current, err := service.SaveCapacityAgreement(red, "operator", flow.SaveCapacityAgreement{ID: agreements[0].ID, Version: "1", Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	engine := tenantlife.New(pool, nil, nil, nil, nil, "fixture has no backups", nil)
	for i, subject := range []string{"alice@example.test", "bob@example.test"} {
		report, err := engine.EraseSubject(ctx, tenants[0], subject, "privacy operator", "agreement lifecycle")
		if err != nil || !report.Complete {
			t.Fatal("agreement subject erasure did not complete", subject, report, err)
		}
		if _, err := service.GetCapacityAgreement(red, "operator", agreements[0].ID, "1"); !errors.Is(err, flow.ErrCapacityAgreementNotFound) {
			t.Fatal("subject erasure retained old matching terms", err)
		}
		got, err := service.GetCapacityAgreement(red, "operator", agreements[0].ID, "")
		if i == 0 && (err != nil || got.Version != current.Version || got.Definition.Reference != "bob@example.test") {
			t.Fatal("old revision erasure destroyed unrelated current financial terms", got, err)
		}
		if i == 1 && !errors.Is(err, flow.ErrCapacityAgreementNotFound) {
			t.Fatal("current matching revision erasure retained its financial agreement", got, err)
		}
		sibling, err := service.GetCapacityAgreement(tenancy.WithTenant(ctx, tenancy.ID(tenants[1])), "operator", agreements[1].ID, "")
		if err != nil || sibling.Definition.Reference != "alice@example.test" {
			t.Fatal("subject erasure crossed the agreement tenant boundary", sibling, err)
		}
	}
}
