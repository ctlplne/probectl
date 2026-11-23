// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package silo

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestPhysicalInventoryKeepsPairedOriginalsAfterSiloCatchUp(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := t.Context()
	prov := NewProvisioner(pool, CHPlanes{}, nil, 0, nil)
	stamp := time.Now().UnixNano()
	ids := [2]string{
		mkTenant(t, pool, fmt.Sprintf("physical-a-%d", stamp), "siloed", ""),
		mkTenant(t, pool, fmt.Sprintf("physical-b-%d", stamp), "siloed", ""),
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for _, id := range ids {
			if err := prov.Teardown(cleanup, id, "", tenancy.IsolationSiloed); err != nil {
				t.Error(err)
			}
		}
		if _, err := pool.Exec(cleanup, `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, ids[:]); err != nil {
			t.Error(err)
		}
	})
	for lane, id := range ids {
		if err := prov.Provision(ctx, id, "", tenancy.IsolationSiloed); err != nil {
			t.Fatal(err)
		}
		if lane == 0 {
			table := quoteIdent(SchemaName(id)) + ".entity_evidence"
			if _, err := pool.Exec(ctx, "ALTER TABLE "+table+" DROP COLUMN snmp_physical_inventory"); err != nil {
				t.Fatal(err)
			}
		}
		if err := prov.CatchUpSchema(ctx, id); err != nil {
			t.Fatal("physical inventory catch-up failed", lane, err)
		}
	}

	tenancy.SetRouter(NewRouter(pool, nil, time.Second))
	t.Cleanup(func() { tenancy.SetRouter(nil) })
	contextID, deviceID, observationID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	source := entity.SourceKey{AgentID: "owned-physical-collector", Kind: entity.DeviceTarget, SourceRef: "192.0.2.31"}
	registry := store.NewEntityRegistry(pool)
	serials := [2]string{"alpha-device-inventory", "beta-device-inventory"}
	for lane, id := range ids {
		bound := tenancy.WithTenant(ctx, tenancy.ID(id))
		serial := fmt.Sprintf("%x", lane+10)
		at := bindPhysicalInventorySiloSource(t, pool, registry, id, contextID, deviceID, serial, source)
		claim := entity.Observation{ID: observationID, Source: source, SourceRef: entity.SNMPPhysicalInventorySource,
			ObservedAt: at, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: source.SourceRef},
			SNMPPhysicalInventory: &entity.SNMPPhysicalInventory{Version: 1, Available: true,
				Components: []entity.SNMPPhysicalComponent{{Index: 7, Class: 3, Serial: serials[lane]}}}}
		receipt, err := registry.WriteEvidenceBatchReceipt(bound, source.AgentID, serial, []entity.Observation{claim})
		if err != nil || receipt.Accepted != 1 || receipt.Unresolved != 0 {
			t.Fatal("physical inventory did not enter the exact routed silo", lane, receipt, err)
		}
	}
	for lane, id := range ids {
		bound := tenancy.WithTenant(ctx, tenancy.ID(id))
		err := tenancy.InTenantReadSnapshot(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
			want := entity.Scope{TenantID: id, ContextID: contextID}
			var evidenceID string
			if err := sc.Q.QueryRow(ctx, `SELECT id::text FROM entity_evidence WHERE tenant_id=$1 AND observation_id=$2`,
				id, observationID).Scan(&evidenceID); err != nil {
				return err
			}
			page, err := registry.CurrentDevicePhysicalInventoryInScope(ctx, sc, want, deviceID, source)
			if err != nil || page.EvidenceID != evidenceID || len(page.Snapshot.Components) != 1 ||
				page.Snapshot.Components[0].Serial != serials[lane] {
				t.Fatal("inventory proof changed original identity or crossed a physical silo", lane, err)
			}
			other := quoteIdent(SchemaName(ids[1-lane])) + ".entity_evidence"
			var visible int
			if err := sc.Q.QueryRow(ctx, "SELECT count(*) FROM "+other).Scan(&visible); err != nil || visible != 0 {
				t.Fatal("direct physical sibling read crossed the database policy", lane, visible, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		err = tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE entity_evidence SET snmp_physical_inventory=NULL
				WHERE tenant_id=$1 AND observation_id=$2`, id, observationID)
			return err
		})
		var denied *pgconn.PgError
		if !errors.As(err, &denied) || denied.Code != "23514" || denied.ConstraintName != "entity_evidence_snmp_physical_inventory_check" {
			t.Fatal("the physical schema did not enforce the typed inventory constraint", lane, err)
		}
	}
}

func bindPhysicalInventorySiloSource(t *testing.T, pool *pgxpool.Pool, registry *store.EntityRegistry, tenantID,
	contextID, deviceID, serial string, source entity.SourceKey) time.Time {
	t.Helper()
	ctx := t.Context()
	agentID := source.AgentID
	agentURI := crypto.AgentSPIFFEID(tenantID, agentID)
	if err := store.NewAgentIdentities(pool).Record(ctx, tenantID, agentID,
		crypto.EntitySPIFFEID(tenantID, agentID), serial, time.Now().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	bound := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	var at time.Time
	err := tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := (store.Agents{}).Register(ctx, sc, agentID, "physical collector", source.SourceRef, "test", agentURI, nil); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
			VALUES($1,$2,$3,$4,'overlap','overlap')`, tenantID, contextID, uuid.NewString(), uuid.NewString()); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label)
			VALUES($1,$2,$3,'device','overlap')`, tenantID, contextID, deviceID); err != nil {
			return err
		}
		if err := registry.AssignEntitySource(ctx, sc, source, contextID, deviceID); err != nil {
			return err
		}
		return sc.Q.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&at)
	})
	if err != nil {
		t.Fatal(err)
	}
	return at
}
