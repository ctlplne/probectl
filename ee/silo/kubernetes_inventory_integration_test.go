// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration || isolation

package silo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestKubernetesInventorySiloCatchUpKeepsForeignReferencesAndPruningScoped(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	provisioner := NewProvisioner(pool, CHPlanes{}, nil, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := t.Context()
	stamp := fmt.Sprint(time.Now().UnixNano())
	tenants := []string{mkTenant(t, pool, "k8s-silo-a-"+stamp, "siloed", ""), mkTenant(t, pool, "k8s-silo-b-"+stamp, "siloed", "")}
	t.Cleanup(func() {
		for _, tenant := range tenants {
			if err := provisioner.Teardown(context.Background(), tenant, "", tenancy.IsolationSiloed); err != nil {
				t.Error(err)
			}
		}
		if _, err := pool.Exec(context.Background(), "DELETE FROM public.tenants WHERE id=ANY($1::uuid[])", tenants); err != nil {
			t.Error(err)
		}
	})
	for _, tenant := range tenants {
		if err := provisioner.Provision(ctx, tenant, "", tenancy.IsolationSiloed); err != nil {
			t.Fatal(err)
		}
	}
	schemaA := quoteIdent(SchemaName(tenants[0]))
	// Remove only this fixture's FK to exercise the upgrade path on an
	// existing silo with the same tables but a missing composite constraint.
	if _, err := pool.Exec(ctx, "ALTER TABLE "+schemaA+".kubernetes_inventory_generations DROP CONSTRAINT k8s_inventory_generation_source_fk"); err != nil {
		t.Fatal(err)
	}
	if err := provisioner.CatchUpSchema(ctx, tenants[0]); err != nil {
		t.Fatal(err)
	}
	previous := tenancy.CurrentRouter()
	t.Cleanup(func() { tenancy.SetRouter(previous); tenancy.SetSiloRequiredTables(nil) })
	tenancy.SetRouter(NewRouter(pool, nil, 0).WithQuarantine(tenancy.NewQuarantine()))
	required, err := RequiredSiloTables(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	tenancy.SetSiloRequiredTables(required)

	contextID, clusterID, generation := uuid.NewString(), uuid.NewString(), uuid.NewString()
	var sources [2]store.KubernetesInventorySource
	for lane, tenant := range tenants {
		agent := uuid.NewString()
		err := tenancy.InTenant(tenancy.WithSiloTableLock(tenancy.WithTenant(ctx, tenancy.ID(tenant))), pool, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (store.Agents{}).Reserve(ctx, sc, agent, "inventory", "inventory", "", crypto.AgentSPIFFEID(tenant, agent), nil); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
VALUES ($1,$2,$2,$2,'inventory','default')`, tenant, contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id)
VALUES ($1,$2,$3)`, tenant, agent, contextID); err != nil {
				return err
			}
			var err error
			sources[lane], err = store.CreateKubernetesInventorySourceInScope(ctx, sc, contextID,
				store.KubernetesInventorySourceInput{ClusterID: clusterID, Namespace: "inventory", AgentID: agent})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	insertGeneration := func(schema, tenant, id string) error {
		_, err := pool.Exec(ctx, `INSERT INTO `+schema+`.kubernetes_inventory_generations
 (tenant_id,context_id,source_id,id,sender_serial,manifest,payload_digest,part_count,row_count,body_bytes)
 VALUES ($1,$2,$3,$4,'01',decode('00','hex'),decode(repeat('00',32),'hex'),1,1,1)`, tenant, contextID, id, generation)
		return err
	}
	var cross *pgconn.PgError
	if err := insertGeneration(schemaA, tenants[0], sources[1].ID); !errors.As(err, &cross) || cross.Code != "23503" ||
		cross.ConstraintName != "k8s_inventory_generation_source_fk" {
		t.Fatal("silo catch-up did not restore the tenant-owned source FK", err)
	}
	for lane, tenant := range tenants {
		schema := quoteIdent(SchemaName(tenant))
		if err := insertGeneration(schema, tenant, sources[lane].ID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.kubernetes_inventory_windows
 (tenant_id,context_id,source_id,generation_id,window_index,object_kind,valid_from,valid_until)
 VALUES ($1,$2,$3,$4,0,1,transaction_timestamp()-interval '2 seconds',transaction_timestamp()-interval '1 second')`,
			tenant, contextID, sources[lane].ID, generation); err != nil {
			t.Fatal(err)
		}
	}
	if deleted, err := store.NewKubernetesInventoryPruner(pool)(ctx, tenants[0], time.Now()); err != nil || deleted != 1 {
		t.Fatalf("retention did not mutate exactly one generation in the routed silo: deleted %d, %v", deleted, err)
	}
	for lane, tenant := range tenants {
		schema := quoteIdent(SchemaName(tenant))
		var windows int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.kubernetes_inventory_windows
WHERE tenant_id=$1 AND context_id=$2 AND generation_id=$3`, tenant, contextID, generation).Scan(&windows); err != nil || windows != lane {
			t.Fatalf("retention cascade crossed the silo boundary for lane %d: windows %d, %v", lane, windows, err)
		}
	}
}
