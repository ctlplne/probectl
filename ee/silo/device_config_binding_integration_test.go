// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration || isolation

package silo

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestConfigArchiveSiloUpgradePreservesLegacyAndExactLocalReferences(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := t.Context()
	prov := NewProvisioner(pool, CHPlanes{}, nil, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ids := []string{mkTenant(t, pool, fmt.Sprintf("config-a-%d", time.Now().UnixNano()), "siloed", ""), mkTenant(t, pool, fmt.Sprintf("config-b-%d", time.Now().UnixNano()), "siloed", "")}
	t.Cleanup(func() {
		for _, id := range ids {
			if err := prov.Teardown(context.Background(), id, "", tenancy.IsolationSiloed); err != nil {
				t.Error(err)
			}
		}
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, ids); err != nil {
			t.Error(err)
		}
	})
	const contextID = "18181818-1818-4818-8818-181818181818"
	const deviceID = "19191919-1919-4919-8919-191919191919"
	for lane, id := range ids {
		if err := prov.Provision(ctx, id, "", tenancy.IsolationSiloed); err != nil {
			t.Fatal("fresh archive silo provision", err)
		}
		schema := quoteIdent(SchemaName(id))
		if lane == 0 {
			// Restore an old archive table with retained rows. Catch-up must add
			// columns/checks/indexes without losing the original name stream.
			for _, sql := range []string{
				`DROP TABLE ` + schema + `.device_configs`,
				`CREATE TABLE ` + schema + `.device_configs (id uuid PRIMARY KEY DEFAULT gen_random_uuid(),tenant_id uuid NOT NULL,device text NOT NULL,source text NOT NULL DEFAULT '',version integer NOT NULL,content text NOT NULL DEFAULT '',content_hash text NOT NULL,previous_hash text NOT NULL DEFAULT '',drifted boolean NOT NULL DEFAULT false,observed_at timestamptz NOT NULL DEFAULT now(),archived_at timestamptz NOT NULL DEFAULT now(),UNIQUE(tenant_id,device,version))`,
			} {
				if _, err := pool.Exec(ctx, sql); err != nil {
					t.Fatal(err)
				}
			}
		}
		var originalID string
		if err := pool.QueryRow(ctx, `INSERT INTO `+schema+`.device_configs(tenant_id,device,version,content,content_hash) VALUES($1,'same-name',1,$2,$2) RETURNING id::text`, id, "original-"+id).Scan(&originalID); err != nil {
			t.Fatal(err)
		}
		if lane == 0 {
			if err := prov.Provision(ctx, id, "", tenancy.IsolationSiloed); err != nil {
				t.Fatal("restored old archive provision", err)
			}
		}
		for range 2 {
			if err := prov.CatchUpSchema(ctx, id); err != nil {
				t.Fatal("online archive catch-up", err)
			}
		}
		if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$2,$2,'same-site','same-vrf')`, id, contextID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','same-device')`, id, contextID, deviceID); err != nil {
			t.Fatal(err)
		}
		for _, source := range []string{"first-source", "second-source"} {
			if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.device_configs(tenant_id,device,version,content,content_hash,entity_context_id,device_entity_id,binding_agent_id,binding_source_ref,binding_source_assigned_at,binding_agent_assigned_at,bound_at)
 VALUES($1,'same-name',1,'bound','bound',$2,$3,'same-agent',$4,now()-interval '1 hour',now()-interval '1 hour',now())`, id, contextID, deviceID, source); err != nil {
				t.Fatal("independent bound stream still collided with a display name", err)
			}
		}
		var parent string
		if err := pool.QueryRow(ctx, `SELECT confrelid::regclass::text FROM pg_constraint WHERE conrelid=$1::regclass AND conname='device_configs_binding_device_fk' AND convalidated`, schema+`.device_configs`).Scan(&parent); err != nil || parent != SchemaName(id)+".entities" {
			t.Fatal("archive FK crossed the physical silo", parent, err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE probectl_app`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('probectl.tenant_id',$1,true)`, ids[1-lane]); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.device_configs`).Scan(&count); err != nil || count != 0 {
			t.Fatal("sibling tenant read a physical archive silo", count, err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.device_configs WHERE tenant_id=$1 AND content=$2 AND id=$3 AND entity_context_id IS NULL`, id, "original-"+id, originalID).Scan(&count); err != nil || count != 1 {
			t.Fatal("catch-up did not preserve the original archive", count, err)
		}
	}
}
