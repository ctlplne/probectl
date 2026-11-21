// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

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

func TestSiloConfigPolicyKeepsImmutableRevisionsAndLocalForeignKeys(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := t.Context()
	prov := NewProvisioner(pool, CHPlanes{}, nil, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ids := [2]string{
		mkTenant(t, pool, fmt.Sprintf("policy-a-%d", time.Now().UnixNano()), "siloed", ""),
		mkTenant(t, pool, fmt.Sprintf("policy-b-%d", time.Now().UnixNano()), "siloed", ""),
	}
	t.Cleanup(func() {
		for _, id := range ids {
			if err := prov.Teardown(context.Background(), id, "", tenancy.IsolationSiloed); err != nil {
				t.Error(err)
			}
		}
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, ids[:]); err != nil {
			t.Error(err)
		}
	})
	const contextID = "18181818-1818-4818-8818-181818181818"
	const deviceID = "19191919-1919-4919-8919-191919191919"
	for lane, id := range ids {
		if err := prov.Provision(ctx, id, "", tenancy.IsolationSiloed); err != nil {
			t.Fatal(err)
		}
		schema := quoteIdent(SchemaName(id))
		if lane == 0 {
			if _, err := pool.Exec(ctx, "ALTER TABLE "+schema+".device_configs DROP COLUMN config_policy_evaluation"); err != nil {
				t.Fatal(err)
			}
		}
		if err := prov.CatchUpSchema(ctx, id); err != nil {
			t.Fatal("configuration policy storage could not upgrade the silo", err)
		}
		table := schema + ".device_config_policy_revisions"
		var parent string
		var mutable, evaluationColumn, evaluationShape bool
		err := pool.QueryRow(ctx, `SELECT
			(SELECT confrelid::regclass::text FROM pg_constraint WHERE conrelid=$1::regclass AND conname='device_config_policy_device_fk'),
			has_table_privilege('probectl_app',$1,'UPDATE'),
			EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=$2::regclass AND attname='config_policy_evaluation' AND NOT attisdropped),
			EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=$2::regclass AND conname='device_configs_policy_evaluation_shape')`,
			table, schema+".device_configs").Scan(&parent, &mutable, &evaluationColumn, &evaluationShape)
		if err != nil || parent != SchemaName(id)+".entities" || mutable || !evaluationColumn || !evaluationShape {
			t.Fatal("configuration policy lost its physical foreign key, immutability or archive evaluation boundary",
				parent, mutable, evaluationColumn, evaluationShape, err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
			VALUES($1,$2,$2,$2,'same-site','same-vrf')`, id, contextID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.entities(tenant_id,context_id,id,kind,label)
			VALUES($1,$2,$3,'device','same-device')`, id, contextID, deviceID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, "INSERT INTO "+table+` (tenant_id,context_id,device_entity_id,version,rules) VALUES($1,$2,$3,1,'[]')`,
			id, contextID, deviceID); err != nil {
			t.Fatal(err)
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
		var visible int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&visible); err != nil || visible != 0 {
			t.Fatal("a sibling tenant could read immutable policy revisions from the physical device silo", visible, err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
}
