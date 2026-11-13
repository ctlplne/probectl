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

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func TestSNMPInterfaceStateSiloChecksKeepAbsenceAndTenantOnCatchup(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := t.Context()
	tenants := []string{
		mkTenant(t, pool, fmt.Sprintf("state-a-%d", time.Now().UnixNano()), "siloed", ""),
		mkTenant(t, pool, fmt.Sprintf("state-b-%d", time.Now().UnixNano()), "siloed", ""),
	}
	prov := NewProvisioner(pool, CHPlanes{}, nil, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() {
		for _, tenant := range tenants {
			if err := prov.Teardown(context.Background(), tenant, "", tenancy.IsolationSiloed); err != nil {
				t.Error(err)
			}
		}
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	contextID, routerID, interfaceID, legacyID, evidenceID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	at := time.Now().UTC().Truncate(time.Microsecond)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	for lane, tenant := range tenants {
		if err := prov.Provision(ctx, tenant, "", tenancy.IsolationSiloed); err != nil {
			t.Fatal(err)
		}
		schema := quoteIdent(SchemaName(tenant))
		exec(`INSERT INTO `+schema+`.entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$2,$2,'same-site','same-vrf')`, tenant, contextID)
		exec(`INSERT INTO `+schema+`.entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','same-router')`, tenant, contextID, routerID)
		exec(`INSERT INTO `+schema+`.entities(tenant_id,context_id,id,kind,label,parent_entity_id,source_agent_id,configured_ref,interface_index)
 VALUES($1,$2,$3,'interface','same-interface',$4,'neutral-agent','192.0.2.1',7)`, tenant, contextID, interfaceID, routerID)
		insert := `INSERT INTO ` + schema + `.entity_evidence(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,source,source_ref,agent_id,source_kind,configured_ref,observed_at,sender_serial)
 VALUES($1,$2,$3,$3,$4,'snmp_interface_id','7','component','snmp:ifIndex:7','neutral-agent','device_target','192.0.2.1',$5,'abc')`
		exec(insert, tenant, contextID, legacyID, interfaceID, at)
		if lane == 0 {
			exec(`ALTER TABLE ` + schema + `.entity_evidence DROP COLUMN snmp_interface_state CASCADE`)
			for range 2 {
				if err := prov.CatchUpSchema(ctx, tenant); err != nil {
					t.Fatal("interface-state catch-up", err)
				}
			}
		}
		exec(insert, tenant, contextID, evidenceID, interfaceID, at)
		body := fmt.Sprintf(`{"version":1,"oper_status":%d,"admin_status":1}`, lane+1)
		exec(`UPDATE `+schema+`.entity_evidence SET snmp_interface_state=$3::jsonb WHERE tenant_id=$1 AND id=$2`, tenant, evidenceID, body)
		var legacyTime time.Time
		if err := pool.QueryRow(ctx, `SELECT observed_at FROM `+schema+`.entity_evidence WHERE tenant_id=$1 AND id=$2 AND snmp_interface_state IS NULL`, tenant, legacyID).Scan(&legacyTime); err != nil || !legacyTime.Equal(at) {
			t.Fatal("catch-up invented legacy state or changed its clock", err)
		}
		for _, mutation := range []string{
			`snmp_interface_state='{"version":1}'::jsonb`,
			`snmp_interface_state='{"version":2,"oper_status":1}'::jsonb`,
			`snmp_interface_state='{"version":1,"oper_status":0}'::jsonb`,
			`snmp_interface_state='{"version":1,"oper_status":8}'::jsonb`,
			`snmp_interface_state='{"version":1,"admin_status":4}'::jsonb`,
			`snmp_interface_state='{"version":1,"oper_status":"1"}'::jsonb`,
			`snmp_interface_state='{"version":1,"oper_status":1,"claimed_agent":"other"}'::jsonb`,
			`source_kind='flow_exporter'`, `source_ref='snmp:configured-target'`, `alias_kind='address'`,
		} {
			_, err := pool.Exec(ctx, `UPDATE `+schema+`.entity_evidence SET `+mutation+` WHERE tenant_id=$1 AND id=$2`, tenant, evidenceID)
			var check *pgconn.PgError
			if !errors.As(err, &check) || check.Code != "23514" {
				t.Fatal("silo admitted an invalid state or wrong observation family", mutation, err)
			}
		}
		for _, caller := range tenants {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `SET LOCAL ROLE probectl_app`); err == nil {
				_, err = tx.Exec(ctx, `SELECT set_config('probectl.tenant_id',$1,true)`, caller)
			}
			var count int
			if err == nil {
				err = tx.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.entity_evidence`).Scan(&count)
			}
			var changed int64
			if err == nil && caller != tenant {
				tag, writeErr := tx.Exec(ctx, `UPDATE `+schema+`.entity_evidence SET snmp_interface_state=NULL WHERE id=$1`, evidenceID)
				err, changed = writeErr, tag.RowsAffected()
			}
			_ = tx.Rollback(ctx)
			want := 0
			if caller == tenant {
				want = 2
			}
			if err != nil || count != want || changed != 0 {
				t.Fatal("qualified interface-state access crossed silo tenant RLS", count, want, changed, err)
			}
		}
	}
	migration, err := migrations.FS.ReadFile("0205_snmp_interface_state.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(migration)); err != nil {
		t.Fatal("state migration replay with retained pooled/silo rows", err)
	}
	t.Log("real-integration: paired private schema provision/catch-up/replay, absent legacy state, strict IF-MIB document checks and qualified app-role RLS; input state is modeled, actual mTLS retention is proved separately")
}
