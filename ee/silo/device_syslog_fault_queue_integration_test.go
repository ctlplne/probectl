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
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestSiloSyslogFaultQueueKeepsLocalOriginalsAfterCatchUp(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := t.Context()
	prov := NewProvisioner(pool, CHPlanes{}, nil, 0, nil)
	ids := [2]string{
		mkTenant(t, pool, fmt.Sprintf("syslog-a-%d", time.Now().UnixNano()), "siloed", ""),
		mkTenant(t, pool, fmt.Sprintf("syslog-b-%d", time.Now().UnixNano()), "siloed", ""),
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
	const eventID = "18181818-1818-4818-8818-181818181818"
	for lane, id := range ids {
		if err := prov.Provision(ctx, id, "", tenancy.IsolationSiloed); err != nil {
			t.Fatal(err)
		}
		schema := quoteIdent(SchemaName(id))
		raw, queue := schema+".device_syslog", schema+".device_syslog_fault_queue"
		if lane == 0 {
			if _, err := pool.Exec(ctx, "DROP TABLE "+queue); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, "DROP INDEX IF EXISTS "+schema+".device_syslog_tenant_id_id_idx"); err != nil {
				t.Fatal(err)
			}
		}
		if err := prov.CatchUpSchema(ctx, id); err != nil {
			t.Fatal("syslog fault queue did not upgrade the physical silo", err)
		}
		var parent string
		err := pool.QueryRow(ctx, `SELECT confrelid::regclass::text FROM pg_constraint
WHERE conrelid=$1::regclass AND conname='device_syslog_fault_event_fk'`, queue).Scan(&parent)
		if err != nil || parent != SchemaName(id)+".device_syslog" {
			t.Fatal("the queue did not reference the owning silo's raw syslog table", parent, err)
		}
		if _, err := pool.Exec(ctx, "INSERT INTO "+raw+" (tenant_id,id,device,message) VALUES($1,$2,'edge','frame')", id, eventID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, "INSERT INTO "+queue+" (tenant_id,event_id,target,subject,observed_at) VALUES($1,$2,$3,'port',now())",
			id, eventID, "device-syslog:"+strings.Repeat("a", 64)); err != nil {
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
		for other, reader := range []string{id, ids[1-lane]} {
			if _, err := tx.Exec(ctx, `SELECT set_config('probectl.tenant_id',$1,true)`, reader); err != nil {
				t.Fatal(err)
			}
			var visible int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+queue).Scan(&visible); err != nil || visible != 1-other {
				t.Fatal("physical fault receipt scope did not match tenant authority", visible, err)
			}
		}
		_, err = tx.Exec(ctx, "INSERT INTO "+queue+" (tenant_id,event_id,target,subject,observed_at) VALUES($1,$2,$3,'port',now())",
			ids[1-lane], eventID, "device-syslog:"+strings.Repeat("a", 64))
		var denied *pgconn.PgError
		if !errors.As(err, &denied) || denied.Code != "42501" {
			t.Fatal("the sibling scope was not refused at the physical write boundary", err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, "DELETE FROM "+raw+" WHERE tenant_id=$1 AND id=$2", id, eventID); err != nil {
			t.Fatal(err)
		}
		var retained int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+queue).Scan(&retained); err != nil || retained != 0 {
			t.Fatal("a deleted original retained its queue receipt", retained, err)
		}
	}
}
