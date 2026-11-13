// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration || isolation

package silo

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func TestBMPPeerSessionSiloChecksKeepAbsenceAndTenantOnCatchup(t *testing.T) {
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
		raw := make([]byte, 49)
		raw[0], raw[5] = 3, 2
		raw[48] = byte(4 + lane)
		binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
		copy(raw[28:32], []byte{192, 0, 2, 7})
		binary.BigEndian.PutUint32(raw[32:36], 64500)
		copy(raw[36:40], []byte{192, 0, 2, 1})
		fact, err := bgp.DecodePhysicalPeerSession(ctx, raw, bgp.PeerMessageBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20})
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(fact)
		if err != nil {
			t.Fatal(err)
		}
		if err := prov.Provision(ctx, tenant, "", tenancy.IsolationSiloed); err != nil {
			t.Fatal(err)
		}
		schema := quoteIdent(SchemaName(tenant))
		exec(`INSERT INTO `+schema+`.entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$2,$2,'same-site','same-vrf')`, tenant, contextID)
		exec(`INSERT INTO `+schema+`.entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','same-router')`, tenant, contextID, routerID)
		exec(`INSERT INTO `+schema+`.entities(tenant_id,context_id,id,kind,label,parent_entity_id,source_agent_id,configured_ref,interface_index)
 VALUES($1,$2,$3,'interface','same-interface',$4,'neutral-agent','192.0.2.1',7)`, tenant, contextID, interfaceID, routerID)
		insert := `INSERT INTO ` + schema + `.entity_evidence(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,source,source_ref,agent_id,source_kind,configured_ref,observed_at,sender_serial,origin_serial)
 VALUES($1,$2,$3,$3,$4,'bmp_peer_id','192.0.2.7/as64500','component','bmp:router:neutral-router:peer-asn:64500','neutral-agent','bmp_peer','neutral-router',$5,'abc','def')`
		exec(insert, tenant, contextID, legacyID, interfaceID, at)
		if lane == 0 {
			exec(`ALTER TABLE ` + schema + `.entity_evidence DROP COLUMN bmp_peer_session CASCADE`)
			for range 2 {
				if err := prov.CatchUpSchema(ctx, tenant); err != nil {
					t.Fatal("peer-session catch-up", err)
				}
			}
		}
		exec(insert, tenant, contextID, evidenceID, interfaceID, at)

		exec(`UPDATE `+schema+`.entity_evidence SET bmp_peer_session=$3::jsonb WHERE tenant_id=$1 AND id=$2`, tenant, evidenceID, body)
		var legacyTime time.Time
		if err := pool.QueryRow(ctx, `SELECT observed_at FROM `+schema+`.entity_evidence WHERE tenant_id=$1 AND id=$2 AND bmp_peer_session IS NULL`, tenant, legacyID).Scan(&legacyTime); err != nil || !legacyTime.Equal(at) {
			t.Fatal("catch-up invented legacy state or changed its clock", err)
		}
		for _, mutation := range []string{
			`bmp_peer_session='{"version":1}'::jsonb`,
			`bmp_peer_session=jsonb_set(bmp_peer_session,'{version}','2')`,
			`bmp_peer_session=jsonb_set(bmp_peer_session,'{peer_asn}','0')`,
			`bmp_peer_session=jsonb_set(bmp_peer_session,'{peer_asn}','4294967296')`,
			`bmp_peer_session=jsonb_set(bmp_peer_session,'{down_reason}','7')`,
			`bmp_peer_session=jsonb_set(bmp_peer_session,'{frame_digest}','"invalid"')`,
			`bmp_peer_session=jsonb_set(bmp_peer_session,'{claimed_agent}','"other"')`,
			`source_kind='flow_exporter'`, `source_ref='snmp:configured-target'`, `alias_kind='address'`, `origin_serial=NULL`,
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
				tag, writeErr := tx.Exec(ctx, `UPDATE `+schema+`.entity_evidence SET bmp_peer_session=NULL WHERE id=$1`, evidenceID)
				err, changed = writeErr, tag.RowsAffected()
			}
			_ = tx.Rollback(ctx)
			want := 0
			if caller == tenant {
				want = 2
			}
			if err != nil || count != want || changed != 0 {
				t.Fatal("qualified peer-session access crossed silo tenant RLS", count, want, changed, err)
			}
		}
	}
	migration, err := migrations.FS.ReadFile("0206_bmp_peer_session.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(migration)); err != nil {
		t.Fatal("state migration replay with retained pooled/silo rows", err)
	}
	t.Log("real-integration: paired private schema provision/catch-up/replay, absent legacy state, strict original BMP document checks and qualified app-role RLS; source frames are modeled, actual mTLS retention is proved separately")
}
