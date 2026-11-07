// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/migrations"
)

// Actual schema/application-role RLS and cascades. Direct modeled snapshot
// completion below checks storage shape; it is not a publication/collector proof.
func TestPublicRoutingSnapshotSchemaKeepsEmptyRIBTenantSourceAndBoundViewIdentity(t *testing.T) {
	f := newRoleInputsFixture(t)
	ctx := t.Context()
	definition, err := migrations.FS.ReadFile("0185_bgp_public_snapshots.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, string(definition)); err != nil {
		t.Fatal("public snapshot migration is not idempotent", err)
	}
	t.Cleanup(func() {
		// Restore this owned test database's guard after the schema omission
		// control; no concurrent catalog proof can run under the fixture lease.
		if _, err := f.pool.Exec(context.Background(), `ALTER TABLE bgp_public_snapshots ENABLE ROW LEVEL SECURITY; ALTER TABLE bgp_public_snapshots FORCE ROW LEVEL SECURITY`); err != nil {
			t.Error(err)
		}
	})
	const ref = "ris/mrt_table_dump_v2/rrc00"
	snapshotID, viewID, generation := uuid.NewString(), uuid.NewString(), uuid.NewString()
	observed := time.Now().UTC().Truncate(time.Microsecond).Add(123 * time.Nanosecond)
	insert := `INSERT INTO bgp_public_snapshots
 (tenant_id,context_id,id,collector_agent_id,source_ref,sender_serial,manifest_digest,expected_views,state,
 observed_at,observed_unix_nanos,last_message_unix_nanos,valid_until,charged_bytes)
 VALUES($1,$2,$3,'role-listener',$4,$5,decode(repeat('01',32),'hex'),0,'staging',$6,$7,$7,$8,512)`
	view := `INSERT INTO bgp_routing_views
 (tenant_id,context_id,id,generation,source_kind,collector_agent_id,source_ref,sender_serial,view_kind,
 peer_key,peer_identity,afi,safi,filtered,state,observed_at,valid_until,completed_at,public_snapshot_id)
 VALUES($1,$2,$3,$4,'public_bgp','role-listener',$5,$6,'public_bgp',decode(repeat('02',32),'hex'),'{}',2,1,false,$7,$8,$9,clock_timestamp(),$10)`
	run := func(tenant string, fn func(context.Context, tenancy.Scope) error) error {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		return tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), tenant, entity.ErrScopeMismatch, func(ctx context.Context) error {
			return tenancy.InTenant(ctx, f.pool, fn)
		})
	}
	for _, tenant := range f.tenants {
		if err := run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id) VALUES($1,'role-listener','public_bgp',$2,$3)`, tenant, ref, f.contextID); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, insert, tenant, f.contextID, snapshotID, ref, f.serials[tenant+"role-listener"], observed, observed.UnixNano(), observed.Add(time.Hour))
			return err
		}); err != nil {
			t.Fatal("complete empty public source header was refused", err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var count, views int
			var clock int64
			if err := sc.Q.QueryRow(ctx, `SELECT count(*),min(expected_views),min(observed_unix_nanos) FROM bgp_public_snapshots`).Scan(&count, &views, &clock); err != nil {
				return err
			}
			used, err := routingStateBytesInScope(ctx, sc)
			if err != nil {
				return err
			}
			if count != 1 || views != 0 || clock != observed.UnixNano() || used != 512 {
				t.Fatal("empty public snapshot leaked tenants, lost exact time or escaped tenant admission", count, views, clock, used)
			}
			return nil
		})
	}
	assertCode := func(want string, fn func(context.Context, tenancy.Scope) error) {
		t.Helper()
		var pg *pgconn.PgError
		if err := run(f.tenants[0], fn); !errors.As(err, &pg) || pg.Code != want {
			t.Fatal("public snapshot storage accepted a foreign or malformed binding", want, err)
		}
	}
	assertCode("42501", func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, insert, f.tenants[1], f.contextID, uuid.NewString(), ref, f.serials[f.tenants[1]+"role-listener"], observed, observed.UnixNano(), observed.Add(time.Hour))
		return err
	})
	assertCode("23503", func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, insert, f.tenants[0], f.contextID, uuid.NewString(), "unassigned", f.serials[f.tenants[0]+"role-listener"], observed, observed.UnixNano(), observed.Add(time.Hour))
		return err
	})
	assertCode("23514", func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, view, f.tenants[0], f.contextID, viewID, generation, ref, f.serials[f.tenants[0]+"role-listener"], "current", observed, observed.Add(time.Hour), nil)
		return err
	})
	assertCode("23503", func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, view, f.tenants[0], f.contextID, viewID, generation, ref, f.serials[f.tenants[1]+"role-listener"], "staging", observed, observed.Add(time.Hour), snapshotID)
		return err
	})
	assertCode("23514", func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE bgp_public_snapshots SET state='current' WHERE tenant_id=$1`, f.tenants[0])
		return err
	})
	assertCode("23514", func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE bgp_public_snapshots SET observed_unix_nanos=observed_unix_nanos+1000,last_message_unix_nanos=last_message_unix_nanos+1000 WHERE tenant_id=$1`, f.tenants[0])
		return err
	})
	for _, tenant := range f.tenants {
		if err := run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, view, tenant, f.contextID, viewID, generation, ref, f.serials[tenant+"role-listener"], "staging", observed, observed.Add(time.Hour), snapshotID); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO bgp_routing_entries(tenant_id,context_id,view_id,generation,afi,safi,prefix,has_path_id,path_id,segments,attributes,next_hops,sequence,observed_at,charged_bytes)
 VALUES($1,$2,$3,$4,2,1,'2001:db8::/32',true,4294967295,'[]','{}',ARRAY['2001:db8::1'::inet],1,$5,512)`, tenant, f.contextID, viewID, generation, observed)
			return err
		}); err != nil {
			t.Fatal("matching public snapshot/view/route ownership was refused", err)
		}
	}
	if err := run(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_source_contexts WHERE tenant_id=$1 AND source_kind='public_bgp'`, f.tenants[0])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var headers, views, entries int
			if err := sc.Q.QueryRow(ctx, `SELECT (SELECT count(*) FROM bgp_public_snapshots),(SELECT count(*) FROM bgp_routing_views),(SELECT count(*) FROM bgp_routing_entries)`).Scan(&headers, &views, &entries); err != nil {
				return err
			}
			if headers != lane || views != lane || entries != lane {
				t.Fatal("public source erasure retained its cohort or deleted a sibling", headers, views, entries, lane)
			}
			return nil
		})
	}
}
