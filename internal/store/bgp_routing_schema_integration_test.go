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
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func TestBGPRoutingSchemaKeepsTenantFamilyPathIdentityAndPublicationShape(t *testing.T) {
	ctx := t.Context()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	var tenants []string
	for _, lane := range []string{"a", "b"} {
		tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("routing-schema-%s-%d", lane, time.Now().UnixNano()), lane)
		if err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, tenant.ID)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	contextID, routerID, viewID, generation := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	fence := tenancy.NewPostgresWriterFence(pool)
	run := func(tenant string, fn func(context.Context, tenancy.Scope) error) error {
		return tenancy.FencedTenantWrite(tenancy.WithTenant(ctx, tenancy.ID(tenant)), fence, tenant, entity.ErrScopeMismatch,
			func(ctx context.Context) error { return tenancy.InTenant(ctx, pool, fn) })
	}
	viewSQL := `INSERT INTO bgp_routing_views
 (tenant_id,context_id,id,generation,source_kind,router_id,collector_agent_id,source_ref,binding_kind,
 sender_serial,origin_serial,view_kind,peer_key,peer_identity,afi,safi,filtered,state,observed_at,valid_until)
 VALUES($1,$2,$3,$4,'router_bmp',$5,'collector','origin',$6,
 'modeled-sender','modeled-origin','loc_rib',decode(repeat('01',32),'hex'),'{}'::jsonb,1,1,false,'staging',now(),now()+interval '1 hour')`
	entrySQL := `INSERT INTO bgp_routing_entries
 (tenant_id,context_id,view_id,generation,afi,safi,prefix,has_path_id,path_id,segments,attributes,next_hops,sequence,observed_at,charged_bytes)
 VALUES($1,$2,$3,$4,$5,1,$6::cidr,$7,$8,'[]'::jsonb,'{}'::jsonb,ARRAY['192.0.2.1'::inet],1,now(),512)`
	for _, tenant := range tenants {
		if err := run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'same-site','same-vrf')`, tenant, contextID, uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','router')`, tenant, contextID, routerID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES($1,'collector',$2)`, tenant, contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id) VALUES($1,'collector','bmp_peer','origin',$2,$3)`, tenant, contextID, routerID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, viewSQL, tenant, contextID, viewID, generation, routerID, "bmp_peer"); err != nil {
				return err
			}
			for _, key := range []struct {
				has bool
				id  int64
			}{{false, 0}, {true, 0}, {true, 4294967295}} {
				if _, err := sc.Q.Exec(ctx, entrySQL, tenant, contextID, viewID, generation, 1, "10.0.0.0/8", key.has, key.id); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal("owned routing schema refused full path identity", err)
		}
	}
	for lane, tenant := range tenants {
		if err := run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var own, foreign, paths int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_entries`).Scan(&own); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_entries WHERE tenant_id=$1`, tenants[1-lane]).Scan(&foreign); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views`).Scan(&paths); err != nil {
				return err
			}
			if own != 3 || foreign != 0 || paths != 1 {
				t.Fatal("routing storage leaked a tenant or collapsed path-id presence", own, foreign, paths)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	assertCode := func(want string, fn func(context.Context, tenancy.Scope) error) {
		t.Helper()
		err := run(tenants[0], fn)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != want {
			t.Fatal("routing storage did not reject forbidden/incomplete state", want, err)
		}
	}
	assertCode("42501", func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, entrySQL, tenants[1], contextID, viewID, generation, 1, "10.1.0.0/16", false, 0)
		return err
	})
	assertCode("23514", func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, viewSQL, tenants[0], contextID, viewID, uuid.NewString(), routerID, nil)
		return err
	})
	for _, change := range []string{
		`UPDATE bgp_routing_views SET state='current'`,
		`UPDATE bgp_routing_views SET last_sequence=1,next_sequence=2,last_digest=NULL`,
	} {
		assertCode("23514", func(ctx context.Context, sc tenancy.Scope) error { _, err := sc.Q.Exec(ctx, change); return err })
	}
	assertCode("23514", func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, entrySQL, tenants[0], contextID, viewID, generation, 1, "2001:db8::/32", true, 1)
		return err
	})
	assertCode("23514", func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, entrySQL, tenants[0], contextID, viewID, generation, 1, "10.3.0.0/16", false, 1)
		return err
	})
	foreignGeneration := uuid.NewString()
	if err := run(tenants[1], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, viewSQL, tenants[1], contextID, viewID, foreignGeneration, routerID, "bmp_peer")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	assertCode("23503", func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, entrySQL, tenants[0], contextID, viewID, foreignGeneration, 1, "10.1.0.0/16", false, 0)
		return err
	})
	ddl, err := migrations.FS.ReadFile("0176_bgp_routing_generations.sql")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := pool.Exec(ctx, string(ddl)); err != nil {
			t.Fatal("routing migration was not idempotent with retained tenant rows", err)
		}
	}
	providerErr := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		var count int
		return q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_entries`).Scan(&count)
	})
	var providerPG *pgconn.PgError
	if !errors.As(providerErr, &providerPG) || providerPG.Code != "42501" {
		t.Fatal("provider acquired implicit routing telemetry access or denial was unexecuted", providerErr)
	}
}
