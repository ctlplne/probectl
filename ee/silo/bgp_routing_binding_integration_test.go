// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package silo

import (
	"context"
	"encoding/json"
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
)

// Real provisioned/caught-up Postgres and application-role storage isolation.
// Minimal view metadata is modeled; no router, credential or live RIB claim.
func TestBGPRoutingBindingStorageKeepsManagedHybridAndOldSchemaBoundaries(t *testing.T) {
	for _, model := range []tenancy.IsolationModel{tenancy.IsolationSiloed, tenancy.IsolationHybrid} {
		t.Run(string(model), func(t *testing.T) {
			pool := itPool(t)
			t.Cleanup(pool.Close)
			testsupport.LockPostgresPublicCatalog(t, pool)
			ctx := t.Context()
			prov := NewProvisioner(pool, CHPlanes{}, nil, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
			stamp := fmt.Sprint(time.Now().UnixNano())
			tenants := []string{mkTenant(t, pool, "routing-bind-a-"+stamp, string(model), ""), mkTenant(t, pool, "routing-bind-b-"+stamp, string(model), "")}
			t.Cleanup(func() {
				for _, tenant := range tenants {
					if err := prov.Teardown(context.Background(), tenant, "", model); err != nil {
						t.Error(err)
					}
				}
				if _, err := pool.Exec(context.Background(), `DELETE FROM public.tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
					t.Error(err)
				}
			})
			for _, tenant := range tenants {
				if err := prov.Provision(ctx, tenant, "", model); err != nil {
					t.Fatal(err)
				}
			}
			if model == tenancy.IsolationSiloed {
				// Restore only this owned empty table's old column/constraint
				// shape. Catch-up must recover the generated storage expression.
				child := quoteIdent(SchemaName(tenants[0])) + `."bgp_routing_views"`
				sourceChild := quoteIdent(SchemaName(tenants[0])) + `."entity_source_contexts"`
				for _, sql := range []string{
					"ALTER TABLE " + sourceChild + " DROP CONSTRAINT IF EXISTS fx5_public_source_shape",
					"ALTER TABLE " + sourceChild + " DROP CONSTRAINT entity_source_contexts_source_kind_check",
					"ALTER TABLE " + sourceChild + " ADD CONSTRAINT entity_source_contexts_source_kind_check CHECK (source_kind IN ('device_target','flow_exporter','path_agent','bmp_peer','agent_site'))",
					"ALTER TABLE " + child + " DROP CONSTRAINT IF EXISTS fx5_route_view_collector_context_fk",
					"ALTER TABLE " + child + " DROP CONSTRAINT fx5_route_view_routing_selection_check",
					"ALTER TABLE " + child + " DROP CONSTRAINT fx5_route_view_kind_check",
					"ALTER TABLE " + child + " DROP COLUMN collector_context_id",
					"ALTER TABLE " + child + " DROP COLUMN routing_selection",
					"ALTER TABLE " + child + " ADD CONSTRAINT fx5_route_view_agent_context_fk FOREIGN KEY (tenant_id,collector_agent_id,context_id) REFERENCES " + quoteIdent(SchemaName(tenants[0])) + `."entity_agent_contexts" (tenant_id,agent_id,context_id) ON DELETE CASCADE`,
					"ALTER TABLE " + child + " ADD CONSTRAINT bgp_routing_views_view_kind_check CHECK (view_kind IN ('loc_rib','public_bgp','adj_rib_in_pre_policy','adj_rib_in_post_policy','adj_rib_out_pre_policy','adj_rib_out_post_policy'))",
				} {
					if _, err := pool.Exec(ctx, sql); err != nil {
						t.Fatal("owned old routing schema setup failed", err)
					}
				}
				if err := prov.CatchUpSchema(ctx, tenants[0]); err != nil {
					t.Fatal(err)
				}
			}
			previous := tenancy.CurrentRouter()
			t.Cleanup(func() { tenancy.SetRouter(previous); tenancy.SetSiloRequiredTables(nil) })
			router := NewRouter(pool, nil, 0).WithQuarantine(tenancy.NewQuarantine())
			tenancy.SetRouter(router)
			required, err := RequiredSiloTables(ctx, pool)
			if err != nil {
				t.Fatal(err)
			}
			tenancy.SetSiloRequiredTables(required)
			run := func(tenant string, fn func(context.Context, tenancy.Scope) error) error {
				return tenancy.InTenant(tenancy.WithSiloTableLock(tenancy.WithTenant(ctx, tenancy.ID(tenant))), pool, fn)
			}
			baseContext, targetContext, baseRouter, targetRouter := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
			viewID, generation, foreignBase := uuid.NewString(), uuid.NewString(), uuid.NewString()
			for lane, tenant := range tenants {
				collectorContext := baseContext
				if lane == 1 {
					collectorContext = foreignBase
				}
				if err := run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
					var generated bool
					if err := sc.Q.QueryRow(ctx, `SELECT attgenerated='s' FROM pg_attribute WHERE attrelid='bgp_routing_views'::regclass AND attname='collector_context_id' AND NOT attisdropped`).Scan(&generated); err != nil {
						return err
					}
					if !generated {
						t.Fatal("silo catch-up lost routing collector computation")
					}
					if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
 VALUES($1,$2,$2,$2,'base','collector'),($1,$3,$3,$3,'target','routing')`, tenant, collectorContext, targetContext); err != nil {
						return err
					}
					if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','base'),($1,$4,$5,'device','target')`, tenant, collectorContext, baseRouter, targetContext, targetRouter); err != nil {
						return err
					}
					if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES($1,'routing-collector',$2)`, tenant, collectorContext); err != nil {
						return err
					}
					if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id) VALUES($1,'routing-collector','bmp_peer','routing-origin',$2,$3)`, tenant, collectorContext, baseRouter); err != nil {
						return err
					}
					if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id) VALUES($1,'routing-collector','public_bgp','ris/mrt_table_dump_v2/rrc00',$2)`, tenant, collectorContext); err != nil {
						t.Fatal("managed public source assignment was refused after schema catch-up", err)
					}
					body, err := json.Marshal(map[string]any{"base_context_id": collectorContext, "base_router_id": baseRouter,
						"context_id": targetContext, "router_id": targetRouter, "epoch": uuid.NewString(), "binding_id": uuid.NewString(),
						"assigned_at": time.Now().UTC(), "families": []int{1, 2}, "binding": map[string]any{}})
					if err != nil {
						return err
					}
					_, err = sc.Q.Exec(ctx, `INSERT INTO bgp_routing_views
 (tenant_id,context_id,id,generation,source_kind,router_id,collector_agent_id,source_ref,binding_kind,sender_serial,origin_serial,
 view_kind,peer_key,peer_identity,afi,safi,filtered,state,observed_at,valid_until,routing_selection)
 VALUES($1,$2,$3,$4,'router_bmp',$5,'routing-collector','routing-origin','bmp_peer','modeled-sender','modeled-origin',
 'operator_loc_rib',decode(repeat('01',32),'hex'),'{}',1,1,false,'staging',clock_timestamp(),clock_timestamp()+interval '1 hour',$6::jsonb)`, tenant, targetContext, viewID, generation, targetRouter, string(body))
					return err
				}); err != nil {
					t.Fatal("owned routing target was not stored in its managed state plane", err)
				}
			}
			for lane, tenant := range tenants {
				collectorContext := baseContext
				if lane == 1 {
					collectorContext = foreignBase
				}
				if err := run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
					var own, foreign, legacy int
					var base, target string
					if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views`).Scan(&own); err != nil {
						return err
					}
					if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views WHERE tenant_id=$1`, tenants[1-lane]).Scan(&foreign); err != nil {
						return err
					}
					if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views WHERE view_kind='loc_rib'`).Scan(&legacy); err != nil {
						return err
					}
					if err := sc.Q.QueryRow(ctx, `SELECT collector_context_id::text,context_id::text FROM bgp_routing_views WHERE id=$1`, viewID).Scan(&base, &target); err != nil {
						return err
					}
					if own != 1 || foreign != 0 || legacy != 0 || base != collectorContext || target != targetContext {
						t.Fatal("managed routing target lost base context, tenant RLS or old-reader exclusion", own, foreign, legacy, base, target)
					}
					var public, anchors int
					if err := sc.Q.QueryRow(ctx, `SELECT count(*),count(anchor_entity_id) FROM entity_source_contexts WHERE source_kind='public_bgp'`).Scan(&public, &anchors); err != nil {
						return err
					}
					if public != 1 || anchors != 0 {
						t.Fatal("managed public source escaped tenant storage or gained router authority", public, anchors)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			err = run(tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET routing_selection=jsonb_set(routing_selection,'{base_context_id}',to_jsonb($2::text)) WHERE tenant_id=$1`, tenants[0], foreignBase)
				return err
			})
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "23503" {
				t.Fatal("routing target borrowed an unassigned foreign collector context", err)
			}
			err = run(tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET anchor_entity_id=$2 WHERE tenant_id=$1 AND source_kind='public_bgp'`, tenants[0], baseRouter)
				return err
			})
			if !errors.As(err, &pg) || pg.Code != "23514" {
				t.Fatal("managed public source accepted an invented router anchor", err)
			}
		})
	}
}
