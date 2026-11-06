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
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Real provisioned Postgres state and application-role current-evidence reads.
// Source identities and observations are modeled through the actual writers;
// this does not replace the mTLS sender or physical router proof.
func TestInterfaceRoleInputsFollowManagedAndHybridCurrentAuthority(t *testing.T) {
	for _, model := range []tenancy.IsolationModel{tenancy.IsolationSiloed, tenancy.IsolationHybrid} {
		t.Run(string(model), func(t *testing.T) {
			pool := itPool(t)
			t.Cleanup(pool.Close)
			testsupport.LockPostgresPublicCatalog(t, pool)
			ctx := t.Context()
			prov := NewProvisioner(pool, CHPlanes{}, nil, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
			stamp := fmt.Sprint(time.Now().UnixNano())
			tenants := []string{mkTenant(t, pool, "role-source-a-"+stamp, string(model), ""), mkTenant(t, pool, "role-source-b-"+stamp, string(model), "")}
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
			previous := tenancy.CurrentRouter()
			t.Cleanup(func() { tenancy.SetRouter(previous); tenancy.SetSiloRequiredTables(nil) })
			router := NewRouter(pool, nil, 0).WithQuarantine(tenancy.NewQuarantine())
			tenancy.SetRouter(router)
			required, err := RequiredSiloTables(ctx, pool)
			if err != nil {
				t.Fatal(err)
			}
			tenancy.SetSiloRequiredTables(required)
			contextID, routerID, interfaceID := uuid.NewString(), uuid.NewString(), uuid.NewString()
			budget := entity.InterfaceRolePolicyBudget{MemoryBytes: 128 << 20, WorkUnits: 64 << 20}
			run := func(tenant string, fn func(context.Context, tenancy.Scope) error) {
				t.Helper()
				if err := tenancy.InTenant(tenancy.WithSiloTableLock(tenancy.WithTenant(ctx, tenancy.ID(tenant))), pool, fn); err != nil {
					t.Fatal(err)
				}
			}
			serials := map[string]string{}
			for lane, tenant := range tenants {
				targets, err := router.TargetsFor(ctx, tenant)
				expected := ""
				if model == tenancy.IsolationSiloed {
					expected = SchemaName(tenant)
				}
				if err != nil || targets.Model != model || targets.PGSchema != expected {
					t.Fatal("role source reader has the wrong provisioned state route", targets, err)
				}
				for _, agent := range []string{"role-snmp", "role-listener", "role-router"} {
					serial := strings.ReplaceAll(uuid.NewString(), "-", "")
					spiffe := crypto.EntitySPIFFEID(tenant, agent)
					if agent == "role-router" {
						spiffe = crypto.BMPSPIFFEID(tenant, agent)
					}
					if err := store.NewAgentIdentities(pool).Record(ctx, tenant, agent, spiffe, serial, time.Now().Add(time.Hour), ""); err != nil {
						t.Fatal(err)
					}
					serials[tenant+agent] = serial
				}
				run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
					if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$2,$2,'owned','same private space')`, tenant, contextID); err != nil {
						return err
					}
					if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','owned router')`, tenant, contextID, routerID); err != nil {
						return err
					}
					if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label,parent_entity_id,source_agent_id,configured_ref,interface_index) VALUES($1,$2,$3,'interface','same interface',$4,'role-snmp','192.0.2.1',7)`, tenant, contextID, interfaceID, routerID); err != nil {
						return err
					}
					if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES($1,'role-snmp',$2),($1,'role-listener',$2)`, tenant, contextID); err != nil {
						return err
					}
					if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id) VALUES($1,'role-snmp','device_target','192.0.2.1',$2,$3),($1,'role-listener','bmp_peer','role-router',$2,$3)`, tenant, contextID, routerID); err != nil {
						return err
					}
					if _, err := (store.InterfaceRoleConfiguration{}).PutPolicy(ctx, sc, contextID, "", "0", entity.InterfaceRolePolicyDefinition{ProviderASNs: []uint32{64496 + uint32(lane)}}, budget); err != nil {
						return err
					}
					_, err := (store.InterfaceRoleConfiguration{}).PutOverride(ctx, sc, contextID, interfaceID, "", "0", entity.InterfaceRoleBackbone)
					return err
				})
				at := time.Now().UTC().Truncate(time.Microsecond)
				source := entity.SourceKey{AgentID: "role-snmp", Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"}
				claims := []entity.Observation{
					{ID: uuid.NewString(), Source: source, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "192.0.2.1"}, SourceRef: "snmp:configured-target", ObservedAt: at, SNMPInterfacePrefixes: []entity.SNMPInterfacePrefix{{IfIndex: 7, Prefix: netip.MustParsePrefix("10.42.0.0/24"), OnLink: true}, {IfIndex: 7, Prefix: netip.MustParsePrefix("2001:db8::/64"), OnLink: true}}},
					{ID: uuid.NewString(), Source: source, Alias: entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: "7"}, SourceRef: "snmp:ifIndex:7", InterfaceDescription: "owned-" + tenant, ObservedAt: at},
					{ID: uuid.NewString(), Source: source, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "10.42.0.2"}, SourceRef: "snmp:ifIndex:7", ObservedAt: at},
				}
				count, unresolved, err := store.NewEntityRegistry(pool).WriteEvidenceBatch(tenancy.WithTenant(ctx, tenancy.ID(tenant)), source.AgentID, serials[tenant+source.AgentID], claims)
				if err != nil || count != len(claims) || unresolved != 0 {
					t.Fatal("managed role source writer lost complete owned observations", count, unresolved, err)
				}
				peer := entity.Observation{ID: uuid.NewString(), Source: entity.SourceKey{AgentID: "role-listener", Kind: entity.BMPPeer, SourceRef: "role-router"}, Alias: entity.AliasKey{Kind: entity.BMPPeerAlias, Value: fmt.Sprintf("10.42.0.1/as%d", 64496+lane)}, SourceRef: fmt.Sprintf("bmp:router:role-router:peer-asn:%d", 64496+lane), OriginSerial: serials[tenant+"role-router"], ObservedAt: at}
				count, unresolved, err = store.NewEntityRegistry(pool).WriteEvidenceBatch(tenancy.WithTenant(ctx, tenancy.ID(tenant)), "role-listener", serials[tenant+"role-listener"], []entity.Observation{peer})
				if err != nil || count != 1 || unresolved != 0 {
					t.Fatal("managed role source writer lost current BMP origin", count, unresolved, err)
				}
			}
			// A valid pooled shadow for a siloed tenant must never supply policy
			// when its physical relation disappears. Hybrid has no PG shadow.
			if model == tenancy.IsolationSiloed {
				for _, tenant := range tenants {
					if _, err := pool.Exec(ctx, `INSERT INTO public.entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$2,$2,'pooled shadow','not current')`, tenant, contextID); err != nil {
						t.Fatal(err)
					}
					if _, err := pool.Exec(ctx, `INSERT INTO public.interface_role_policies(tenant_id,context_id,id,definition) VALUES($1,$2,$3,'{"provider_asns":[4294967295],"customer_asns":[],"description_rules":[]}'::jsonb)`, tenant, contextID, uuid.NewString()); err != nil {
						t.Fatal(err)
					}
				}
			}
			reader := store.NewInterfaceRoleInputs(pool)
			load := func(tenant string) store.InterfaceRoleInputs {
				t.Helper()
				got, err := reader.Load(tenancy.WithTenant(ctx, tenancy.ID(tenant)), entity.Scope{TenantID: tenant, ContextID: contextID}, interfaceID, budget)
				if err != nil {
					t.Fatal("managed current role inputs unavailable", err)
				}
				return got
			}
			for lane, tenant := range tenants {
				got := load(tenant)
				if got.TenantID != tenant || got.ContextID != contextID || got.RouterID != routerID || got.InterfaceID != interfaceID || got.SNMP == nil || got.SNMP.Description != "owned-"+tenant || len(got.SNMP.Prefixes) != 2 || len(got.Peers) != 1 || got.Peers[0].ASN != 64496+uint32(lane) || len(got.Policy.Definition.ProviderASNs) != 1 || got.Policy.Definition.ProviderASNs[0] != 64496+uint32(lane) || got.Override == nil || got.Override.Role != entity.InterfaceRoleBackbone {
					t.Fatal("managed role source crossed physical route, tenant or current authority", got)
				}
				run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
					var count, foreign int
					if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM interface_role_policies`).Scan(&count); err != nil {
						return err
					}
					if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM interface_role_policies WHERE tenant_id=$1`, tenants[1-lane]).Scan(&foreign); err != nil {
						return err
					}
					if count != 1 || foreign != 0 {
						t.Fatal("managed role policies bypassed storage RLS", count, foreign)
					}
					return nil
				})
			}
			if _, err := reader.Load(tenancy.WithTenant(ctx, tenancy.ID(tenants[1])), entity.Scope{TenantID: tenants[0], ContextID: contextID}, interfaceID, budget); !errors.Is(err, entity.ErrScopeMismatch) {
				t.Fatal("managed role reader accepted contradictory tenant", err)
			}
			run(tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET revoked_at=statement_timestamp() WHERE tenant_id=$1 AND agent_id='role-snmp'`, tenants[0])
				return err
			})
			if got := load(tenants[0]); got.SNMP != nil || got.Override == nil || got.Override.Role != entity.InterfaceRoleBackbone {
				t.Fatal("managed role reader revived revoked source or lost manual override")
			}
			if got := load(tenants[1]); got.SNMP == nil || got.SNMP.Description != "owned-"+tenants[1] {
				t.Fatal("managed source revocation crossed sibling tenant")
			}
			if model == tenancy.IsolationSiloed {
				table := pgx.Identifier{SchemaName(tenants[0]), "interface_role_policies"}.Sanitize()
				if _, err := pool.Exec(ctx, `ALTER TABLE `+table+` RENAME TO interface_role_policies_held`); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if _, err := pool.Exec(context.Background(), `ALTER TABLE `+pgx.Identifier{SchemaName(tenants[0]), "interface_role_policies_held"}.Sanitize()+` RENAME TO interface_role_policies`); err != nil {
						t.Error(err)
					}
				})
				if got, err := reader.Load(tenancy.WithTenant(ctx, tenancy.ID(tenants[0])), entity.Scope{TenantID: tenants[0], ContextID: contextID}, interfaceID, budget); err == nil || got.SNMP != nil || got.Policy.ID != "" {
					t.Fatal("missing managed role relation fell through to pooled shadow", err)
				}
			}
		})
	}
}
