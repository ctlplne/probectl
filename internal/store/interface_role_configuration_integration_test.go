// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestInterfaceRoleConfigurationPostgresKeepsTenantCASAndOverrideIncarnations(t *testing.T) {
	ctx := t.Context()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	var tenants []string
	for _, suffix := range []string{"a", "b"} {
		tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("role-config-%s-%d", suffix, time.Now().UnixNano()), suffix)
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
	contextID, routerID, interfaceID, foreignOnly := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	fence := tenancy.NewPostgresWriterFence(pool)
	run := func(tenant string, fn func(context.Context, tenancy.Scope) error) error {
		return tenancy.FencedTenantWrite(tenancy.WithTenant(ctx, tenancy.ID(tenant)), fence, tenant, entity.ErrScopeMismatch,
			func(ctx context.Context) error { return tenancy.InTenant(ctx, pool, fn) })
	}
	for _, tenant := range tenants {
		if err := run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'same-site','same-vrf')`, tenant, contextID, uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','router')`, tenant, contextID, routerID); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label,parent_entity_id) VALUES($1,$2,$3,'interface','uplink',$4)`, tenant, contextID, interfaceID, routerID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := run(tenants[1], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label,parent_entity_id) VALUES($1,$2,$3,'interface','foreign-only',$4)`, tenants[1], contextID, foreignOnly, routerID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	store := InterfaceRoleConfiguration{}
	budget := entity.InterfaceRolePolicyBudget{MemoryBytes: 1 << 30, WorkUnits: 4 << 20}
	for lane, tenant := range tenants {
		if err := run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			initial := entity.InterfaceRolePolicyDefinition{ProviderASNs: []uint32{uint32(64500 + lane)}}
			old, err := store.PutPolicy(ctx, sc, contextID, "", "0", initial, budget)
			if err != nil || old.ID == "" || old.Revision != "1" {
				t.Fatal("owned role policy create failed", err)
			}
			// Model configuration removal/recreation, as after subject erasure.
			// The same context and revision must not revive an old edit token.
			if _, err := sc.Q.Exec(ctx, `DELETE FROM interface_role_policies WHERE tenant_id=$1 AND context_id=$2`, tenant, contextID); err != nil {
				return err
			}
			current, err := store.PutPolicy(ctx, sc, contextID, "", "0", initial, budget)
			if err != nil || current.ID == old.ID || current.Revision != "1" {
				t.Fatal("recreated role policy reused its old incarnation", err)
			}
			stale := entity.InterfaceRolePolicyDefinition{ProviderASNs: []uint32{64599}}
			if _, err := store.PutPolicy(ctx, sc, contextID, old.ID, old.Revision, stale, budget); !errors.Is(err, entity.ErrInterfaceRoleConflict) {
				t.Fatal("stale role policy incarnation replaced recreated configuration", err)
			}
			definition := initial
			for index := 0; index < 4097; index++ {
				definition.DescriptionRules = append(definition.DescriptionRules, entity.InterfaceRoleDescriptionRule{
					Pattern: "^" + tenant + strings.Repeat("-uplink", 24) + fmt.Sprint(index) + "$", Role: entity.InterfaceRoleBackbone})
			}
			current, err = store.PutPolicy(ctx, sc, contextID, current.ID, current.Revision, definition, budget)
			if err != nil || len(current.Definition.DescriptionRules) != 4097 {
				t.Fatal("complete role policy retained the provisional document ceiling", err)
			}
			body, err := json.Marshal(current.Definition)
			if err != nil || len(body) <= 1<<20 {
				t.Fatal("role policy corpus did not exceed its provisional document ceiling", len(body), err)
			}
			unchanged, err := store.PutPolicy(ctx, sc, contextID, current.ID, current.Revision, current.Definition, budget)
			if err != nil || unchanged.Revision != current.Revision || !unchanged.UpdatedAt.Equal(current.UpdatedAt) {
				t.Fatal("equivalent role policy changed semantic revision or clock", err)
			}
			if _, err := store.Policy(ctx, sc, contextID, entity.InterfaceRolePolicyBudget{MemoryBytes: 8192, WorkUnits: 1 << 20}); !errors.Is(err, entity.ErrInterfaceRoleBudget) {
				t.Fatal("bounded role-policy SQL projection loaded an oversized definition", err)
			}
			var count int
			var own []byte
			if err := sc.Q.QueryRow(ctx, `SELECT count(*),min(definition::text)::jsonb FROM interface_role_policies WHERE context_id=$1`, contextID).Scan(&count, &own); err != nil {
				return err
			}
			var stored entity.InterfaceRolePolicyDefinition
			if err := json.Unmarshal(own, &stored); err != nil || count != 1 || !sameInterfaceRolePolicy(stored, current.Definition) {
				t.Fatal("complete role policy crossed FORCE RLS or changed stored values", count, err)
			}
			first, err := store.PutOverride(ctx, sc, contextID, interfaceID, "", "0", entity.InterfaceRoleTransit)
			if err != nil || first.ID == "" || first.Revision != "1" {
				t.Fatal("owned interface override create failed", err)
			}
			if err := store.ResetOverride(ctx, sc, contextID, interfaceID, first.ID, first.Revision); err != nil {
				return err
			}
			second, err := store.PutOverride(ctx, sc, contextID, interfaceID, "", "0", entity.InterfaceRoleCustomer)
			if err != nil || second.ID == first.ID || second.Revision != "1" {
				t.Fatal("reset override reused the old identity", err)
			}
			if _, err := store.PutOverride(ctx, sc, contextID, interfaceID, first.ID, first.Revision, entity.InterfaceRoleOther); !errors.Is(err, entity.ErrInterfaceRoleConflict) {
				t.Fatal("stale override incarnation replaced reset configuration", err)
			}
			if err := store.ResetOverride(ctx, sc, contextID, interfaceID, first.ID, first.Revision); !errors.Is(err, entity.ErrInterfaceRoleConflict) {
				t.Fatal("stale override incarnation erased reset configuration", err)
			}
			definition = current.Definition
			definition.ProviderASNs = []uint32{uint32(64600 + lane)}
			if _, err := store.PutPolicy(ctx, sc, contextID, current.ID, current.Revision, definition, budget); err != nil {
				return err
			}
			kept, err := store.Override(ctx, sc, contextID, interfaceID)
			if err != nil || kept.ID != second.ID || kept.Role != second.Role || kept.Revision != second.Revision {
				t.Fatal("policy reclassification rewrote the operator override", err)
			}
			if _, err := store.Override(ctx, sc, contextID, routerID); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal("device UUID became an interface override target", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range []string{routerID, foreignOnly} {
		err := run(tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO interface_role_overrides(tenant_id,context_id,interface_id,id,role) VALUES($1,$2,$3,$4,'transit')`, tenants[0], contextID, target, uuid.NewString())
			return err
		})
		var refusal *pgconn.PgError
		if !errors.As(err, &refusal) || refusal.Code != "23503" {
			t.Fatal("override storage accepted a foreign or wrong-kind interface", err)
		}
	}
}
