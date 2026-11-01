// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// A graph window may be visually capped, but the authoritative inventory
// must page past the published 250-device comparison point without exposing
// a same-context UUID from another tenant.
func TestEntityRegistryPagesBeyond250DevicesWithinTenant(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "entity-scale-a-"+suffix, "Scale A")
	if err != nil {
		t.Fatal(err)
	}
	createdTenants := []string{a.ID}
	defer func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, createdTenants); err != nil {
			t.Errorf("remove entity scale tenants: %v", err)
		}
	}()
	b, err := NewTenants(pool).Create(ctx, "entity-scale-b-"+suffix, "Scale B")
	if err != nil {
		t.Fatal(err)
	}
	createdTenants = append(createdTenants, b.ID)
	contextID := uuid.NewString()
	for _, tenantID := range []string{a.ID, b.ID} {
		inTenant(ctx, t, pool, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
				VALUES ($1,$2,$3,$4,'scale-site','scale-vrf')`,
				tenantID, contextID, uuid.NewString(), uuid.NewString())
			return err
		})
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO entities
			(tenant_id,context_id,id,kind,label)
			SELECT $1,$2,gen_random_uuid(),'device','router-' || n::text
			FROM generate_series(1,251) AS n`, a.ID, contextID)
		return err
	})
	foreignID := uuid.NewString()
	inTenant(ctx, t, pool, b.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO entities
			(tenant_id,context_id,id,kind,label)
			VALUES ($1,$2,$3,'device','foreign-router')`, b.ID, contextID, foreignID)
		return err
	})

	repo := NewEntityRegistry(pool)
	scopeA := entity.Scope{TenantID: a.ID, ContextID: contextID}
	seen := map[string]bool{}
	cursor := ""
	for pageNo := 0; pageNo < 3; pageNo++ {
		page, err := repo.ListEntities(tenancy.WithTenant(ctx, tenancy.ID(a.ID)), scopeA, cursor, 100)
		if err != nil {
			t.Fatal(err)
		}
		wantLen := 100
		if pageNo == 2 {
			wantLen = 51
		}
		if len(page.Items) != wantLen {
			t.Fatalf("page %d: got %d devices, want %d", pageNo, len(page.Items), wantLen)
		}
		for _, item := range page.Items {
			if seen[item.ID] || item.Scope != scopeA || item.ID == foreignID {
				t.Fatalf("page %d contains duplicate or foreign device: %+v", pageNo, item)
			}
			seen[item.ID] = true
		}
		if pageNo < 2 && page.NextCursor == "" || pageNo == 2 && page.NextCursor != "" {
			t.Fatalf("page %d has wrong continuation cursor %q", pageNo, page.NextCursor)
		}
		cursor = page.NextCursor
	}
	if len(seen) != 251 {
		t.Fatalf("paged inventory has %d unique devices, want 251", len(seen))
	}
	if _, err := repo.GetEntity(tenancy.WithTenant(ctx, tenancy.ID(a.ID)), scopeA, foreignID); err == nil {
		t.Fatal("same-context foreign device was visible across the tenant boundary")
	}
	// The Topology projection calls this same bounded batch resolver. A page
	// count alone cannot show whether a 251-node graph can attach identity in
	// one request, so make 251 independent, sender-bound address observations.
	const sourceAgent = "scale-agent"
	serial := strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := NewAgentIdentities(pool).Record(ctx, a.ID, sourceAgent,
		crypto.EntitySPIFFEID(a.ID, sourceAgent), serial,
		time.Now().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
			(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`,
			a.ID, sourceAgent, contextID); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `WITH numbered AS (
			SELECT id,row_number() OVER (ORDER BY id) AS n
			FROM entities WHERE tenant_id=$1 AND context_id=$2
		)
			INSERT INTO entity_source_contexts
			(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
			SELECT $1,$3,'device_target','10.43.0.' || n::text,$2,id
			FROM numbered`, a.ID, contextID, sourceAgent); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO entity_evidence
			(tenant_id,context_id,id,observation_id,entity_id,
			 alias_kind,alias_value,source,source_ref,agent_id,
			 source_kind,configured_ref,observed_at,sender_serial)
			SELECT $1,$2,gen_random_uuid(),gen_random_uuid(),m.anchor_entity_id,
			 'address',m.source_ref,'snmp','snmp:configured-target',m.agent_id,
			 m.source_kind,m.source_ref,clock_timestamp(),$3
			FROM entity_source_contexts m
			WHERE m.tenant_id=$1 AND m.agent_id=$4`,
			a.ID, contextID, serial, sourceAgent)
		return err
	})
	const foreignAgent = "scale-foreign-agent"
	foreignSerial := strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := NewAgentIdentities(pool).Record(ctx, b.ID, foreignAgent,
		crypto.EntitySPIFFEID(b.ID, foreignAgent), foreignSerial,
		time.Now().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	inTenant(ctx, t, pool, b.ID, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
			(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`,
			b.ID, foreignAgent, contextID); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
			(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
			VALUES ($1,$2,'device_target','10.43.0.1',$3,$4)`,
			b.ID, foreignAgent, contextID, foreignID); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO entity_evidence
			(tenant_id,context_id,id,observation_id,entity_id,
			 alias_kind,alias_value,source,source_ref,agent_id,
			 source_kind,configured_ref,observed_at,sender_serial)
			VALUES ($1,$2,gen_random_uuid(),gen_random_uuid(),$3,
			 'address','10.43.0.1','snmp','snmp:configured-target',$4,
			 'device_target','10.43.0.1',clock_timestamp(),$5)`,
			b.ID, contextID, foreignID, foreignAgent, foreignSerial)
		return err
	})
	addresses := make([]string, 0, 251)
	for n := 1; n <= 251; n++ {
		addresses = append(addresses, fmt.Sprintf("10.43.0.%d", n))
	}
	resolved, err := repo.ResolveAddresses(tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
		scopeA, addresses)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != len(addresses) {
		t.Fatalf("batch projected %d of %d graph addresses", len(resolved), len(addresses))
	}
	for _, address := range addresses {
		result := resolved[address]
		if result.Status != entity.Resolved || result.EntityID == "" ||
			result.Scope != scopeA || result.EntityID == foreignID {
			t.Fatalf("batch address %s lost tenant-scoped identity: %+v", address, result)
		}
	}
	foreignResolution, err := repo.ResolveAddresses(
		tenancy.WithTenant(ctx, tenancy.ID(b.ID)),
		entity.Scope{TenantID: b.ID, ContextID: contextID},
		[]string{"10.43.0.1", "10.43.0.2"})
	if err != nil || foreignResolution["10.43.0.1"].EntityID != foreignID ||
		foreignResolution["10.43.0.2"].Status != entity.Unresolved {
		t.Fatalf("paired tenant lost its own overlapping address: %+v %v", foreignResolution, err)
	}
}
