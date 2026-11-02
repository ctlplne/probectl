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
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// The bus authenticates the tenant, not the raw row's claimed agent. An
// operator-owned exporter address must be unique inside that tenant before
// its context and tags may label tenant-wide Explorer rows.
func TestTagTenantSnapshotUsesOnlyUniqueOwnedExporterAddress(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	stamp := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "tag-tenant-a-"+stamp, "Tag tenant A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "tag-tenant-b-"+stamp, "Tag tenant B")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`,
			[]string{a.ID, b.ID}); err != nil {
			t.Errorf("remove tag tenant fixture: %v", err)
		}
	})
	contextA, contextA2, contextB := uuid.NewString(), uuid.NewString(), uuid.NewString()
	tagID := uuid.NewString()
	for _, row := range []struct{ tenantID, contextID, agentID, value string }{
		{a.ID, contextA, "agent-a", "A"},
		{b.ID, contextB, "agent-b", "B"},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO entity_contexts
			(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
			VALUES ($1,$2,$3,$4,$3::uuid::text,$4::uuid::text)`,
			row.tenantID, row.contextID, uuid.NewString(), uuid.NewString()); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO entity_agent_contexts
			(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`,
			row.tenantID, row.agentID, row.contextID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO entity_source_contexts
			(tenant_id,agent_id,source_kind,source_ref,context_id)
			VALUES ($1,$2,'flow_exporter','192.0.2.10',$3)`,
			row.tenantID, row.agentID, row.contextID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO tenant_tag_definitions
			(tenant_id,id,key) VALUES ($1,$2,'customer')`, row.tenantID, tagID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO tenant_tag_assignments
			(tenant_id,context_id,id,tag_id,target_kind,exporter_agent_id,
			 exporter_source_kind,exporter_source_ref,value,source)
			VALUES ($1,$2,$3,$4,'exporter',$5,'flow_exporter','192.0.2.10',$6,'manual')`,
			row.tenantID, row.contextID, uuid.NewString(), tagID, row.agentID, row.value); err != nil {
			t.Fatal(err)
		}
	}
	loader := NewTagSnapshots(pool)
	address := netip.MustParseAddr("192.0.2.10")
	var initialA *TenantTagSnapshot
	for _, row := range []struct{ tenantID, value string }{{a.ID, "A"}, {b.ID, "B"}} {
		loaded, err := loader.LoadTenant(tenancy.WithTenant(ctx, tenancy.ID(row.tenantID)), 1<<20)
		if err != nil {
			t.Fatalf("load tenant %s: %v", row.tenantID, err)
		}
		resolved, err := loaded.ResolveExporter(address)
		if err != nil || len(resolved) != 1 || resolved[0].Value != row.value {
			t.Fatalf("tenant %s resolved foreign or missing tag: %+v, %v", row.tenantID, resolved, err)
		}
		if row.tenantID == a.ID {
			initialA = loaded
		}
		definitions, err := loaded.Definitions()
		if err != nil || len(definitions) != 1 || definitions[0].Key != "customer" ||
			definitions[0].TenantID != row.tenantID {
			t.Fatalf("tenant %s tag vocabulary: %+v, %v", row.tenantID, definitions, err)
		}
		projection, err := loaded.ProjectExporters(1 << 20)
		if err != nil || len(projection) != 1 || projection[0].Exporter != address.String() ||
			projection[0].Values["customer"] != row.value {
			t.Fatalf("tenant %s query projection: %+v, %v", row.tenantID, projection, err)
		}
		if _, err := loaded.ProjectExporters(128); !errors.Is(err, ErrTagSnapshotBudget) {
			t.Fatalf("tenant %s partial query projection admitted: %v", row.tenantID, err)
		}
		if unknown, err := loaded.ResolveExporter(netip.MustParseAddr("192.0.2.11")); err != nil || len(unknown) != 0 {
			t.Fatalf("unknown exporter resolved tags: %+v, %v", unknown, err)
		}
	}
	if _, err := loader.LoadTenant(tenancy.WithTenant(ctx, tenancy.ID(a.ID)), 1024); !errors.Is(err, ErrTagSnapshotBudget) {
		t.Fatalf("undersized tenant budget admitted exporter catalogue: %v", err)
	}
	if _, err := loader.LoadTenant(ctx, 1<<20); !errors.Is(err, tags.ErrScopeMismatch) {
		t.Fatalf("missing tenant loaded tag catalogue: %v", err)
	}
	// A second registered agent in another context claims the same RFC1918
	// exporter. The tenant-wide loader must not pick either context from a raw
	// row's claimed agent ID, even though each source assignment is valid.
	if _, err := pool.Exec(ctx, `INSERT INTO entity_contexts
		(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
		VALUES ($1,$2,$3,$4,$3::uuid::text,$4::uuid::text)`,
		a.ID, contextA2, uuid.NewString(), uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO entity_agent_contexts
		(tenant_id,agent_id,context_id) VALUES ($1,'agent-a2',$2)`, a.ID, contextA2); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO entity_source_contexts
		(tenant_id,agent_id,source_kind,source_ref,context_id)
		VALUES ($1,'agent-a2','flow_exporter','192.0.2.10',$2)`, a.ID, contextA2); err != nil {
		t.Fatal(err)
	}
	ambiguous, err := loader.LoadTenant(tenancy.WithTenant(ctx, tenancy.ID(a.ID)), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	initialRevision, err := initialA.Revision()
	if err != nil {
		t.Fatal(err)
	}
	ambiguousRevision, err := ambiguous.Revision()
	if err != nil || ambiguousRevision <= initialRevision {
		t.Fatalf("source ownership edit did not invalidate tag revision: %d -> %d, %v",
			initialRevision, ambiguousRevision, err)
	}
	resolved, err := ambiguous.ResolveExporter(address)
	if err != nil || len(resolved) != 0 {
		t.Fatalf("ambiguous exporter selected an agent/context: %+v, %v", resolved, err)
	}
	projection, err := ambiguous.ProjectExporters(1 << 20)
	if err != nil || len(projection) != 0 {
		t.Fatalf("ambiguous exporter appeared in query projection: %+v, %v", projection, err)
	}
	resolved, err = initialA.ResolveExporter(address)
	if err != nil || len(resolved) != 1 || resolved[0].Value != "A" {
		t.Fatalf("pinned query snapshot changed after new binding: %+v, %v", resolved, err)
	}
	// Expiring the second agent's context removes its authority even if its
	// source row still exists. A fresh query may again use the unique owner.
	if _, err := pool.Exec(ctx, `UPDATE entity_agent_contexts SET expires_at=clock_timestamp()
		WHERE tenant_id=$1 AND agent_id='agent-a2'`, a.ID); err != nil {
		t.Fatal(err)
	}
	current, err := loader.LoadTenant(tenancy.WithTenant(ctx, tenancy.ID(a.ID)), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	currentRevision, err := current.Revision()
	if err != nil || currentRevision <= ambiguousRevision {
		t.Fatalf("agent-context expiry did not invalidate tag revision: %d -> %d, %v",
			ambiguousRevision, currentRevision, err)
	}
	resolved, err = current.ResolveExporter(address)
	if err != nil || len(resolved) != 1 || resolved[0].Value != "A" {
		t.Fatalf("expired agent context still shadowed unique owner: %+v, %v", resolved, err)
	}
	// The other tenant's same address stays independently resolvable.
	independent, err := loader.LoadTenant(tenancy.WithTenant(ctx, tenancy.ID(b.ID)), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err = independent.ResolveExporter(address)
	if err != nil || len(resolved) != 1 || resolved[0].Value != "B" {
		t.Fatalf("tenant B lost its own exporter tag: %+v, %v", resolved, err)
	}
}
