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
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Use the migration login directly: RLS would also reject these inserts, but
// this fixture proves that the compound foreign keys hold below the handler.
func TestIncidentVerifiedEntityForeignKeysBindTenantAndContext(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "incident-entity-a-"+suffix, "A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "incident-entity-b-"+suffix, "B")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`,
			[]string{a.ID, b.ID}); err != nil {
			t.Errorf("remove incident entity tenants: %v", err)
		}
	}()
	routingContext := uuid.NewString()
	entityA, entityB := uuid.NewString(), uuid.NewString()
	for _, fixture := range []struct{ tenant, entity string }{{a.ID, entityA}, {b.ID, entityB}} {
		if _, err := pool.Exec(ctx, `INSERT INTO entity_contexts
			(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
			VALUES ($1,$2,$3,$4,$3::text,$4::text)`, fixture.tenant, routingContext,
			uuid.NewString(), uuid.NewString()); err != nil {
			t.Fatalf("seed incident routing context: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO entities
			(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'device','router')`,
			fixture.tenant, routingContext, fixture.entity); err != nil {
			t.Fatalf("seed incident canonical entity: %v", err)
		}
	}
	incidentA, incidentB := uuid.NewString(), uuid.NewString()
	for _, fixture := range []struct {
		tenant, incident, entity string
		signalCount              int
	}{
		{a.ID, incidentA, entityA, 1}, {b.ID, incidentB, entityB, 0},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO incidents
			(tenant_id,id,title,entity_context_id,entity_id,identity_lookup_attempted,signal_count)
			VALUES ($1,$2,'verified incident',$3,$4,true,$5)`, fixture.tenant,
			fixture.incident, routingContext, fixture.entity, fixture.signalCount); err != nil {
			t.Fatalf("seed verified incident: %v", err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO incidents
		(tenant_id,id,title,entity_context_id,entity_id,identity_lookup_attempted)
		VALUES ($1,$2,'cross-tenant',$3,$4,true)`, a.ID, uuid.NewString(),
		routingContext, entityB); err == nil {
		t.Fatal("public incident accepted a foreign tenant entity in a shared context UUID")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO incidents
		(tenant_id,id,title,entity_id) VALUES ($1,$2,'half identity',$3)`,
		a.ID, uuid.NewString(), entityA); err == nil {
		t.Fatal("public incident accepted an entity ID without its verified context")
	}
	insertSignal := func(incidentID, entityID string) error {
		_, err := pool.Exec(ctx, `INSERT INTO incident_signals
			(tenant_id,incident_id,plane,kind,entity_context_id,entity_id,identity_lookup_attempted)
			VALUES ($1,$2,'device','alert.firing',$3,$4,true)`,
			a.ID, incidentID, routingContext, entityID)
		return err
	}
	if err := insertSignal(incidentB, entityA); err == nil {
		t.Fatal("public signal accepted a foreign tenant incident UUID")
	}
	if err := insertSignal(incidentA, entityB); err == nil {
		t.Fatal("public signal accepted a foreign tenant entity UUID")
	}
	if err := insertSignal(incidentA, entityA); err != nil {
		t.Fatalf("public signal rejected its own verified tuple: %v", err)
	}
	var sourceSignal string
	if err := pool.QueryRow(ctx, `SELECT id::text FROM incident_signals
		WHERE tenant_id=$1 AND incident_id=$2 LIMIT 1`, a.ID, incidentA).Scan(&sourceSignal); err != nil {
		t.Fatalf("read own incident signal: %v", err)
	}
	detachedA := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO incidents
		(tenant_id,id,title,entity_context_id,entity_id,identity_lookup_attempted)
		VALUES ($1,$2,'detached',$3,$4,true)`, a.ID, detachedA, routingContext, entityA); err != nil {
		t.Fatalf("seed own detached incident: %v", err)
	}
	insertOverride := func(detached, entityID string) error {
		_, err := pool.Exec(ctx, `INSERT INTO incident_correlation_overrides
			(tenant_id,source_incident_id,detached_incident_id,source_signal_id,
			 plane,kind,target,prefix,reason,created_by,
			 entity_context_id,entity_id,identity_lookup_attempted)
			VALUES ($1,$2,$3,$4,'device','alert.firing','10.42.0.1','',
			        'separate fault','operator-a',$5,$6,true)`,
			a.ID, incidentA, detached, sourceSignal, routingContext, entityID)
		return err
	}
	if err := insertOverride(incidentB, entityA); err == nil {
		t.Fatal("public override accepted another tenant's detached incident")
	}
	if err := insertOverride(detachedA, entityB); err == nil {
		t.Fatal("public override accepted another tenant's canonical entity")
	}
	if err := insertOverride(detachedA, entityA); err != nil {
		t.Fatalf("public override rejected its own verified identity: %v", err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		got, err := (Incidents{}).Get(ctx, sc, incidentA)
		if err != nil {
			return err
		}
		if got.IdentityContextID != routingContext || got.IdentityEntityID != entityA ||
			!got.IdentityLookupAttempted || len(got.Signals) != 1 ||
			got.Signals[0].IdentityEntityID != entityA {
			t.Fatalf("repository lost verified incident/signal tuple: %+v", got)
		}
		_, err = (Incidents{}).AppendSignal(ctx, sc, incidentA, incident.Signal{
			TenantID: a.ID, Plane: "flow", Kind: "fault", Target: "10.42.0.1",
			OccurredAt: time.Now(), IdentityContextID: routingContext,
			IdentityEntityID: entityA, IdentityLookupAttempted: true,
		})
		return err
	})
	if _, err := pool.Exec(ctx, `DELETE FROM entities
		WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, a.ID, routingContext, entityA); err != nil {
		t.Fatalf("delete canonical entity while retaining incident history: %v", err)
	}
	for _, table := range []string{"incidents", "incident_signals", "incident_correlation_overrides"} {
		var kept, unbound int
		if err := pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER
			(WHERE entity_context_id=$2 AND entity_id IS NULL AND identity_lookup_attempted) FROM `+table+`
			WHERE tenant_id=$1`, a.ID, routingContext).Scan(&kept, &unbound); err != nil ||
			kept != map[string]int{"incidents": 2, "incident_signals": 2,
				"incident_correlation_overrides": 1}[table] || unbound != kept {
			t.Fatalf("deleted entity erased or lost the context tombstone on %s: kept=%d tombstones=%d err=%v",
				table, kept, unbound, err)
		}
	}
}
