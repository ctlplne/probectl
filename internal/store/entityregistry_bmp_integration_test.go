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

func TestBMPOriginSerialRevocationDoesNotReactivateInAnotherTenant(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "entity-bmp-a-"+suffix, "BMP A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "entity-bmp-b-"+suffix, "BMP B")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a.ID, b.ID}); err != nil {
			t.Errorf("remove BMP entity fixtures: %v", err)
		}
	}()
	const listener, router, address = "listener-auth", "router-auth", "10.42.0.1"
	contextID := uuid.NewString() // same context UUID and RFC1918 IP in both tenants
	serials := map[string]string{a.ID: "ab1234", b.ID: "cd5678"}
	listenerSerials := map[string]string{}
	entities := map[string]string{}
	for _, tenantID := range []string{a.ID, b.ID} {
		listenerSerials[tenantID] = strings.ReplaceAll(uuid.NewString(), "-", "")
		identities := NewAgentIdentities(pool)
		if err := identities.Record(ctx, tenantID, listener,
			crypto.EntitySPIFFEID(tenantID, listener), listenerSerials[tenantID],
			time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		if err := identities.Record(ctx, tenantID, router,
			crypto.BMPSPIFFEID(tenantID, router), serials[tenantID],
			time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		entities[tenantID] = uuid.NewString()
		inTenant(ctx, t, pool, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
                VALUES ($1,$2,$3,$4,$3::text,$4::text)`,
				tenantID, contextID, uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
				(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`,
				tenantID, listener, contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities
				(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'device','router')`,
				tenantID, contextID, entities[tenantID]); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
				(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
				VALUES ($1,$2,'bmp_peer',$3,$4,$5)`, tenantID, listener,
				router, contextID, entities[tenantID])
			return err
		})
	}
	repo := NewEntityRegistry(pool)
	alias := entity.AliasKey{Kind: entity.AddressAlias, Value: address}
	claim := func(serial string) entity.Observation {
		return entity.Observation{ID: uuid.NewString(),
			Source: entity.SourceKey{AgentID: listener, Kind: entity.BMPPeer, SourceRef: router},
			Alias:  alias, SourceRef: "bmp:router:router-auth:peer-asn:64500",
			OriginSerial: serial, ObservedAt: time.Now().UTC()}
	}
	// The listener's evidence SVID remains live, but it cannot attest a BMP
	// frame dated after the router's origin SVID expires. The same private IP
	// and serial-independent listener in tenant B must remain unaffected.
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE agent_identities
			SET not_after=clock_timestamp()+interval '2 minutes'
			WHERE tenant_id=$1 AND agent_id=$2 AND serial=$3`, a.ID, router, serials[a.ID])
		return err
	})
	future := claim(serials[a.ID])
	future.ObservedAt = time.Now().UTC().Add(3 * time.Minute)
	if accepted, unresolved, err := repo.WriteEvidenceBatch(
		tenancy.WithTenant(ctx, tenancy.ID(a.ID)), listener,
		listenerSerials[a.ID], []entity.Observation{future}); err != nil || accepted != 0 || unresolved != 1 {
		t.Fatalf("future BMP frame outlived router SVID: %d/%d %v", accepted, unresolved, err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE agent_identities
			SET not_after=clock_timestamp()+interval '1 hour'
			WHERE tenant_id=$1 AND agent_id=$2 AND serial=$3`, a.ID, router, serials[a.ID])
		return err
	})
	for _, tenantID := range []string{a.ID, b.ID} {
		accepted, unresolved, err := repo.WriteEvidenceBatch(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)), listener,
			listenerSerials[tenantID], []entity.Observation{claim(serials[tenantID])})
		if err != nil || accepted != 1 || unresolved != 0 {
			t.Fatalf("initial BMP evidence %s: %d/%d %v", tenantID, accepted, unresolved, err)
		}
	}
	resolve := func(tenantID string) entity.Resolution {
		t.Helper()
		got, err := repo.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			entity.Scope{TenantID: tenantID, ContextID: contextID}, alias)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	resolveBatch := func(tenantID string) entity.Resolution {
		t.Helper()
		got, err := repo.ResolveAddresses(tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			entity.Scope{TenantID: tenantID, ContextID: contextID}, []string{address})
		if err != nil {
			t.Fatal(err)
		}
		return got[address]
	}
	if got := resolve(a.ID); got.Status != entity.Resolved || got.EntityID != entities[a.ID] {
		t.Fatalf("tenant A before revocation: %+v", got)
	}
	if got := resolveBatch(a.ID); got.Status != entity.Resolved || got.EntityID != entities[a.ID] {
		t.Fatalf("batched path join before revocation: %+v", got)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE agent_identities
			SET revoked_at=clock_timestamp(),revoked_by='operator'
			WHERE tenant_id=$1 AND agent_id=$2 AND serial=$3`, a.ID, router, serials[a.ID])
		return err
	})
	if got := resolve(a.ID); got.Status != entity.Unresolved {
		t.Fatalf("revoked BMP origin still resolved: %+v", got)
	}
	if got := resolveBatch(a.ID); got.Status != entity.Unresolved {
		t.Fatalf("batched path join revived revoked BMP origin: %+v", got)
	}
	if got := resolve(b.ID); got.Status != entity.Resolved || got.EntityID != entities[b.ID] {
		t.Fatalf("other tenant affected by BMP revocation: %+v", got)
	}
	if err := NewAgentIdentities(pool).Record(ctx, a.ID, router,
		crypto.BMPSPIFFEID(a.ID, router), "ef9012", time.Now().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	accepted, unresolved, err := repo.WriteEvidenceBatch(
		tenancy.WithTenant(ctx, tenancy.ID(a.ID)), listener, listenerSerials[a.ID],
		[]entity.Observation{claim(serials[a.ID])})
	if err != nil || accepted != 0 || unresolved != 1 {
		t.Fatalf("old serial survived replacement: %d/%d %v", accepted, unresolved, err)
	}
	if got := resolve(a.ID); got.Status != entity.Unresolved {
		t.Fatalf("old evidence revived after replacement: %+v", got)
	}
	if got := resolveBatch(a.ID); got.Status != entity.Unresolved {
		t.Fatalf("batched path join revived replaced BMP origin: %+v", got)
	}
	accepted, unresolved, err = repo.WriteEvidenceBatch(
		tenancy.WithTenant(ctx, tenancy.ID(a.ID)), listener, listenerSerials[a.ID],
		[]entity.Observation{claim("ef9012")})
	if err != nil || accepted != 1 || unresolved != 0 {
		t.Fatalf("replacement serial not accepted: %d/%d %v", accepted, unresolved, err)
	}
	if got := resolve(a.ID); got.Status != entity.Resolved || got.EntityID != entities[a.ID] {
		t.Fatalf("replacement evidence not resolved: %+v", got)
	}
	if got := resolveBatch(a.ID); got.Status != entity.Resolved || got.EntityID != entities[a.ID] {
		t.Fatalf("batched path join did not accept current router serial: %+v", got)
	}
	page, err := repo.ListEntityEvidence(tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
		entity.Scope{TenantID: a.ID, ContextID: contextID}, entities[a.ID], "", 10)
	if err != nil || len(page.Items) != 2 || page.Items[0].Current == page.Items[1].Current {
		t.Fatalf("historical/current BMP serial distinction: %+v %v", page, err)
	}
}
