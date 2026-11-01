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

// Revoking a tenant's credential also closes its canonical source mapping.
// A second tenant may use the same agent UUID, context UUID and private IP;
// neither the revocation nor the resulting resolution crosses that boundary.
func TestEntityRegistryAgentRevocationClosesOnlyOwnSource(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "entity-revoke-a-"+suffix, "Entity A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "entity-revoke-b-"+suffix, "Entity B")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a.ID, b.ID}); err != nil {
			t.Errorf("remove entity revocation fixture tenants: %v", err)
		}
	}()
	agentID, contextID := uuid.NewString(), uuid.NewString()
	entities := map[string]string{a.ID: uuid.NewString(), b.ID: uuid.NewString()}
	identities := NewAgentIdentities(pool)
	for _, tenantID := range []string{a.ID, b.ID} {
		entitySerial := strings.ReplaceAll(uuid.NewString(), "-", "")
		if err := identities.Record(ctx, tenantID, agentID,
			crypto.EntitySPIFFEID(tenantID, agentID), entitySerial,
			time.Now().Add(time.Hour), ""); err != nil {
			t.Fatalf("record %s entity identity: %v", tenantID, err)
		}
		if err := identities.Record(ctx, tenantID, agentID,
			crypto.AgentSPIFFEID(tenantID, agentID), uuid.NewString(),
			time.Now().Add(time.Hour), ""); err != nil {
			t.Fatalf("record %s identity: %v", tenantID, err)
		}
		inTenant(ctx, t, pool, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
                VALUES ($1,$2,$3,$4,$3::uuid::text,$4::uuid::text)`, tenantID,
				contextID, uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
				(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`,
				tenantID, agentID, contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
				(tenant_id,agent_id,source_kind,source_ref,context_id)
				VALUES ($1,$2,'device_target','10.42.0.1',$3)`,
				tenantID, agentID, contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities
				(tenant_id,context_id,id,kind,label)
				VALUES ($1,$2,$3,'device','router')`, tenantID,
				contextID, entities[tenantID]); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
				SET anchor_entity_id=$1 WHERE tenant_id=$2 AND agent_id=$3`,
				entities[tenantID], tenantID, agentID); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_evidence
				(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,
				 source,source_ref,agent_id,source_kind,configured_ref,observed_at,sender_serial)
				VALUES ($1,$2,$3,$3,$4,'address','10.42.0.1',
				        'snmp','router',$5,'device_target','10.42.0.1',
				        clock_timestamp(),$6)`, tenantID, contextID, uuid.NewString(),
				entities[tenantID], agentID, entitySerial)
			return err
		})
	}
	// Even an assignment that starts in the future must be closed before it
	// can activate under a now-revoked identity.
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
			(tenant_id,agent_id,source_kind,source_ref,context_id,assigned_at)
			VALUES ($1,$2,'device_target','10.42.0.2',$3,
			        clock_timestamp()+interval '1 hour')`, a.ID, agentID, contextID)
		return err
	})
	repo := NewEntityRegistry(pool)
	alias := entity.AliasKey{Kind: entity.AddressAlias, Value: "10.42.0.1"}
	for _, tenantID := range []string{a.ID, b.ID} {
		got, err := repo.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			entity.Scope{TenantID: tenantID, ContextID: contextID}, alias)
		if err != nil || got.Status != entity.Resolved || got.EntityID != entities[tenantID] {
			t.Fatalf("before revocation %s: %+v err=%v", tenantID, got, err)
		}
	}
	if _, _, err := identities.RevokeAgent(ctx, a.ID, agentID, "operator"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		tenantID string
		want     entity.Status
	}{
		{a.ID, entity.Unresolved}, {b.ID, entity.Resolved},
	} {
		got, err := repo.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(tc.tenantID)),
			entity.Scope{TenantID: tc.tenantID, ContextID: contextID}, alias)
		if err != nil || got.Status != tc.want ||
			(tc.want == entity.Resolved && got.EntityID != entities[tc.tenantID]) {
			t.Fatalf("after revocation %s: %+v err=%v", tc.tenantID, got, err)
		}
	}
	// A stale operator process or racing map write must not resurrect a
	// revoked producer's canonical joins. The read checks revocation too.
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `UPDATE entity_agent_contexts
			SET assigned_at=clock_timestamp(), expires_at=NULL
			WHERE tenant_id=$1 AND agent_id=$2`, a.ID, agentID); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
			SET assigned_at=clock_timestamp(), expires_at=NULL
			WHERE tenant_id=$1 AND agent_id=$2 AND source_ref='10.42.0.1'`,
			a.ID, agentID)
		return err
	})
	if _, err := repo.ResolveSourceContext(
		tenancy.WithTenant(ctx, tenancy.ID(a.ID)), a.ID,
		entity.SourceKey{AgentID: agentID, Kind: entity.DeviceTarget,
			SourceRef: "10.42.0.1"}); err == nil {
		t.Fatal("revoked agent source assignment became authoritative again")
	}
	got, err := repo.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
		entity.Scope{TenantID: a.ID, ContextID: contextID}, alias)
	if err != nil || got.Status != entity.Unresolved {
		t.Fatalf("revoked evidence resolved after map rebind: %+v err=%v", got, err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var historicalCount, futureClosed int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_evidence
			WHERE tenant_id=$1 AND agent_id=$2`, a.ID, agentID).Scan(&historicalCount); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_source_contexts
			WHERE tenant_id=$1 AND agent_id=$2 AND source_ref='10.42.0.2'
			  AND expires_at=assigned_at`, a.ID, agentID).Scan(&futureClosed); err != nil {
			return err
		}
		if historicalCount != 1 || futureClosed != 1 {
			t.Fatalf("revocation lost history or left future mapping: history=%d future_closed=%d",
				historicalCount, futureClosed)
		}
		return nil
	})
}

// An agent can re-register after the legacy DELETE route. Its old evidence
// certificate must still be refused even if an operator maps the new
// registration to the same source and canonical anchor.
func TestEntityRegistryDeleteRetiresExactEvidenceIdentity(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tenant, err := NewTenants(pool).Create(ctx,
		fmt.Sprintf("entity-delete-%d", time.Now().UnixNano()), "Entity Delete")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM tenants WHERE id=$1`, tenant.ID); err != nil {
			t.Errorf("remove entity delete tenant: %v", err)
		}
	}()
	agentID, oldSerial := uuid.NewString(), strings.ReplaceAll(uuid.NewString(), "-", "")
	identities := NewAgentIdentities(pool)
	if err := identities.Record(ctx, tenant.ID, agentID,
		crypto.EntitySPIFFEID(tenant.ID, agentID), oldSerial,
		time.Now().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	register := func() {
		t.Helper()
		inTenant(ctx, t, pool, tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := (Agents{}).Register(ctx, sc, agentID, "entity-test-agent",
				"entity-host", "test", crypto.AgentSPIFFEID(tenant.ID, agentID), nil)
			return err
		})
	}
	register()
	if known, err := identities.KnownIssuedIdentity(ctx, tenant.ID, agentID,
		crypto.EntitySPIFFEID(tenant.ID, agentID), oldSerial); err != nil || !known {
		t.Fatalf("original evidence identity not known: %v, %v", known, err)
	}
	repo := NewEntityRegistry(pool)
	var contextID, anchorID string
	assign := func(create bool) {
		t.Helper()
		inTenant(ctx, t, pool, tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
			if create {
				scope, err := repo.CreateEntityContext(ctx, sc, "West DC", "Customer A")
				if err != nil {
					return err
				}
				contextID = scope.ContextID
				anchor, err := repo.CreateCanonicalEntity(ctx, sc, contextID,
					entity.Device, "re-registered router")
				if err != nil {
					return err
				}
				anchorID = anchor.ID
			}
			return repo.AssignEntitySource(ctx, sc, entity.SourceKey{
				AgentID: agentID, Kind: entity.DeviceTarget, SourceRef: "10.42.0.1",
			}, contextID, anchorID)
		})
	}
	assign(true)
	bound := tenancy.WithTenant(ctx, tenancy.ID(tenant.ID))
	alias := entity.AliasKey{Kind: entity.AddressAlias, Value: "10.42.0.1"}
	oldClaim := entity.Observation{ID: uuid.NewString(), Source: entity.SourceKey{
		AgentID: agentID, Kind: entity.DeviceTarget, SourceRef: "10.42.0.1",
	}, Alias: alias, SourceRef: "snmp:router", ObservedAt: time.Now().UTC().Truncate(time.Microsecond)}
	if accepted, unresolved, err := repo.WriteEvidenceBatch(bound, agentID,
		oldSerial, []entity.Observation{oldClaim}); err != nil || accepted != 1 || unresolved != 0 {
		t.Fatalf("old certificate initial evidence: accepted=%d unresolved=%d err=%v",
			accepted, unresolved, err)
	}
	inTenant(ctx, t, pool, tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
		return (Agents{}).Delete(ctx, sc, agentID)
	})
	register()
	if known, err := identities.KnownIssuedIdentity(ctx, tenant.ID, agentID,
		crypto.EntitySPIFFEID(tenant.ID, agentID), oldSerial); err != nil || known {
		t.Fatalf("old evidence certificate was reactivated: %v, %v", known, err)
	}
	if known, err := identities.KnownSerial(ctx, tenant.ID, agentID, oldSerial); err != nil || known {
		t.Fatalf("old evidence certificate can rotate: %v, %v", known, err)
	}
	if revoked, err := identities.IsAgentRevoked(ctx, tenant.ID, agentID); err != nil || revoked {
		t.Fatalf("evidence retirement blocked raw re-registration: %v, %v", revoked, err)
	}
	newSerial := strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := identities.Record(ctx, tenant.ID, agentID,
		crypto.EntitySPIFFEID(tenant.ID, agentID), newSerial,
		time.Now().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	if known, err := identities.KnownIssuedIdentity(ctx, tenant.ID, agentID,
		crypto.EntitySPIFFEID(tenant.ID, agentID), newSerial); err != nil || !known {
		t.Fatalf("fresh evidence certificate denied: %v, %v", known, err)
	}
	assign(false)
	resolved, err := repo.ResolveAlias(bound,
		entity.Scope{TenantID: tenant.ID, ContextID: contextID}, alias)
	if err != nil || resolved.Status != entity.Unresolved {
		t.Fatalf("re-registration revived old certificate evidence: %+v err=%v", resolved, err)
	}
	batched, err := repo.ResolveAddresses(bound,
		entity.Scope{TenantID: tenant.ID, ContextID: contextID}, []string{"10.42.0.1"})
	if err != nil || batched["10.42.0.1"].Status != entity.Unresolved {
		t.Fatalf("batched path join revived old certificate evidence: %+v err=%v", batched, err)
	}
	if accepted, unresolved, err := repo.WriteEvidenceBatch(bound, agentID, newSerial,
		[]entity.Observation{oldClaim}); err != nil || accepted != 0 || unresolved != 1 {
		t.Fatalf("new certificate replayed pre-issuance observation: accepted=%d unresolved=%d err=%v",
			accepted, unresolved, err)
	}
	claim := entity.Observation{ID: uuid.NewString(), Source: entity.SourceKey{
		AgentID: agentID, Kind: entity.DeviceTarget, SourceRef: "10.42.0.1",
	}, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "10.42.0.1"},
		SourceRef: "snmp:router", ObservedAt: time.Now().UTC()}
	// A signed batch can arrive before its SVID expires while carrying a
	// future-dated observation after that expiry. It must not become historical
	// canonical evidence once the receiver's clock reaches that future time.
	inTenant(ctx, t, pool, tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE agent_identities
			SET not_after=clock_timestamp()+interval '2 minutes'
			WHERE tenant_id=$1 AND agent_id=$2 AND serial=$3`, tenant.ID, agentID, newSerial)
		return err
	})
	futureClaim := claim
	futureClaim.ID = uuid.NewString()
	futureClaim.ObservedAt = time.Now().UTC().Add(3 * time.Minute)
	if accepted, unresolved, err := repo.WriteEvidenceBatch(bound, agentID, newSerial,
		[]entity.Observation{futureClaim}); err != nil || accepted != 0 || unresolved != 1 {
		t.Fatalf("future observation outlived its sender SVID: accepted=%d unresolved=%d err=%v",
			accepted, unresolved, err)
	}
	inTenant(ctx, t, pool, tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE agent_identities
			SET not_after=clock_timestamp()+interval '1 hour'
			WHERE tenant_id=$1 AND agent_id=$2 AND serial=$3`, tenant.ID, agentID, newSerial)
		return err
	})
	if _, _, err := repo.WriteEvidenceBatch(bound, agentID, oldSerial,
		[]entity.Observation{claim}); err != ErrEvidenceIdentityInactive {
		t.Fatalf("retired certificate authored new mapping: %v", err)
	}
	if accepted, unresolved, err := repo.WriteEvidenceBatch(bound, agentID,
		newSerial, []entity.Observation{claim}); err != nil || accepted != 1 || unresolved != 0 {
		t.Fatalf("fresh certificate cannot author: accepted=%d unresolved=%d err=%v",
			accepted, unresolved, err)
	}
	resolved, err = repo.ResolveAlias(bound,
		entity.Scope{TenantID: tenant.ID, ContextID: contextID}, alias)
	if err != nil || resolved.Status != entity.Resolved || resolved.EntityID != anchorID {
		t.Fatalf("fresh evidence did not resolve: %+v err=%v", resolved, err)
	}
	batched, err = repo.ResolveAddresses(bound,
		entity.Scope{TenantID: tenant.ID, ContextID: contextID}, []string{"10.42.0.1"})
	if err != nil || batched["10.42.0.1"].Status != entity.Resolved ||
		batched["10.42.0.1"].EntityID != anchorID {
		t.Fatalf("fresh evidence missing from batched path join: %+v err=%v", batched, err)
	}
	if _, _, err := identities.RevokeAgent(ctx, tenant.ID, agentID, "operator"); err != nil {
		t.Fatal(err)
	}
	if revoked, err := identities.IsAgentRevoked(ctx, tenant.ID, agentID); err != nil || !revoked {
		t.Fatalf("operator revocation did not supersede evidence retirement: %v, %v", revoked, err)
	}
}

// A delete must acquire the agent-row lock before its serial update. If it
// updates serials first, an issuer holding a share lock can insert a new SVID
// between that update and the eventual agent-row DELETE.
func TestEntityDeleteIncludesSerialIssuedWhileItWaits(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tenant, err := NewTenants(pool).Create(ctx,
		fmt.Sprintf("entity-delete-race-%d", time.Now().UnixNano()), "Entity Delete Race")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.ID); err != nil {
			t.Errorf("remove entity delete race tenant: %v", err)
		}
	}()
	agentID := uuid.NewString()
	inTenant(ctx, t, pool, tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (Agents{}).Register(ctx, sc, agentID, "entity-race-agent",
			"entity-host", "test", crypto.AgentSPIFFEID(tenant.ID, agentID), nil)
		return err
	})
	serial := strings.ReplaceAll(uuid.NewString(), "-", "")
	bound := tenancy.WithTenant(ctx, tenancy.ID(tenant.ID))
	backendPID := make(chan int, 1)
	deleted := make(chan error, 1)
	err = tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
		var held int
		if err := sc.Q.QueryRow(ctx, `SELECT 1 FROM agents
			WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant.ID, agentID).Scan(&held); err != nil {
			return err
		}
		go func() {
			deleted <- tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
				var pid int
				if err := sc.Q.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
					return err
				}
				backendPID <- pid
				return (Agents{}).Delete(ctx, sc, agentID)
			})
		}()
		var pid int
		select {
		case pid = <-backendPID:
		case err := <-deleted:
			return fmt.Errorf("delete finished before serial race: %v", err)
		case <-time.After(3 * time.Second):
			return fmt.Errorf("delete did not reach the database")
		}
		deadline := time.Now().Add(3 * time.Second)
		for {
			var waiting bool
			if err := pool.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock'
				AND query LIKE '%agents%',false)
				FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waiting); err != nil {
				return err
			}
			if waiting {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("delete never waited on the agent-row lock")
			}
			time.Sleep(10 * time.Millisecond)
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO agent_identities
			(tenant_id,agent_id,spiffe_id,serial,not_after)
			VALUES ($1,$2,$3,$4,statement_timestamp()+interval '1 hour')`,
			tenant.ID, agentID, crypto.EntitySPIFFEID(tenant.ID, agentID), serial)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-deleted; err != nil {
		t.Fatal(err)
	}
	var revoked bool
	if err := tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT revoked_at IS NOT NULL
			FROM agent_identities WHERE tenant_id=$1 AND agent_id=$2 AND serial=$3`,
			tenant.ID, agentID, serial).Scan(&revoked)
	}); err != nil || !revoked {
		t.Fatalf("concurrent delete left new SVID live: revoked=%v err=%v", revoked, err)
	}
}
