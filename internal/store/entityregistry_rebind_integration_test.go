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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// An unchanged operator binding is idempotent. Changing its anchor starts a
// new authority interval; changing back cannot revive an old address row.
func TestEntityRebindDoesNotReviveEarlierEvidence(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tenant, err := NewTenants(pool).Create(ctx,
		fmt.Sprintf("entity-rebind-%d", time.Now().UnixNano()), "Entity Rebind")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.ID); err != nil {
			t.Errorf("remove entity rebind fixture: %v", err)
		}
	}()
	agentID := uuid.NewString()
	serial := strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := NewAgentIdentities(pool).Record(ctx, tenant.ID, agentID,
		crypto.EntitySPIFFEID(tenant.ID, agentID), serial,
		time.Now().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	repo := NewEntityRegistry(pool)
	var scope entity.Scope
	var anchorID, replacementID string
	source := entity.SourceKey{AgentID: agentID, Kind: entity.DeviceTarget,
		SourceRef: "10.42.0.1"}
	inTenant(ctx, t, pool, tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := (Agents{}).Register(ctx, sc, agentID, "entity-rebind-agent",
			"fixture", "", crypto.AgentSPIFFEID(tenant.ID, agentID), nil); err != nil {
			return err
		}
		created, err := repo.CreateEntityContext(ctx, sc, "West DC", "Customer A")
		if err != nil {
			return err
		}
		scope = entity.Scope{TenantID: tenant.ID, ContextID: created.ContextID}
		anchor, err := repo.CreateCanonicalEntityWithNetwork(ctx, sc, scope.ContextID,
			entity.Device, "router", "")
		if err != nil {
			return err
		}
		anchorID = anchor.ID
		replacement, err := repo.CreateCanonicalEntityWithNetwork(ctx, sc, scope.ContextID,
			entity.Device, "replacement router", "")
		if err != nil {
			return err
		}
		replacementID = replacement.ID
		return repo.AssignEntitySource(ctx, sc, source, scope.ContextID, anchorID)
	})
	bound := tenancy.WithTenant(ctx, tenancy.ID(tenant.ID))
	alias := entity.AliasKey{Kind: entity.AddressAlias, Value: "10.42.0.1"}
	old := entity.Observation{ID: uuid.NewString(), Source: source, Alias: alias,
		SourceRef: "snmp:target", ObservedAt: time.Now().UTC()}
	if accepted, unresolved, err := repo.WriteEvidenceBatch(bound, agentID, serial,
		[]entity.Observation{old}); err != nil || accepted != 1 || unresolved != 0 {
		t.Fatalf("initial evidence: accepted=%d unresolved=%d err=%v", accepted, unresolved, err)
	}
	if got, err := repo.ResolveAlias(bound, scope, alias); err != nil ||
		got.Status != entity.Resolved || got.EntityID != anchorID {
		t.Fatalf("initial current resolution: %+v err=%v", got, err)
	}
	inTenant(ctx, t, pool, tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
		return repo.AssignEntitySource(ctx, sc, source, scope.ContextID, anchorID)
	})
	if got, err := repo.ResolveAlias(bound, scope, alias); err != nil ||
		got.Status != entity.Resolved || got.EntityID != anchorID {
		t.Fatalf("identical assignment hid current evidence: %+v err=%v", got, err)
	}
	// Ensure the new assigned_at is strictly after the old observed_at even
	// on a database clock with coarse precision.
	time.Sleep(2 * time.Millisecond)
	inTenant(ctx, t, pool, tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
		return repo.AssignEntitySource(ctx, sc, source, scope.ContextID, replacementID)
	})
	inTenant(ctx, t, pool, tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
		return repo.AssignEntitySource(ctx, sc, source, scope.ContextID, anchorID)
	})
	if got, err := repo.ResolveAlias(bound, scope, alias); err != nil ||
		got.Status != entity.Unresolved {
		t.Fatalf("old evidence revived after rebind: %+v err=%v", got, err)
	}
	if batch, err := repo.ResolveAddresses(bound, scope, []string{alias.Value}); err != nil ||
		batch[alias.Value].Status != entity.Unresolved {
		t.Fatalf("batched resolver revived old evidence: %+v err=%v", batch, err)
	}
	page, err := repo.ListEntityEvidence(bound, scope, anchorID, "", 10)
	if err != nil || len(page.Items) != 1 || page.Items[0].Current {
		t.Fatalf("historical evidence mislabeled current: %+v err=%v", page, err)
	}
	if accepted, unresolved, err := repo.WriteEvidenceBatch(bound, agentID, serial,
		[]entity.Observation{old}); err != nil || accepted != 1 || unresolved != 0 {
		t.Fatalf("exact historical UUID retry: accepted=%d unresolved=%d err=%v", accepted, unresolved, err)
	}
	changed := old
	changed.Alias.Value = "10.42.0.99"
	if _, _, err := repo.WriteEvidenceBatch(bound, agentID, serial,
		[]entity.Observation{changed}); !errors.Is(err, entity.ErrConflictingEvidence) {
		t.Fatalf("rebound source accepted changed historical UUID: %v", err)
	}
	page, err = repo.ListEntityEvidence(bound, scope, anchorID, "", 10)
	if err != nil || len(page.Items) != 1 || page.Items[0].Current {
		t.Fatalf("retry revived or duplicated old evidence: %+v err=%v", page, err)
	}
	fresh := old
	fresh.ID = uuid.NewString()
	fresh.ObservedAt = time.Now().UTC()
	if accepted, unresolved, err := repo.WriteEvidenceBatch(bound, agentID, serial,
		[]entity.Observation{fresh}); err != nil || accepted != 1 || unresolved != 0 {
		t.Fatalf("post-rebind evidence: accepted=%d unresolved=%d err=%v", accepted, unresolved, err)
	}
	if got, err := repo.ResolveAlias(bound, scope, alias); err != nil ||
		got.Status != entity.Resolved || got.EntityID != anchorID {
		t.Fatalf("new evidence did not restore current identity: %+v err=%v", got, err)
	}
	inTenant(ctx, t, pool, tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
			SET expires_at=clock_timestamp()
			WHERE tenant_id=$1 AND agent_id=$2 AND source_kind=$3 AND source_ref=$4`,
			tenant.ID, agentID, string(source.Kind), source.SourceRef)
		return err
	})
	if accepted, unresolved, err := repo.WriteEvidenceBatch(bound, agentID, serial,
		[]entity.Observation{fresh}); err != nil || accepted != 1 || unresolved != 0 {
		t.Fatalf("exact UUID retry after expiry: accepted=%d unresolved=%d err=%v",
			accepted, unresolved, err)
	}
	changed = fresh
	changed.Alias.Value = "10.42.0.99"
	if _, _, err := repo.WriteEvidenceBatch(bound, agentID, serial,
		[]entity.Observation{changed}); !errors.Is(err, entity.ErrConflictingEvidence) {
		t.Fatalf("expired source accepted changed UUID: %v", err)
	}
	if got, err := repo.ResolveAlias(bound, scope, alias); err != nil ||
		got.Status != entity.Unresolved {
		t.Fatalf("expiry retry revived canonical identity: %+v err=%v", got, err)
	}
}
