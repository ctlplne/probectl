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

func TestAgentSiteEvidenceRequiresTenantAndOperatorContext(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "agent-site-a-"+suffix, "Agent site A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "agent-site-b-"+suffix, "Agent site B")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`,
			[]string{a.ID, b.ID}); err != nil {
			t.Errorf("remove site fixture tenants: %v", err)
		}
	}()
	const agentID = "canary-agent"
	contextID := uuid.NewString() // same UUID and label in both tenants
	alias := entity.AliasKey{Kind: entity.AgentSiteAlias, Value: "dub-1"}
	repo := NewEntityRegistry(pool)
	resolvedIDs := make(map[string]string)
	for _, tenantID := range []string{a.ID, b.ID} {
		serial := strings.ReplaceAll(uuid.NewString(), "-", "")
		if err := NewAgentIdentities(pool).Record(ctx, tenantID, agentID,
			crypto.EntitySPIFFEID(tenantID, agentID), serial, time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		siteID := uuid.NewString()
		inTenant(ctx, t, pool, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
                VALUES ($1,$2,$3,$4,$3::text,$4::text)`,
				tenantID, contextID, siteID, uuid.NewString()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities
				(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'site','Dublin')`,
				tenantID, contextID, siteID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
				(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`, tenantID, agentID, contextID); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
				(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
				VALUES ($1,$2,'agent_site',$2,$3,$4)`, tenantID, agentID, contextID, siteID)
			return err
		})
		claim := entity.Observation{ID: uuid.NewString(), Source: entity.SourceKey{
			AgentID: agentID, Kind: entity.AgentSite, SourceRef: agentID},
			Alias: alias, SourceRef: "agent:label:site", ObservedAt: time.Now().UTC()}
		writeCtx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
		if accepted, unresolved, err := repo.WriteEvidenceBatch(writeCtx, agentID, serial,
			[]entity.Observation{claim}); err != nil || accepted != 1 || unresolved != 0 {
			t.Fatalf("agent-site claim %s: %d/%d %v", tenantID, accepted, unresolved, err)
		}
		got, err := repo.ResolveAlias(writeCtx,
			entity.Scope{TenantID: tenantID, ContextID: contextID}, alias)
		if err != nil || got.Status != entity.Resolved || got.EntityID != siteID ||
			len(got.Candidates) != 1 || got.Candidates[0].EntityKind != entity.Site {
			t.Fatalf("agent-site identity %s: %+v %v", tenantID, got, err)
		}
		resolvedIDs[tenantID] = got.EntityID
	}
	if resolvedIDs[a.ID] == resolvedIDs[b.ID] {
		t.Fatal("identical site labels merged across tenants")
	}
	otherContext := uuid.NewString()
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
			(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
                VALUES ($1,$2,$3,$4,$3::text,$4::text)`,
			a.ID, otherContext, uuid.NewString(), uuid.NewString())
		return err
	})
	wrong, err := repo.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
		entity.Scope{TenantID: a.ID, ContextID: otherContext}, alias)
	if err != nil || wrong.Status != entity.Unresolved {
		t.Fatalf("site label crossed routing context: %+v %v", wrong, err)
	}
}
