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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestEntityEvidenceCannotRepublishBeforeErasureCutoff(t *testing.T) {
	ctx := t.Context()
	pool := setup(ctx, t)
	defer pool.Close()
	registry := NewEntityRegistry(pool)
	const agentID = "neutral-site-agent"
	area, site, vrf, anchor, observationID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	tenants := []string{}
	serials := []string{}
	defer func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	}()
	for lane := range 2 {
		tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("evidence-replay-%d-%d", time.Now().UnixNano(), lane), "Evidence replay")
		if err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, tenant.ID)
		serial := strings.ReplaceAll(uuid.NewString(), "-", "")
		serials = append(serials, serial)
		if err := NewAgentIdentities(pool).Record(ctx, tenant.ID, agentID, crypto.EntitySPIFFEID(tenant.ID, agentID), serial, time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		inTenant(ctx, t, pool, tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'site','vrf')`, tenant.ID, area, site, vrf); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'site','neutral-site')`, tenant.ID, area, anchor); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES($1,$2,$3)`, tenant.ID, agentID, area); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id) VALUES($1,$2,'agent_site',$2,$3,$4)`, tenant.ID, agentID, area, anchor)
			return err
		})
	}
	var observed time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&observed); err != nil {
		t.Fatal(err)
	}
	observation := entity.Observation{ID: observationID, Source: entity.SourceKey{AgentID: agentID, Kind: entity.AgentSite, SourceRef: agentID},
		Alias: entity.AliasKey{Kind: entity.AgentSiteAlias, Value: agentID}, SourceRef: "agent:label:site", ObservedAt: observed, AgentAddresses: []netip.Addr{netip.MustParseAddr("10.42.0.1")}}
	for lane, tenant := range tenants {
		if accepted, unresolved, err := registry.WriteEvidenceBatch(tenancy.WithTenant(ctx, tenancy.ID(tenant)), agentID, serials[lane], []entity.Observation{observation}); err != nil || accepted != 1 || unresolved != 0 {
			t.Fatal("seed evidence refused", accepted, unresolved, err)
		}
	}
	// This is the same epoch mutation used by subject/source erasure. Only the
	// matched metadata row is removed; its neutral source and site stay live.
	inTenant(ctx, t, pool, tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		if err := sourceepoch.PrepareInScope(ctx, sc); err != nil {
			return err
		}
		if err := tenancy.LockTenantAuditStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
			return err
		}
		if err := sourceepoch.InvalidateSourceGenerationInScope(ctx, sc); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `DELETE FROM entity_evidence WHERE observation_id=$1`, observationID); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `UPDATE flow_snapshot_epochs SET generation=generation+1,invalidating=false,transition_token=NULL,observation_erasing=false WHERE tenant_id=$1`, tenants[0])
		return err
	})
	accepted, unresolved, err := registry.WriteEvidenceBatch(tenancy.WithTenant(ctx, tenancy.ID(tenants[0])), agentID, serials[0], []entity.Observation{observation})
	if err != nil || accepted != 0 || unresolved != 1 {
		t.Errorf("pre-erasure payload was allowed to repopulate deleted evidence: accepted=%d unresolved=%d err=%v", accepted, unresolved, err)
	}
	for lane, tenant := range tenants {
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var super, bypass bool
			if err := sc.Q.QueryRow(ctx, `SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&super, &bypass); err != nil {
				return err
			}
			if super || bypass {
				return errors.New("evidence proof did not use a least-privilege RLS role")
			}
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_evidence`).Scan(&count); err != nil {
				return err
			}
			if count != lane {
				return fmt.Errorf("tenant %d sees %d evidence rows, want %d", lane, count, lane)
			}
			return nil
		})
	}
	fresh := observation
	fresh.ID = uuid.NewString()
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&fresh.ObservedAt); err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range tenants {
		if accepted, unresolved, err := registry.WriteEvidenceBatch(tenancy.WithTenant(ctx, tenancy.ID(tenant)), agentID, serials[lane], []entity.Observation{fresh}); err != nil || accepted != 1 || unresolved != 0 {
			t.Fatal("fresh evidence or healthy sibling was blocked", accepted, unresolved, err)
		}
	}
	if _, _, err := registry.WriteEvidenceBatch(tenancy.WithTenant(ctx, tenancy.ID(tenants[1])), agentID, serials[0], []entity.Observation{fresh}); !errors.Is(err, ErrEvidenceIdentityInactive) {
		t.Fatal("foreign issued serial crossed the tenant boundary", err)
	}
}
