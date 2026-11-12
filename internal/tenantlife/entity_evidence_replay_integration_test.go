// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package tenantlife

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestEntityEvidenceSubjectErasureRejectsLateSenderReplay(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := t.Context()
	stamp := fmt.Sprint(time.Now().UnixNano())
	tenants := []string{mkTenant(t, pool, "evidence-replay-handler-a-"+stamp), mkTenant(t, pool, "evidence-replay-handler-b-"+stamp)}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	area, site, vrf, anchor, observationID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	const sender = "neutral-site-collector"
	serials := make([]string, len(tenants))
	for lane, tenant := range tenants {
		serials[lane] = strings.ReplaceAll(uuid.NewString(), "-", "")
		if err := store.NewAgentIdentities(pool).Record(ctx, tenant, sender, crypto.EntitySPIFFEID(tenant, sender), serials[lane], time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'neutral site','neutral VRF')`, tenant, area, site, vrf); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'site','neutral site')`, tenant, area, anchor); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES($1,$2,$3)`, tenant, sender, area); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id) VALUES($1,$2,'agent_site',$2,$3,$4)`, tenant, sender, area, anchor)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	var observed time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&observed); err != nil {
		t.Fatal(err)
	}
	claim := entity.Observation{ID: observationID, Source: entity.SourceKey{AgentID: sender, Kind: entity.AgentSite, SourceRef: sender}, Alias: entity.AliasKey{Kind: entity.AgentSiteAlias, Value: "neutral-site"}, SourceRef: "agent:label:site", ObservedAt: observed, AgentAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.7")}}
	registry := store.NewEntityRegistry(pool)
	for lane, tenant := range tenants {
		if accepted, unresolved, err := writeEntityEvidenceBatchForTest(tenancy.WithTenant(ctx, tenancy.ID(tenant)), registry, sender, serials[lane], []entity.Observation{claim}); err != nil || accepted != 1 || unresolved != 0 {
			t.Fatal("issued source seed refused", accepted, unresolved, err)
		}
	}
	sink := func(ctx context.Context, actor, action, target string, data map[string]any) error {
		_, err := audit.ProviderAppend(ctx, pool, actor, action, target, data)
		return err
	}
	engine := New(pool, nil, nil, nil, sink, "fixture backups expire", nil)
	report, err := engine.EraseSubject(ctx, tenants[0], "192.0.2.7", "privacy-admin", "reject late source replay")
	if err != nil || !report.Complete {
		t.Fatal("subject handler did not complete", err, report)
	}
	plane := subjectPlanesByName(report.Planes)["postgres:entity_evidence"]
	if plane.Deleted != 1 || plane.Remaining != 0 {
		t.Fatal("subject handler did not erase the original personal metadata", plane)
	}
	accepted, unresolved, err := writeEntityEvidenceBatchForTest(tenancy.WithTenant(ctx, tenancy.ID(tenants[0])), registry, sender, serials[0], []entity.Observation{claim})
	if err != nil || accepted != 0 || unresolved != 1 {
		t.Errorf("full subject erasure allowed old sender data back: accepted=%d unresolved=%d err=%v", accepted, unresolved, err)
	}
	for lane, tenant := range tenants {
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_evidence`).Scan(&count); err != nil {
				return err
			}
			if count != lane {
				return fmt.Errorf("tenant %d has %d metadata rows, want %d", lane, count, lane)
			}
			var bindings int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_source_contexts`).Scan(&bindings); err != nil {
				return err
			}
			if bindings != 1 {
				return fmt.Errorf("source was removed instead of refusing old payloads: %d", bindings)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	fresh := claim
	fresh.ID = uuid.NewString()
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&fresh.ObservedAt); err != nil {
		t.Fatal(err)
	}
	if accepted, unresolved, err := writeEntityEvidenceBatchForTest(tenancy.WithTenant(ctx, tenancy.ID(tenants[0])), registry, sender, serials[0], []entity.Observation{fresh}); err != nil || accepted != 1 || unresolved != 0 {
		t.Fatal("fresh post-erasure collection was blocked", accepted, unresolved, err)
	}
}

// writeEntityEvidenceBatchForTest retains the legacy assertion vocabulary
// while exercising the shipped committed receipt API.
func writeEntityEvidenceBatchForTest(ctx context.Context, registry *store.EntityRegistry, agent, serial string, claims []entity.Observation) (int, int, error) {
	receipt, err := registry.WriteEvidenceBatchReceipt(ctx, agent, serial, claims)
	return receipt.Accepted, receipt.Unresolved, err
}
