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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type assessmentTopologyFixture struct {
	tenant, context, agent, serial, local, remote string
	refs                                          []ReportPhysicalLinkRef
}

func seedAssessmentTopology(t *testing.T, pool *pgxpool.Pool, contextID string) assessmentTopologyFixture {
	t.Helper()
	tenant, err := NewTenants(pool).Create(t.Context(), "assessment-graph-"+uuid.NewString(), "assessment graph")
	if err != nil {
		t.Fatal(err)
	}
	f := assessmentTopologyFixture{tenant: tenant.ID, context: contextID, agent: "assessment-snmp", serial: strings.ReplaceAll(uuid.NewString(), "-", ""), local: uuid.NewString(), remote: uuid.NewString()}
	t.Cleanup(func() {
		_, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, f.tenant)
		if err != nil {
			t.Error(err)
		}
	})
	if err := NewAgentIdentities(pool).Record(t.Context(), f.tenant, f.agent, crypto.EntitySPIFFEID(f.tenant, f.agent), f.serial, time.Now().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	inTenant(t.Context(), t, pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
 VALUES($1,$2,$3,$4,'site','vrf')`, f.tenant, f.context, uuid.NewString(), uuid.NewString()); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,context_id,agent_id) VALUES($1,$2,$3)`, f.tenant, f.context, f.agent); err != nil {
			return err
		}
		for _, member := range []struct{ id, address string }{{f.local, "192.0.2.1"}, {f.remote, "192.0.2.2"}} {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device',$4)`, f.tenant, f.context, member.id, member.address); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,context_id,agent_id,source_kind,source_ref,anchor_entity_id)
 VALUES($1,$2,$3,'device_target',$4,$5)`, f.tenant, f.context, f.agent, member.address, member.id); err != nil {
				return err
			}
		}
		return nil
	})
	at := time.Now().UTC()
	remote := entity.Observation{ID: uuid.NewString(), Source: entity.SourceKey{AgentID: f.agent, Kind: entity.DeviceTarget, SourceRef: "192.0.2.2"}, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "192.0.2.2"}, SourceRef: "snmp:configured-target", ObservedAt: at}
	local := entity.Observation{ID: uuid.NewString(), Source: entity.SourceKey{AgentID: f.agent, Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"}, Alias: entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: "4294967295"}, SourceRef: "snmp:ifIndex:4294967295", ObservedAt: at}
	claims := []entity.Observation{remote, local}
	for n := range 103 {
		alias := fmt.Sprintf("neighbor:%064x", n+1)
		claims = append(claims, entity.Observation{ID: uuid.NewString(), Source: local.Source, Alias: entity.AliasKey{Kind: entity.PhysicalNeighborAlias, Value: alias}, SourceRef: alias, ObservedAt: at,
			NeighborProtocol: "lldp", NeighborLocalIfIndex: 4294967295, NeighborLocalPortID: "xe-0/0/7", NeighborRemotePortID: fmt.Sprintf("xe-0/0/%d", n), NeighborChassisID: "00:11:22:33:44:55", NeighborDeviceName: "remote", NeighborAddress: "192.0.2.2"})
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(f.tenant))
	for len(claims) > 0 {
		n := min(32, len(claims))
		if accepted, unresolved, err := NewEntityRegistry(pool).WriteEvidenceBatch(ctx, f.agent, f.serial, claims[:n]); err != nil || accepted != n || unresolved != 0 {
			t.Fatal("original graph admission", accepted, unresolved, err)
		}
		claims = claims[n:]
	}
	return f
}

func TestAssessmentTopologyRetainsExactCaptureSupportAndTwoTenantAuthority(t *testing.T) {
	pool := setup(t.Context(), t)
	t.Cleanup(pool.Close)
	contextID := uuid.NewString()
	fixtures := []assessmentTopologyFixture{seedAssessmentTopology(t, pool, contextID), seedAssessmentTopology(t, pool, contextID)}
	registry := NewEntityRegistry(pool)
	read := func(f assessmentTopologyFixture, run func(context.Context, tenancy.Scope) error) error {
		return tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenant)), pool, run)
	}
	for lane := range fixtures {
		f := &fixtures[lane]
		if err := read(*f, func(ctx context.Context, sc tenancy.Scope) error {
			var visible int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_links WHERE kind='physical'`).Scan(&visible); err != nil || visible != 103 {
				t.Fatal("graph RLS leaked or capped originals", visible, err)
			}
			checked := 0
			authorize := func(_ context.Context, record entity.ContextRecord, from, to string) error {
				if record.TenantID != f.tenant || record.ContextID != f.context || from == "" || to != f.remote {
					t.Fatal("graph borrowed endpoint/context authority")
				}
				checked++
				return nil
			}
			items, err := registry.ClientReportPhysicalLinksInScope(ctx, sc, 32<<20, authorize)
			if err != nil || len(items) != 103 || checked != 103 {
				t.Fatal("complete physical receipt population", len(items), checked, err)
			}
			for _, item := range items {
				if item.TenantID != f.tenant || item.Protocol != "lldp" || item.RemoteEvidenceID == "" || item.RemoteObservationID == "" || item.LocalIfIndex != 4294967295 || item.OriginalsDigest == "" {
					t.Fatal("missing original graph evidence", item)
				}
			}
			f.refs = ClientReportPhysicalLinkRefs(items)
			if err := registry.RecheckReportPhysicalLinksInScope(ctx, sc, f.refs, 32<<20); err != nil {
				return err
			}
			denied := errors.New("current topology permission removed")
			if out, err := registry.ClientReportPhysicalLinksInScope(ctx, sc, 32<<20, func(context.Context, entity.ContextRecord, string, string) error { return denied }); !errors.Is(err, denied) || out != nil {
				t.Fatal("graph partially disclosed a denied population", err)
			}
			if out, err := registry.ClientReportPhysicalLinksInScope(ctx, sc, 8192, authorize); err == nil || out != nil {
				t.Fatal("resource admission returned a truncated graph", len(out), err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := read(fixtures[1], func(ctx context.Context, sc tenancy.Scope) error {
		return registry.RecheckReportPhysicalLinksInScope(ctx, sc, fixtures[0].refs, 32<<20)
	}); err == nil {
		t.Fatal("foreign original IDs bypassed graph RLS")
	}
	for _, f := range fixtures {
		// Renew the active identity, then age the original certificate and
		// measurement TTL AFTER capture. The frozen capture remains readable;
		// the ordinary live reader must not turn those old facts into health.
		if err := NewAgentIdentities(pool).Record(t.Context(), f.tenant, f.agent, crypto.EntitySPIFFEID(f.tenant, f.agent), strings.ReplaceAll(uuid.NewString(), "-", ""), time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		inTenant(t.Context(), t, pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `UPDATE entity_evidence SET expires_at=clock_timestamp()-interval '1 microsecond' WHERE tenant_id=$1`, f.tenant); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET not_after=clock_timestamp()-interval '1 microsecond' WHERE tenant_id=$1 AND agent_id=$2 AND serial=$3`, f.tenant, f.agent, f.serial)
			return err
		})
		if err := read(f, func(ctx context.Context, sc tenancy.Scope) error {
			if err := registry.RecheckReportPhysicalLinksInScope(ctx, sc, f.refs, 32<<20); err != nil {
				return err
			}
			out, err := registry.ClientReportPhysicalLinksInScope(ctx, sc, 32<<20, func(context.Context, entity.ContextRecord, string, string) error { return nil })
			if err != nil || len(out) != 0 {
				t.Fatal("historical validity escaped into live graph", len(out), err)
			}
			return nil
		}); err != nil {
			t.Fatal("capture replaced original support or required a fresh TTL", err)
		}
	}
	primary := fixtures[0]
	inTenant(t.Context(), t, pool, primary.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_evidence SET snmp_system_description='changed after capture' WHERE tenant_id=$1 AND id=$2`, primary.tenant, primary.refs[0].RemoteEvidenceID)
		return err
	})
	if err := read(primary, func(ctx context.Context, sc tenancy.Scope) error {
		return registry.RecheckReportPhysicalLinksInScope(ctx, sc, primary.refs, 32<<20)
	}); err == nil {
		t.Fatal("edited original support was replaced by an alias match")
	}
	if err := read(fixtures[1], func(ctx context.Context, sc tenancy.Scope) error {
		return registry.RecheckReportPhysicalLinksInScope(ctx, sc, fixtures[1].refs, 32<<20)
	}); err != nil {
		t.Fatal("sibling original support was affected", err)
	}
	paired := fixtures[1]
	inTenant(t.Context(), t, pool, paired.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET assigned_at=clock_timestamp() WHERE tenant_id=$1`, paired.tenant)
		return err
	})
	if err := read(paired, func(ctx context.Context, sc tenancy.Scope) error {
		return registry.RecheckReportPhysicalLinksInScope(ctx, sc, paired.refs, 32<<20)
	}); err == nil {
		t.Fatal("historical graph revived a replaced current source assignment")
	}
}
