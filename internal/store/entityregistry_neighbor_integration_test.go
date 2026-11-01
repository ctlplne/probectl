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
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// An LLDP frame can form a physical edge only after both endpoints are
// independently known in the same tenant/context. The original ports and
// chassis stay on the evidence row; a duplicate remote IP cannot pick a
// winner, and a replay cannot change the original physical endpoint.
func TestPhysicalNeighborRequiresUniqueScopedSNMPDevices(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "neighbor-a-"+suffix, "Neighbor A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "neighbor-b-"+suffix, "Neighbor B")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`,
			[]string{a.ID, b.ID}); err != nil {
			t.Errorf("remove neighbor tenants: %v", err)
		}
	}()
	const agentID = "snmp-collector"
	contextID := uuid.NewString() // deliberately identical in both tenants
	repo := NewEntityRegistry(pool)
	type fixture struct {
		tenant, serial, localID, remoteID, interfaceID string
		neighbor                                       entity.Observation
	}
	fixtures := make([]fixture, 0, 2)
	for _, tenantID := range []string{a.ID, b.ID} {
		f := fixture{tenant: tenantID, serial: strings.ReplaceAll(uuid.NewString(), "-", ""),
			localID: uuid.NewString(), remoteID: uuid.NewString()}
		if err := NewAgentIdentities(pool).Record(ctx, tenantID, agentID,
			crypto.EntitySPIFFEID(tenantID, agentID), f.serial, time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		inTenant(ctx, t, pool, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
                VALUES ($1,$2,$3,$4,$3::text,$4::text)`,
				tenantID, contextID, uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
				(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`, tenantID, agentID, contextID); err != nil {
				return err
			}
			for _, target := range []struct{ address, id string }{{"10.42.0.1", f.localID}, {"10.42.0.2", f.remoteID}} {
				if _, err := sc.Q.Exec(ctx, `INSERT INTO entities
					(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'device',$4)`,
					tenantID, contextID, target.id, target.address); err != nil {
					return err
				}
				if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
					(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
					VALUES ($1,$2,'device_target',$3,$4,$5)`, tenantID, agentID,
					target.address, contextID, target.id); err != nil {
					return err
				}
			}
			return nil
		})
		at := time.Now().UTC()
		remote := entity.Observation{ID: uuid.NewString(), Source: entity.SourceKey{AgentID: agentID,
			Kind: entity.DeviceTarget, SourceRef: "10.42.0.2"}, Alias: entity.AliasKey{
			Kind: entity.AddressAlias, Value: "10.42.0.2"}, SourceRef: "snmp:configured-target", ObservedAt: at}
		localIf := entity.Observation{ID: uuid.NewString(), Source: entity.SourceKey{AgentID: agentID,
			Kind: entity.DeviceTarget, SourceRef: "10.42.0.1"}, Alias: entity.AliasKey{
			Kind: entity.SNMPInterfaceAlias, Value: "4294967295"},
			SourceRef: "snmp:ifIndex:4294967295", ObservedAt: at}
		neighbor := entity.Observation{ID: uuid.NewString(), Source: localIf.Source,
			Alias:     entity.AliasKey{Kind: entity.PhysicalNeighborAlias, Value: "neighbor:abc123"},
			SourceRef: "neighbor:abc123", ObservedAt: at, NeighborProtocol: "lldp",
			NeighborLocalIfIndex: 4294967295, NeighborLocalPortID: "xe-0/0/7",
			NeighborRemotePortID: "xe-0/0/8", NeighborChassisID: "00:11:22:33:44:55",
			NeighborDeviceName: "edge-b", NeighborAddress: "10.42.0.2"}
		writeCtx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
		if accepted, unresolved, err := repo.WriteEvidenceBatch(writeCtx, agentID, f.serial,
			[]entity.Observation{remote, localIf, neighbor}); err != nil || accepted != 3 || unresolved != 0 {
			t.Fatalf("write %s: accepted=%d unresolved=%d err=%v", tenantID, accepted, unresolved, err)
		}
		scope := entity.Scope{TenantID: tenantID, ContextID: contextID}
		resolved, err := repo.ResolveAlias(writeCtx, scope, localIf.Alias)
		if err != nil || resolved.Status != entity.Resolved || len(resolved.Candidates) != 1 ||
			resolved.Candidates[0].EntityKind != entity.Interface {
			t.Fatalf("interface %s: %+v %v", tenantID, resolved, err)
		}
		interfaceID := resolved.EntityID
		f.interfaceID, f.neighbor = interfaceID, neighbor
		links, err := repo.ListEntityLinks(writeCtx, scope, interfaceID, "", 100)
		if err != nil || len(links.Items) != 2 {
			t.Fatalf("neighbor links %s: %+v %v", tenantID, links, err)
		}
		physical := 0
		for _, link := range links.Items {
			if link.Kind == "physical" {
				physical++
				if link.FromEntityID != interfaceID || link.ToEntityID != f.remoteID {
					t.Fatalf("physical edge crossed identity: %+v", link)
				}
			}
		}
		if physical != 1 {
			t.Fatalf("physical edges=%d, want one", physical)
		}
		evidence, err := repo.ListEntityEvidence(writeCtx, scope, interfaceID, "", 100)
		if err != nil || len(evidence.Items) != 2 {
			t.Fatalf("interface evidence: %+v %v", evidence, err)
		}
		originalFound := false
		physicalEvidenceID := ""
		for _, item := range evidence.Items {
			if item.Alias.Kind != entity.PhysicalNeighborAlias {
				continue
			}
			originalFound = true
			physicalEvidenceID = item.ID
			if !item.Current || item.NeighborProtocol != "lldp" ||
				item.NeighborLocalIfIndex != 4294967295 ||
				item.NeighborLocalPortID != "xe-0/0/7" ||
				item.NeighborRemotePortID != "xe-0/0/8" ||
				item.NeighborChassisID != "00:11:22:33:44:55" ||
				item.NeighborDeviceName != "edge-b" ||
				item.NeighborAddress != "10.42.0.2" {
				t.Fatalf("original physical evidence changed: %+v", item)
			}
		}
		if !originalFound {
			t.Fatal("physical link lost its original LLDP evidence")
		}
		duplicateErr := tenancy.InTenant(writeCtx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_links
				(tenant_id,context_id,id,from_entity_id,to_entity_id,
				 evidence_id,kind,observed_at)
				VALUES ($1,$2,$3,$4,$5,$6,'physical',clock_timestamp())`,
				tenantID, contextID, uuid.NewString(), interfaceID, f.localID,
				physicalEvidenceID)
			return err
		})
		var pgErr *pgconn.PgError
		if !errors.As(duplicateErr, &pgErr) || pgErr.Code != "23505" {
			t.Fatalf("one LLDP observation created two physical endpoints: %v", duplicateErr)
		}
		if accepted, unresolved, err := repo.WriteEvidenceBatch(writeCtx, agentID, f.serial,
			[]entity.Observation{neighbor}); err != nil || accepted != 1 || unresolved != 0 {
			t.Fatalf("idempotent neighbor retry: %d %d %v", accepted, unresolved, err)
		}
		changed := neighbor
		changed.NeighborRemotePortID = "different"
		if _, _, err := repo.WriteEvidenceBatch(writeCtx, agentID, f.serial,
			[]entity.Observation{changed}); !errors.Is(err, entity.ErrConflictingEvidence) {
			t.Fatalf("neighbor UUID changed endpoint: %v", err)
		}
		changed = neighbor
		changed.NeighborAddress = "10.42.0.99"
		if _, _, err := repo.WriteEvidenceBatch(writeCtx, agentID, f.serial,
			[]entity.Observation{changed}); !errors.Is(err, entity.ErrConflictingEvidence) {
			t.Fatalf("neighbor UUID changed remote management address: %v", err)
		}
		// The local LLDP row can outlive the remote SNMP observation. Its
		// physical alias must stop resolving while that independent support
		// is stale, even though the stored edge and local SVID still exist.
		inTenant(ctx, t, pool, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE entity_evidence
				SET expires_at=observed_at+interval '1 millisecond'
				WHERE tenant_id=$1 AND context_id=$2 AND observation_id=$3`,
				tenantID, contextID, remote.ID)
			return err
		})
		time.Sleep(10 * time.Millisecond)
		stale, err := repo.ResolveAlias(writeCtx, scope, neighbor.Alias)
		if err != nil || stale.Status != entity.Unresolved {
			t.Fatalf("expired remote SNMP kept physical alias current: %+v %v", stale, err)
		}
		stalePage, err := repo.ListEntityEvidence(writeCtx, scope, interfaceID, "", 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range stalePage.Items {
			if item.ObservationID == neighbor.ID && item.Current {
				t.Fatal("expired remote SNMP left local LLDP current")
			}
		}
		inTenant(ctx, t, pool, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE entity_evidence
				SET expires_at=observed_at+interval '24 hours'
				WHERE tenant_id=$1 AND context_id=$2 AND observation_id=$3`,
				tenantID, contextID, remote.ID)
			return err
		})
		fixtures = append(fixtures, f)
	}
	if fixtures[0].remoteID == fixtures[1].remoteID {
		t.Fatal("paired tenants shared a canonical device")
	}
	// One more current SNMP source claims the same management IP inside A's
	// context. A new LLDP observation must now be unresolved, not linked to
	// either possible router.
	f := fixtures[0]
	otherID := uuid.NewString()
	inTenant(ctx, t, pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entities
			(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'device','duplicate-ip')`,
			f.tenant, contextID, otherID); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
			(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
			VALUES ($1,$2,'device_target','10.42.0.3',$3,$4)`,
			f.tenant, agentID, contextID, otherID)
		return err
	})
	dup := entity.Observation{ID: uuid.NewString(), Source: entity.SourceKey{AgentID: agentID,
		Kind: entity.DeviceTarget, SourceRef: "10.42.0.3"}, Alias: entity.AliasKey{
		Kind: entity.AddressAlias, Value: "10.42.0.2"}, SourceRef: "snmp:interface-address", ObservedAt: time.Now().UTC()}
	writeCtx := tenancy.WithTenant(ctx, tenancy.ID(f.tenant))
	if accepted, _, err := repo.WriteEvidenceBatch(writeCtx, agentID, f.serial, []entity.Observation{dup}); err != nil || accepted != 1 {
		t.Fatalf("seed conflicting remote IP: %d %v", accepted, err)
	}
	conflictedScope := entity.Scope{TenantID: f.tenant, ContextID: contextID}
	prior, err := repo.ResolveAlias(writeCtx, conflictedScope, f.neighbor.Alias)
	if err != nil || prior.Status != entity.Unresolved {
		t.Fatalf("competing remote device kept old physical alias current: %+v %v", prior, err)
	}
	conflictedPage, err := repo.ListEntityEvidence(writeCtx, conflictedScope, f.interfaceID, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range conflictedPage.Items {
		if item.ObservationID == f.neighbor.ID && item.Current {
			t.Fatal("competing remote device left old LLDP evidence current")
		}
	}
	ambiguous := entity.Observation{ID: uuid.NewString(), Source: entity.SourceKey{AgentID: agentID,
		Kind: entity.DeviceTarget, SourceRef: "10.42.0.1"}, Alias: entity.AliasKey{
		Kind: entity.PhysicalNeighborAlias, Value: "neighbor:def456"}, SourceRef: "neighbor:def456",
		ObservedAt: time.Now().UTC(), NeighborProtocol: "cdp", NeighborLocalIfIndex: 4294967295,
		NeighborLocalPortID: "xe-0/0/7", NeighborRemotePortID: "Ethernet1",
		NeighborDeviceName: "unknown", NeighborAddress: "10.42.0.2"}
	if accepted, unresolved, err := repo.WriteEvidenceBatch(writeCtx, agentID, f.serial,
		[]entity.Observation{ambiguous}); err != nil || accepted != 0 || unresolved != 1 {
		t.Fatalf("conflicting remote selected a physical edge: %d %d %v", accepted, unresolved, err)
	}
	// Deletion cascades the physical edge, but preserves the local LLDP row
	// for historical citation. A retry of that exact UUID must acknowledge
	// the original observation without binding it to the replacement router
	// now claiming the same management address.
	inTenant(ctx, t, pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entities
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, f.tenant, contextID, f.remoteID)
		return err
	})
	if accepted, unresolved, err := repo.WriteEvidenceBatch(writeCtx, agentID, f.serial,
		[]entity.Observation{f.neighbor}); err != nil || accepted != 1 || unresolved != 0 {
		t.Fatalf("orphaned LLDP retry changed or failed: accepted=%d unresolved=%d err=%v",
			accepted, unresolved, err)
	}
	changed := f.neighbor
	changed.NeighborRemotePortID = "different-after-delete"
	if _, _, err := repo.WriteEvidenceBatch(writeCtx, agentID, f.serial,
		[]entity.Observation{changed}); !errors.Is(err, entity.ErrConflictingEvidence) {
		t.Fatalf("orphaned LLDP UUID accepted changed metadata: %v", err)
	}
	scope := entity.Scope{TenantID: f.tenant, ContextID: contextID}
	page, err := repo.ListEntityEvidence(writeCtx, scope, f.interfaceID, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	var retained, current bool
	for _, row := range page.Items {
		if row.ObservationID == f.neighbor.ID {
			retained, current = true, row.Current
		}
	}
	if !retained || current {
		t.Fatalf("deleted remote left current or missing LLDP citation: retained=%v current=%v", retained, current)
	}
	links, err := repo.ListEntityLinks(writeCtx, scope, f.interfaceID, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range links.Items {
		if link.Kind == "physical" {
			t.Fatalf("orphaned LLDP replay reattached to a different device: %+v", link)
		}
	}
	resolution, err := repo.ResolveAlias(writeCtx, scope, f.neighbor.Alias)
	if err != nil || resolution.Status != entity.Unresolved {
		t.Fatalf("orphaned physical-neighbor alias stayed current: %+v %v", resolution, err)
	}
}
