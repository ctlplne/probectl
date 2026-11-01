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

func TestUnanchoredFlowAndBMPRequireCurrentUniqueTenantLocalSNMPSupport(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "entity-inferred-a-"+suffix, "Inferred A")
	if err != nil {
		t.Fatal(err)
	}
	createdTenants := []string{a.ID}
	defer func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, createdTenants); err != nil {
			t.Errorf("remove inferred evidence tenants: %v", err)
		}
	}()
	b, err := NewTenants(pool).Create(ctx, "entity-inferred-b-"+suffix, "Inferred B")
	if err != nil {
		t.Fatal(err)
	}
	createdTenants = append(createdTenants, b.ID)
	contextID := uuid.NewString() // Deliberately reused across both tenants.
	const address = "10.42.0.1"
	deviceA, deviceB, deviceForeign := uuid.NewString(), uuid.NewString(), uuid.NewString()
	serials := map[string]string{}
	register := func(tenantID, agentID, plane string) {
		t.Helper()
		serial := strings.ReplaceAll(uuid.NewString(), "-", "")
		spiffeID := crypto.EntitySPIFFEID(tenantID, agentID)
		if plane == "bmp" {
			spiffeID = crypto.BMPSPIFFEID(tenantID, agentID)
		}
		if err := NewAgentIdentities(pool).Record(ctx, tenantID, agentID,
			spiffeID, serial, time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		serials[tenantID+agentID] = serial
	}
	seed := func(tenantID, deviceID, snmpAgent string, extras bool) {
		t.Helper()
		inTenant(ctx, t, pool, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
				VALUES ($1,$2,$3,$4,'inferred-site','inferred-vrf')`,
				tenantID, contextID, uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entities
				(tenant_id,context_id,id,kind,label)
				VALUES ($1,$2,$3,'device','router')`, tenantID, contextID, deviceID)
			return err
		})
		register(tenantID, snmpAgent, "entity")
		if extras {
			register(tenantID, "flow-a", "entity")
			register(tenantID, "bmp-listener", "entity")
			register(tenantID, "bmp-router", "bmp")
		}
		inTenant(ctx, t, pool, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			for _, agentID := range []string{snmpAgent, "flow-a", "bmp-listener"} {
				if !extras && agentID != snmpAgent {
					continue
				}
				if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
					(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`,
					tenantID, agentID, contextID); err != nil {
					return err
				}
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
				(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
				VALUES ($1,$2,'device_target','snmp-target',$3,$4)`,
				tenantID, snmpAgent, contextID, deviceID); err != nil {
				return err
			}
			if extras {
				if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
					(tenant_id,agent_id,source_kind,source_ref,context_id)
					VALUES ($1,'flow-a','flow_exporter',$2,$3),
					       ($1,'bmp-listener','bmp_peer','bmp-router',$3)`,
					tenantID, address, contextID); err != nil {
					return err
				}
			}
			return nil
		})
	}
	seed(b.ID, deviceForeign, "snmp-foreign", false)
	seed(a.ID, deviceA, "snmp-a", true)
	repo := NewEntityRegistry(pool)
	observed := func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
	snmpClaim := func(agentID string) entity.Observation {
		return entity.Observation{ID: uuid.NewString(),
			Source: entity.SourceKey{AgentID: agentID, Kind: entity.DeviceTarget,
				SourceRef: "snmp-target"},
			Alias:     entity.AliasKey{Kind: entity.AddressAlias, Value: address},
			SourceRef: "snmp:interface-address", ObservedAt: observed()}
	}
	write := func(tenantID, agentID string, claim entity.Observation, wantAccepted, wantUnresolved int) {
		t.Helper()
		accepted, unresolved, err := repo.WriteEvidenceBatch(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)), agentID,
			serials[tenantID+agentID], []entity.Observation{claim})
		if err != nil || accepted != wantAccepted || unresolved != wantUnresolved {
			t.Fatalf("tenant=%s agent=%s accepted=%d unresolved=%d err=%v; want %d/%d",
				tenantID, agentID, accepted, unresolved, err, wantAccepted, wantUnresolved)
		}
	}
	write(b.ID, "snmp-foreign", snmpClaim("snmp-foreign"), 1, 0)
	flowClaim := entity.Observation{ID: uuid.NewString(),
		Source: entity.SourceKey{AgentID: "flow-a", Kind: entity.FlowExporter,
			SourceRef: address},
		Alias: entity.AliasKey{Kind: entity.FlowExporterAlias,
			Value: address + "/ipfix/99"},
		SourceRef: "flow:ipfix:domain:99", ObservedAt: observed()}
	write(a.ID, "flow-a", flowClaim, 0, 1) // Foreign tenant is not support.
	write(a.ID, "snmp-a", snmpClaim("snmp-a"), 1, 0)
	interfaceClaim := entity.Observation{ID: uuid.NewString(),
		Source: entity.SourceKey{AgentID: "snmp-a", Kind: entity.DeviceTarget,
			SourceRef: "snmp-target"},
		Alias:     entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: "7"},
		SourceRef: "snmp:ifIndex:7", ObservedAt: observed()}
	write(a.ID, "snmp-a", interfaceClaim, 1, 0)
	interfaceResolution, err := repo.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
		entity.Scope{TenantID: a.ID, ContextID: contextID}, interfaceClaim.Alias)
	if err != nil || interfaceResolution.Status != entity.Resolved ||
		interfaceResolution.EntityID == deviceA {
		t.Fatalf("SNMP interface was not a distinct child: %+v %v", interfaceResolution, err)
	}
	// The support selector orders rows by observation time. Keep that order
	// strict even on hosts whose wall clock advances in coarse increments.
	time.Sleep(2 * time.Millisecond)
	interfaceAddress := snmpClaim("snmp-a")
	interfaceAddress.SourceRef = "snmp:ifIndex:7"
	write(a.ID, "snmp-a", interfaceAddress, 1, 0)
	time.Sleep(2 * time.Millisecond)
	flowClaim.ObservedAt = observed()
	write(a.ID, "flow-a", flowClaim, 1, 0)
	bmpClaim := entity.Observation{ID: uuid.NewString(),
		Source: entity.SourceKey{AgentID: "bmp-listener", Kind: entity.BMPPeer,
			SourceRef: "bmp-router"},
		Alias: entity.AliasKey{Kind: entity.BMPPeerAlias,
			Value: address + "/as64500"},
		SourceRef:    "bmp:router:bmp-router:peer-asn:64500",
		OriginSerial: serials[a.ID+"bmp-router"], ObservedAt: observed()}
	write(a.ID, "bmp-listener", bmpClaim, 1, 0)
	flowAddress := flowClaim
	flowAddress.ID, flowAddress.Alias, flowAddress.ObservedAt = uuid.NewString(),
		entity.AliasKey{Kind: entity.AddressAlias, Value: address}, observed()
	write(a.ID, "flow-a", flowAddress, 1, 0)
	bmpAddress := bmpClaim
	bmpAddress.ID, bmpAddress.Alias, bmpAddress.ObservedAt = uuid.NewString(),
		entity.AliasKey{Kind: entity.AddressAlias, Value: address}, observed()
	write(a.ID, "bmp-listener", bmpAddress, 1, 0)
	assertSender := func(tenantID, routingContext, expectedDevice string, want bool) {
		t.Helper()
		inTenant(ctx, t, pool, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			got, err := CurrentSourceAddressInScope(ctx, sc,
				entity.Scope{TenantID: tenantID, ContextID: routingContext},
				entity.AliasKey{Kind: entity.AddressAlias, Value: address},
				flowAddress.Source, serials[a.ID+"flow-a"], expectedDevice, time.Now())
			if err != nil || got != want {
				t.Fatalf("tenant %s flow sender current=%t err=%v; want %t",
					tenantID, got, err, want)
			}
			return nil
		})
	}
	assertSender(a.ID, contextID, deviceA, true)
	assertSender(b.ID, contextID, deviceA, false) // Identical address/context cannot cross RLS.

	scope := entity.Scope{TenantID: a.ID, ContextID: contextID}
	assertCurrent := func(alias entity.AliasKey, want entity.Status) {
		t.Helper()
		result, err := repo.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(a.ID)), scope, alias)
		if err != nil || result.Status != want || (want == entity.Resolved && result.EntityID != deviceA) {
			t.Fatalf("alias %+v: status=%s entity=%s err=%v; want %s/%s",
				alias, result.Status, result.EntityID, err, want, deviceA)
		}
	}
	assertCurrent(flowClaim.Alias, entity.Resolved)
	assertCurrent(bmpClaim.Alias, entity.Resolved)
	assertBatch := func(want entity.Status) {
		t.Helper()
		batch, err := repo.ResolveAddresses(tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
			scope, []string{address})
		if err != nil || batch[address].Status != want ||
			(want == entity.Resolved && batch[address].EntityID != deviceA) {
			t.Fatalf("batched address resolution = %+v, err=%v; want %s", batch[address], err, want)
		}
	}
	assertBatch(entity.Resolved)
	initialBatch, err := repo.ResolveAddresses(tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
		scope, []string{address})
	if err != nil || len(initialBatch[address].Candidates) != 1 ||
		initialBatch[address].Candidates[0].SupportEvidenceID == "" {
		t.Fatalf("address batch did not expose inferred support provenance: %+v, %v",
			initialBatch[address], err)
	}
	var supportID string
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT support_evidence_id::text FROM entity_evidence
			WHERE tenant_id=$1 AND agent_id='flow-a' AND observation_id=$2`,
			a.ID, flowClaim.ID).Scan(&supportID)
	})
	if supportID == "" {
		t.Fatal("inferred flow claim omitted its exact SNMP support row")
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var supportEntity string
		if err := sc.Q.QueryRow(ctx, `SELECT entity_id::text FROM entity_evidence
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
			a.ID, contextID, supportID).Scan(&supportEntity); err != nil {
			return err
		}
		if supportEntity != interfaceResolution.EntityID {
			t.Fatalf("flow support lost the original interface IP row: %s want %s",
				supportEntity, interfaceResolution.EntityID)
		}
		return nil
	})
	// The same private address in a second VRF of this same tenant is an
	// independent device. It must neither support nor conflict with the first
	// context's inferred exporter and BMP peer.
	otherContextID, otherDeviceID := uuid.NewString(), uuid.NewString()
	register(a.ID, "snmp-other-vrf", "entity")
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
			(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
			VALUES ($1,$2,$3,$4,'inferred-site','other-vrf')`,
			a.ID, otherContextID, uuid.NewString(), uuid.NewString()); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entities
			(tenant_id,context_id,id,kind,label)
			VALUES ($1,$2,$3,'device','other-vrf-router')`,
			a.ID, otherContextID, otherDeviceID); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
			(tenant_id,agent_id,context_id) VALUES ($1,'snmp-other-vrf',$2)`,
			a.ID, otherContextID); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
			(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
			VALUES ($1,'snmp-other-vrf','device_target','snmp-target',$2,$3)`,
			a.ID, otherContextID, otherDeviceID)
		return err
	})
	write(a.ID, "snmp-other-vrf", snmpClaim("snmp-other-vrf"), 1, 0)
	otherResolution, err := repo.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
		entity.Scope{TenantID: a.ID, ContextID: otherContextID},
		entity.AliasKey{Kind: entity.AddressAlias, Value: address})
	if err != nil || otherResolution.Status != entity.Resolved ||
		otherResolution.EntityID != otherDeviceID {
		t.Fatalf("other routing context resolved %+v, err=%v; want %s",
			otherResolution, err, otherDeviceID)
	}
	assertSender(a.ID, otherContextID, deviceA, false)
	assertCurrent(flowClaim.Alias, entity.Resolved)
	assertBatch(entity.Resolved)
	assertDetail := func(wantCurrent bool) {
		t.Helper()
		page, err := repo.ListEntityEvidence(tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
			scope, deviceA, "", 20)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			if item.ObservationID == flowClaim.ID {
				if item.Current != wantCurrent || item.SupportEvidenceID != supportID {
					t.Fatalf("flow detail current=%t support=%q; want %t/%q",
						item.Current, item.SupportEvidenceID, wantCurrent, supportID)
				}
				return
			}
		}
		t.Fatal("flow detail omitted the original evidence row")
	}
	assertDetail(true)
	// A delayed SNMP observation may become the preferred support for a new
	// claim. Replaying the already accepted flow observation must still ACK
	// idempotently and retain its original exact support row.
	delayedSNMP := snmpClaim("snmp-a")
	delayedSNMP.ObservedAt = flowClaim.ObservedAt
	write(a.ID, "snmp-a", delayedSNMP, 1, 0)
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var preferred string
		if err := sc.Q.QueryRow(ctx, `SELECT id::text FROM entity_evidence
			WHERE tenant_id=$1 AND agent_id='snmp-a' AND observation_id=$2`,
			a.ID, delayedSNMP.ID).Scan(&preferred); err != nil {
			return err
		}
		if preferred == supportID {
			t.Fatal("delayed SNMP fixture did not introduce a distinct support row")
		}
		_, selectedSupport, err := independentSNMPSupport(ctx, sc,
			a.ID, contextID, address, flowClaim.ObservedAt)
		if err != nil || selectedSupport != preferred {
			t.Fatalf("delayed SNMP row was not preferred: got %q, want %q, err=%v",
				selectedSupport, preferred, err)
		}
		return nil
	})
	write(a.ID, "flow-a", flowClaim, 1, 0)
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_evidence
			WHERE tenant_id=$1 AND agent_id='flow-a' AND observation_id=$2
			  AND support_evidence_id=$3`, a.ID, flowClaim.ID, supportID).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			t.Fatalf("flow retry changed its original support or added a row: count=%d", count)
		}
		return nil
	})
	// A second independently authenticated device with the same address makes
	// both derived joins historical without deleting either raw observation.
	register(a.ID, "snmp-rival", "entity")
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entities
			(tenant_id,context_id,id,kind,label)
			VALUES ($1,$2,$3,'device','rival')`, a.ID, contextID, deviceB); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
			(tenant_id,agent_id,context_id) VALUES ($1,'snmp-rival',$2)`, a.ID, contextID); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
			(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
			VALUES ($1,'snmp-rival','device_target','snmp-target',$2,$3)`,
			a.ID, contextID, deviceB)
		return err
	})
	write(a.ID, "snmp-rival", snmpClaim("snmp-rival"), 1, 0)
	assertCurrent(flowClaim.Alias, entity.Unresolved)
	assertCurrent(bmpClaim.Alias, entity.Unresolved)
	assertBatch(entity.Conflict)
	assertDetail(false)
	assertSender(a.ID, contextID, deviceA, false)
	// Expire only the rival source: the original support becomes unique again.
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
			SET expires_at=clock_timestamp()
			WHERE tenant_id=$1 AND agent_id='snmp-rival'`, a.ID)
		return err
	})
	assertCurrent(flowClaim.Alias, entity.Resolved)
	assertBatch(entity.Resolved)
	assertDetail(true)
	assertSender(a.ID, contextID, deviceA, true)
	// Rebinding the exact supporting source retires the original observation.
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
			SET anchor_entity_id=$2 WHERE tenant_id=$1 AND agent_id='snmp-a'`,
			a.ID, deviceB)
		return err
	})
	assertCurrent(flowClaim.Alias, entity.Unresolved)
	assertCurrent(bmpClaim.Alias, entity.Unresolved)
	assertBatch(entity.Unresolved)
	assertDetail(false)
	assertSender(a.ID, contextID, deviceA, false)
}
