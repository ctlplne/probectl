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
	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestEntityRegistryTenantAndContextIsolation(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "entity-a-"+suffix, "Entity A")
	if err != nil {
		t.Fatal(err)
	}
	createdTenants := []string{a.ID}
	defer func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, createdTenants); err != nil {
			t.Errorf("remove entity registry fixture tenants: %v", err)
		}
	}()
	b, err := NewTenants(pool).Create(ctx, "entity-b-"+suffix, "Entity B")
	if err != nil {
		t.Fatal(err)
	}
	createdTenants = append(createdTenants, b.ID)
	ctxA1, ctxA2 := uuid.NewString(), uuid.NewString()
	ctxB := ctxA1 // Force the same routing-context UUID in both tenants.
	siteID, defaultVRF, customerVRF := uuid.NewString(), uuid.NewString(), uuid.NewString()
	entityA1, entityA2, entityB := uuid.NewString(), uuid.NewString(), uuid.NewString()
	serials := map[string]string{}
	key := entity.AliasKey{Kind: entity.AddressAlias, Value: "10.42.0.1"}
	seed := func(tenant, routingContext, vrfID, entityID string) {
		t.Helper()
		agentID := "collector-1"
		if tenant == a.ID && routingContext == ctxA1 {
			agentID = "collector-a1"
		}
		serial := strings.ReplaceAll(uuid.NewString(), "-", "")
		if err := NewAgentIdentities(pool).Record(ctx, tenant, agentID,
			crypto.EntitySPIFFEID(tenant, agentID), serial,
			time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		serials[tenant+agentID] = serial
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
                VALUES ($1,$2,$3,$4,$3::uuid::text,$4::uuid::text)`, tenant, routingContext, siteID, vrfID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
				(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`,
				tenant, agentID, routingContext); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
				(tenant_id,agent_id,source_kind,source_ref,context_id)
				VALUES ($1,$2,'device_target','10.42.0.1',$3)`,
				tenant, agentID, routingContext); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities
				(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'device','router')`, tenant, routingContext, entityID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
				SET anchor_entity_id=$1 WHERE tenant_id=$2 AND agent_id=$3`,
				entityID, tenant, agentID); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_evidence
				(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,source,source_ref,
				 agent_id,source_kind,configured_ref,observed_at,sender_serial)
				VALUES ($1,$2,$3,$3,$4,'address','10.42.0.1','snmp','lab-router',
				        $5,'device_target','10.42.0.1',clock_timestamp(),$6)`,
				tenant, routingContext, uuid.NewString(), entityID, agentID, serial)
			return err
		})
	}
	seed(a.ID, ctxA1, defaultVRF, entityA1)
	seed(a.ID, ctxA2, customerVRF, entityA2)
	seed(b.ID, ctxB, defaultVRF, entityB)
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a.ID)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_evidence
				(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,
				 source,source_ref,agent_id,source_kind,configured_ref,observed_at)
				VALUES ($1,$2,$3,$4,$5,'address','10.42.0.1',
				        'fixture','missing-sender','collector-a1','device_target',
				        '10.42.0.1',clock_timestamp())`,
				a.ID, ctxA1, uuid.NewString(), uuid.NewString(), entityA1)
			return err
		}); err == nil {
		t.Fatal("evidence without an issuing sender certificate entered the registry")
	}
	for name, anchor := range map[string]string{
		"other tenant": entityB,
		"other VRF":    entityA2,
	} {
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a.ID)), pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
					SET anchor_entity_id=$1
					WHERE tenant_id=$2 AND agent_id='collector-a1'`, anchor, a.ID)
				return err
			}); err == nil {
			t.Fatalf("source accepted %s canonical anchor", name)
		}
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
			SET anchor_entity_id=$1
			WHERE tenant_id=$2 AND agent_id='collector-a1'`, entityA1, a.ID)
		return err
	})
	repo := NewEntityRegistry(pool)
	inTenant(ctx, t, pool, b.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
			SET anchor_entity_id=$1
			WHERE tenant_id=$2 AND agent_id='collector-1'`, entityB, b.ID)
		return err
	})
	// The same observation UUID and private address can be written in both
	// tenants, but neither request may choose another agent or context.
	observed := time.Now().UTC().Truncate(time.Microsecond)
	observationID := uuid.NewString()
	makeObservation := func(agentID string) entity.Observation {
		name := "  edge for " + agentID + "  "
		if agentID == "collector-1" {
			name = "" // positive empty presence must differ from legacy NULL
		}
		return entity.Observation{
			ID: observationID,
			Source: entity.SourceKey{AgentID: agentID, Kind: entity.DeviceTarget,
				SourceRef: "10.42.0.1"},
			Alias:             key,
			SourceRef:         "snmp:configured-target",
			ObservedAt:        observed,
			SystemDescription: "router OS for " + agentID,
			SystemName:        &name,
		}
	}
	for _, tc := range []struct{ tenantID, agentID string }{
		{a.ID, "collector-a1"}, {b.ID, "collector-1"},
	} {
		claim := makeObservation(tc.agentID)
		for attempt := 0; attempt < 2; attempt++ {
			accepted, unresolved, err := repo.WriteEvidenceBatch(
				tenancy.WithTenant(ctx, tenancy.ID(tc.tenantID)), tc.agentID,
				serials[tc.tenantID+tc.agentID], []entity.Observation{claim})
			if err != nil || accepted != 1 || unresolved != 0 {
				t.Fatalf("tenant %s evidence attempt %d: accepted=%d unresolved=%d err=%v",
					tc.tenantID, attempt, accepted, unresolved, err)
			}
		}
		changed := claim
		changed.SystemDescription = "different router OS"
		if _, _, err := repo.WriteEvidenceBatch(tenancy.WithTenant(ctx, tenancy.ID(tc.tenantID)), tc.agentID,
			serials[tc.tenantID+tc.agentID], []entity.Observation{changed}); !errors.Is(err, entity.ErrConflictingEvidence) {
			t.Fatalf("same-UUID replay changed retained system metadata: %v", err)
		}
		for _, name := range []*string{nil, new(string)} {
			if name != nil && *name == *claim.SystemName {
				continue // the exact replay was already accepted above
			}
			changed := claim
			changed.SystemName = name
			if _, _, err := repo.WriteEvidenceBatch(tenancy.WithTenant(ctx, tenancy.ID(tc.tenantID)), tc.agentID,
				serials[tc.tenantID+tc.agentID], []entity.Observation{changed}); !errors.Is(err, entity.ErrConflictingEvidence) {
				t.Fatalf("same-UUID replay collapsed absent, empty or raw name: %v", err)
			}
		}
		inTenant(ctx, t, pool, tc.tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			var description string
			var name *string
			if err := sc.Q.QueryRow(ctx, `SELECT snmp_system_description,snmp_system_name FROM entity_evidence
				WHERE tenant_id=$1 AND agent_id=$2 AND observation_id=$3`,
				tc.tenantID, tc.agentID, observationID).Scan(&description, &name); err != nil {
				return err
			}
			if description != claim.SystemDescription || name == nil || *name != *claim.SystemName {
				t.Fatal("tenant evidence lost or crossed the system-description metadata")
			}
			foreign := a.ID
			if tc.tenantID == a.ID {
				foreign = b.ID
			}
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_evidence
				WHERE tenant_id=$1 AND observation_id=$2 AND (snmp_system_description IS NOT NULL OR snmp_system_name IS NOT NULL)`, foreign, observationID).Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				t.Fatal("system-description metadata bypassed storage-layer tenant isolation")
			}
			var observedAt, expiresAt time.Time
			if err := sc.Q.QueryRow(ctx, `SELECT observed_at,expires_at FROM entity_evidence
				WHERE tenant_id=$1 AND agent_id=$2 AND observation_id=$3`,
				tc.tenantID, tc.agentID, observationID).Scan(&observedAt, &expiresAt); err != nil {
				return err
			}
			if !expiresAt.Equal(observedAt.Add(evidenceFreshness)) {
				t.Fatalf("tenant %s evidence has no bounded freshness: observed=%s expires=%s",
					tc.tenantID, observedAt, expiresAt)
			}
			return nil
		})
	}
	// Both descriptions now exist. The first lane cannot read the second
	// lane's metadata even when the observation UUID and private IP match.
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_evidence
			WHERE tenant_id=$1 AND observation_id=$2 AND snmp_system_description IS NOT NULL`, b.ID, observationID).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatal("first tenant read the second tenant's retained system metadata")
		}
		return nil
	})
	for name, foreignParent := range map[string]string{
		"other tenant":  entityB,
		"other context": entityA2,
	} {
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a.ID)), pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `INSERT INTO entities
					(tenant_id,context_id,id,kind,label,parent_entity_id,
					 source_agent_id,configured_ref,interface_index)
					VALUES ($1,$2,$3,'interface','ifIndex 8',$4,
					        'collector-a1','10.42.0.1',8)`,
					a.ID, ctxA1, uuid.NewString(), foreignParent)
				return err
			}); err == nil {
			t.Fatalf("interface accepted parent from %s", name)
		}
	}
	interfaceIDs := map[string]bool{}
	for _, fixture := range []struct{ tenant, routingContext, agent, device string }{
		{a.ID, ctxA1, "collector-a1", entityA1},
		{a.ID, ctxA2, "collector-1", entityA2},
		{b.ID, ctxB, "collector-1", entityB},
	} {
		claim := entity.Observation{ID: uuid.NewString(),
			Source: entity.SourceKey{AgentID: fixture.agent, Kind: entity.DeviceTarget,
				SourceRef: "10.42.0.1"},
			Alias:     entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: "4294967295"},
			SourceRef: "snmp:ifIndex:4294967295", ObservedAt: time.Now().UTC(),
			InterfaceName: "xe-0/0/7", InterfaceDescription: "lab uplink"}
		accepted, unresolved, err := repo.WriteEvidenceBatch(
			tenancy.WithTenant(ctx, tenancy.ID(fixture.tenant)), fixture.agent,
			serials[fixture.tenant+fixture.agent], []entity.Observation{claim})
		if err != nil || accepted != 1 || unresolved != 0 {
			t.Fatalf("SNMP interface %s/%s: accepted=%d unresolved=%d err=%v",
				fixture.tenant, fixture.routingContext, accepted, unresolved, err)
		}
		resolved, err := repo.ResolveAlias(
			tenancy.WithTenant(ctx, tenancy.ID(fixture.tenant)),
			entity.Scope{TenantID: fixture.tenant, ContextID: fixture.routingContext},
			claim.Alias)
		if err != nil || resolved.Status != entity.Resolved ||
			len(resolved.Candidates) != 1 || resolved.Candidates[0].EntityKind != entity.Interface ||
			interfaceIDs[resolved.EntityID] || resolved.EntityID == fixture.device {
			t.Fatalf("SNMP ifIndex merged devices/tenants/contexts: %+v err=%v", resolved, err)
		}
		interfaceIDs[resolved.EntityID] = true
		links, err := repo.ListEntityLinks(
			tenancy.WithTenant(ctx, tenancy.ID(fixture.tenant)),
			entity.Scope{TenantID: fixture.tenant, ContextID: fixture.routingContext},
			resolved.EntityID, "", 10)
		if err != nil || len(links.Items) != 1 ||
			links.Items[0].Kind != "contains" ||
			links.Items[0].FromEntityID != fixture.device ||
			links.Items[0].ToEntityID != resolved.EntityID {
			t.Fatalf("interface lost evidence-backed parent: %+v err=%v", links, err)
		}
		evidence, err := repo.ListEntityEvidence(
			tenancy.WithTenant(ctx, tenancy.ID(fixture.tenant)),
			entity.Scope{TenantID: fixture.tenant, ContextID: fixture.routingContext},
			resolved.EntityID, "", 10)
		if err != nil || len(evidence.Items) != 1 || !evidence.Items[0].Current ||
			evidence.Items[0].InterfaceName != "xe-0/0/7" ||
			evidence.Items[0].InterfaceDescription != "lab uplink" {
			t.Fatalf("interface lost current SNMP labels: %+v err=%v", evidence, err)
		}
		interfaceAddress := entity.Observation{ID: uuid.NewString(),
			Source: entity.SourceKey{AgentID: fixture.agent, Kind: entity.DeviceTarget,
				SourceRef: "10.42.0.1"},
			Alias: key, SourceRef: "snmp:ifIndex:4294967295",
			ObservedAt: time.Now().UTC()}
		if accepted, unresolved, err := repo.WriteEvidenceBatch(
			tenancy.WithTenant(ctx, tenancy.ID(fixture.tenant)), fixture.agent,
			serials[fixture.tenant+fixture.agent], []entity.Observation{interfaceAddress}); err != nil || accepted != 1 || unresolved != 0 {
			t.Fatalf("interface address %s/%s: %d/%d %v",
				fixture.tenant, fixture.routingContext, accepted, unresolved, err)
		}
		addressResolution, err := repo.ResolveAlias(
			tenancy.WithTenant(ctx, tenancy.ID(fixture.tenant)),
			entity.Scope{TenantID: fixture.tenant, ContextID: fixture.routingContext}, key)
		if err != nil || addressResolution.Status != entity.Resolved ||
			addressResolution.EntityID != fixture.device {
			t.Fatalf("interface IP did not project parent device: %+v %v", addressResolution, err)
		}
		addressBatch, err := repo.ResolveAddresses(
			tenancy.WithTenant(ctx, tenancy.ID(fixture.tenant)),
			entity.Scope{TenantID: fixture.tenant, ContextID: fixture.routingContext},
			[]string{key.Value})
		if err != nil || addressBatch[key.Value].Status != entity.Resolved ||
			addressBatch[key.Value].EntityID != fixture.device {
			t.Fatalf("batched interface IP did not project parent device: %+v %v",
				addressBatch[key.Value], err)
		}
		addressPage, err := repo.ListEntityEvidence(
			tenancy.WithTenant(ctx, tenancy.ID(fixture.tenant)),
			entity.Scope{TenantID: fixture.tenant, ContextID: fixture.routingContext},
			resolved.EntityID, "", 10)
		if err != nil || len(addressPage.Items) != 2 {
			t.Fatalf("interface detail lost address evidence: %+v %v", addressPage, err)
		}
		var foundAddress bool
		for _, row := range addressPage.Items {
			if row.Alias == key && row.SourceRef == interfaceAddress.SourceRef && row.Current {
				foundAddress = true
			}
		}
		if !foundAddress {
			t.Fatalf("interface IP missing from current detail: %+v", addressPage)
		}
	}
	otherDevice := uuid.NewString()
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entities
			(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'device','replacement')`,
			a.ID, ctxA1, otherDevice); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET anchor_entity_id=$1
			WHERE tenant_id=$2 AND agent_id='collector-a1' AND source_kind='device_target'`,
			otherDevice, a.ID)
		return err
	})
	reanchoredClaim := entity.Observation{ID: uuid.NewString(),
		Source: entity.SourceKey{AgentID: "collector-a1", Kind: entity.DeviceTarget,
			SourceRef: "10.42.0.1"},
		Alias:     entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: "4294967295"},
		SourceRef: "snmp:ifIndex:4294967295", ObservedAt: time.Now().UTC()}
	accepted, unresolved, err := repo.WriteEvidenceBatch(
		tenancy.WithTenant(ctx, tenancy.ID(a.ID)), "collector-a1",
		serials[a.ID+"collector-a1"], []entity.Observation{reanchoredClaim})
	if err != nil || accepted != 0 || unresolved != 1 {
		t.Fatalf("reanchored source moved an old interface: accepted=%d unresolved=%d err=%v",
			accepted, unresolved, err)
	}
	reanchoredAddress := reanchoredClaim
	reanchoredAddress.ID = uuid.NewString()
	reanchoredAddress.Alias = key
	accepted, unresolved, err = repo.WriteEvidenceBatch(
		tenancy.WithTenant(ctx, tenancy.ID(a.ID)), "collector-a1",
		serials[a.ID+"collector-a1"], []entity.Observation{reanchoredAddress})
	if err != nil || accepted != 0 || unresolved != 1 {
		t.Fatalf("reanchored source moved an old interface IP: accepted=%d unresolved=%d err=%v",
			accepted, unresolved, err)
	}
	staleInterface, err := repo.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
		entity.Scope{TenantID: a.ID, ContextID: ctxA1}, reanchoredClaim.Alias)
	if err != nil || staleInterface.Status != entity.Unresolved {
		t.Fatalf("old device interface stayed current after reanchor: %+v err=%v", staleInterface, err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET anchor_entity_id=$1
			WHERE tenant_id=$2 AND agent_id='collector-a1' AND source_kind='device_target'`,
			entityA1, a.ID)
		return err
	})
	for _, fixture := range []struct{ tenant, routingContext, entityID string }{
		{a.ID, ctxA1, entityA1}, {b.ID, ctxB, entityB},
	} {
		batch, err := repo.ResolveAddresses(
			tenancy.WithTenant(ctx, tenancy.ID(fixture.tenant)),
			entity.Scope{TenantID: fixture.tenant, ContextID: fixture.routingContext},
			[]string{"10.42.0.1", "10.42.0.99", "10.42.0.1"})
		if err != nil || batch["10.42.0.1"].Status != entity.Resolved ||
			batch["10.42.0.1"].EntityID != fixture.entityID ||
			batch["10.42.0.99"].Status != entity.Unresolved {
			t.Fatalf("batched path identities tenant=%s: %+v, %v", fixture.tenant, batch, err)
		}
	}
	if _, _, err := repo.WriteEvidenceBatch(
		tenancy.WithTenant(ctx, tenancy.ID(a.ID)), "collector-a1",
		serials[a.ID+"collector-a1"], []entity.Observation{makeObservation("collector-1")}); !errors.Is(err, entity.ErrInvalidClaim) {
		t.Fatalf("same-tenant agent forgery reached evidence storage: %v", err)
	}
	forged := makeObservation("collector-a1")
	forged.Alias.Value = "10.42.0.2"
	if _, _, err := repo.WriteEvidenceBatch(
		tenancy.WithTenant(ctx, tenancy.ID(a.ID)), "collector-a1",
		serials[a.ID+"collector-a1"], []entity.Observation{forged}); !errors.Is(err, entity.ErrConflictingEvidence) {
		t.Fatalf("same observation UUID changed its claim: %v", err)
	}
	if _, _, err := repo.WriteEvidenceBatch(
		tenancy.WithTenant(ctx, tenancy.ID(a.ID)), "collector-a1",
		serials[b.ID+"collector-1"], []entity.Observation{makeObservation("collector-a1")}); !errors.Is(err, ErrEvidenceIdentityInactive) {
		t.Fatalf("foreign tenant certificate entered evidence store: %v", err)
	}
	source := entity.SourceKey{AgentID: "collector-1", Kind: entity.DeviceTarget, SourceRef: "10.42.0.1"}
	for _, mapping := range []struct{ tenant, routingContext string }{
		{a.ID, ctxA2}, {b.ID, ctxB},
	} {
		got, err := repo.ResolveSourceContext(
			tenancy.WithTenant(ctx, tenancy.ID(mapping.tenant)), mapping.tenant, source)
		if err != nil || got.ContextID != mapping.routingContext {
			t.Fatalf("source context tenant=%s: %+v err=%v", mapping.tenant, got, err)
		}
	}
	if _, err := repo.ResolveSourceContext(
		tenancy.WithTenant(ctx, tenancy.ID(a.ID)), b.ID, source); !errors.Is(err, entity.ErrScopeMismatch) {
		t.Fatalf("foreign tenant source assignment visible: %v", err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a.ID)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
				(tenant_id,agent_id,source_kind,source_ref,context_id)
				VALUES ($1,$2,$3,$4,$5)`, a.ID, source.AgentID,
				string(source.Kind), "10.42.0.2", ctxA1)
			return err
		}); err == nil {
		t.Fatal("one evidence agent was assigned to two routing contexts")
	}
	if _, err := repo.ResolveSourceContext(
		tenancy.WithTenant(ctx, tenancy.ID(a.ID)), a.ID,
		entity.SourceKey{AgentID: "collector-unknown", Kind: entity.DeviceTarget, SourceRef: source.SourceRef}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("unassigned collector selected a context: %v", err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
			SET assigned_at=clock_timestamp()-interval '2 hours',
			    expires_at=clock_timestamp()-interval '1 hour'
			WHERE tenant_id=$1 AND agent_id=$2 AND source_kind=$3 AND source_ref=$4`,
			a.ID, source.AgentID, string(source.Kind), source.SourceRef)
		return err
	})
	if _, err := repo.ResolveSourceContext(
		tenancy.WithTenant(ctx, tenancy.ID(a.ID)), a.ID, source); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expired source assignment selected a context: %v", err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
			SET assigned_at=clock_timestamp()+interval '1 hour', expires_at=NULL
			WHERE tenant_id=$1 AND agent_id=$2 AND source_kind=$3 AND source_ref=$4`,
			a.ID, source.AgentID, string(source.Kind), source.SourceRef)
		return err
	})
	if _, err := repo.ResolveSourceContext(
		tenancy.WithTenant(ctx, tenancy.ID(a.ID)), a.ID, source); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("future-dated source assignment selected a context: %v", err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
			SET assigned_at=clock_timestamp(), expires_at=NULL
			WHERE tenant_id=$1 AND agent_id=$2 AND source_kind=$3 AND source_ref=$4`,
			a.ID, source.AgentID, string(source.Kind), source.SourceRef)
		return err
	})
	// A valid sender certificate cannot backdate an observation into the
	// period before the operator assigned its source to this routing context.
	// Move only this fixture's issuance back so the assignment is the rule
	// under test, then keep the original evidence rows available for reads.
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE agent_identities
			SET issued_at=clock_timestamp()-interval '2 hours'
			WHERE tenant_id=$1 AND agent_id=$2 AND serial=$3`,
			a.ID, source.AgentID, serials[a.ID+source.AgentID])
		return err
	})
	preAssignment := entity.Observation{ID: uuid.NewString(), Source: source,
		Alias: key, SourceRef: "snmp:pre-assignment",
		ObservedAt: time.Now().UTC().Add(-time.Minute)}
	if accepted, unresolved, err := repo.WriteEvidenceBatch(
		tenancy.WithTenant(ctx, tenancy.ID(a.ID)), source.AgentID,
		serials[a.ID+source.AgentID], []entity.Observation{preAssignment}); err != nil || accepted != 0 || unresolved != 1 {
		t.Fatalf("pre-assignment observation became canonical: accepted=%d unresolved=%d err=%v",
			accepted, unresolved, err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
			SET anchor_entity_id=$1
			WHERE tenant_id=$2 AND agent_id=$3 AND context_id=$4`,
			entityA2, a.ID, source.AgentID, ctxA2)
		return err
	})
	// Moving this fixture's assignment clock forward correctly retires its
	// earlier evidence. A new observation at the stored assignment instant
	// restores only this tenant/context's current resolution.
	var assignedAt time.Time
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT assigned_at FROM entity_source_contexts
			WHERE tenant_id=$1 AND agent_id=$2 AND source_kind=$3 AND source_ref=$4`,
			a.ID, source.AgentID, string(source.Kind), source.SourceRef).Scan(&assignedAt)
	})
	postAssignment := entity.Observation{ID: uuid.NewString(), Source: source,
		Alias: key, SourceRef: "snmp:post-assignment", ObservedAt: assignedAt}
	if accepted, unresolved, err := repo.WriteEvidenceBatch(
		tenancy.WithTenant(ctx, tenancy.ID(a.ID)), source.AgentID,
		serials[a.ID+source.AgentID], []entity.Observation{postAssignment}); err != nil || accepted != 1 || unresolved != 0 {
		t.Fatalf("post-assignment observation: accepted=%d unresolved=%d err=%v",
			accepted, unresolved, err)
	}
	for _, tc := range []struct {
		tenant, routingContext, want string
	}{
		{a.ID, ctxA1, entityA1},
		{a.ID, ctxA2, entityA2},
		{b.ID, ctxB, entityB},
	} {
		result, err := repo.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(tc.tenant)),
			entity.Scope{TenantID: tc.tenant, ContextID: tc.routingContext}, key)
		if err != nil || result.Status != entity.Resolved || result.EntityID != tc.want || len(result.Candidates) != 1 {
			t.Fatalf("resolve tenant=%s context=%s: %+v err=%v", tc.tenant, tc.routingContext, result, err)
		}
	}
	// A source reanchored by its operator must stop lending its old evidence
	// to the former entity, even though that evidence remains for citations.
	reanchored := uuid.NewString()
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entities
			(tenant_id,context_id,id,kind,label)
			VALUES ($1,$2,$3,'device','replacement')`, a.ID, ctxA1, reanchored); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
			SET anchor_entity_id=$1 WHERE tenant_id=$2 AND agent_id='collector-a1'`,
			reanchored, a.ID)
		return err
	})
	result, err := repo.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
		entity.Scope{TenantID: a.ID, ContextID: ctxA1}, key)
	if err != nil || result.Status != entity.Unresolved {
		t.Fatalf("old anchor still lent evidence after reanchor: %+v err=%v", result, err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
			SET anchor_entity_id=$1 WHERE tenant_id=$2 AND agent_id='collector-a1'`,
			entityA1, a.ID)
		return err
	})
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
			SET anchor_entity_id=NULL WHERE tenant_id=$1 AND agent_id=$2`,
			a.ID, source.AgentID)
		return err
	})
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_agent_contexts
			SET context_id=$1, assigned_at=clock_timestamp()
			WHERE tenant_id=$2 AND agent_id=$3`, ctxA1, a.ID, source.AgentID)
		return err
	})
	result, err = repo.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
		entity.Scope{TenantID: a.ID, ContextID: ctxA2}, key)
	if err != nil || result.Status != entity.Unresolved || result.EntityID != "" {
		t.Fatalf("re-bound collector's old VRF evidence still resolved: %+v err=%v", result, err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_agent_contexts
			SET context_id=$1, assigned_at=clock_timestamp()
			WHERE tenant_id=$2 AND agent_id=$3`, ctxA2, a.ID, source.AgentID)
		return err
	})
	redCtx := tenancy.WithTenant(ctx, tenancy.ID(a.ID))
	record, err := repo.GetEntity(redCtx, entity.Scope{TenantID: a.ID, ContextID: ctxA1}, entityA1)
	if err != nil || record.ID != entityA1 || record.Kind != entity.Device || record.Scope.TenantID != a.ID {
		t.Fatalf("read own canonical entity: %+v err=%v", record, err)
	}
	if _, err := repo.GetEntity(redCtx, entity.Scope{TenantID: a.ID, ContextID: ctxA1}, entityB); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("foreign tenant entity ID became visible: %v", err)
	}
	if _, err := repo.GetEntity(redCtx, entity.Scope{TenantID: a.ID, ContextID: ctxA2}, entityA1); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("wrong-context entity ID became visible: %v", err)
	}
	if _, err := repo.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
		entity.Scope{TenantID: b.ID, ContextID: ctxB}, key); !errors.Is(err, entity.ErrScopeMismatch) {
		t.Fatalf("forged tenant resolved: %v", err)
	}
	if _, err := repo.ResolveAlias(ctx, entity.Scope{TenantID: a.ID, ContextID: ctxA1}, key); !errors.Is(err, entity.ErrScopeMismatch) {
		t.Fatalf("missing tenant resolved: %v", err)
	}
	if _, err := repo.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
		entity.Scope{TenantID: a.ID}, key); !errors.Is(err, entity.ErrInvalidScope) {
		t.Fatalf("missing routing context resolved: %v", err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a.ID)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_evidence
				(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,source,source_ref,
				 agent_id,source_kind,configured_ref,observed_at,sender_serial)
				VALUES ($1,$2,$3,$3,$4,'address','10.42.0.1','snmp','forged',
				        'collector-a1','device_target','10.42.0.1',clock_timestamp(),$5)`,
				a.ID, ctxA1, uuid.NewString(), entityB, serials[a.ID+"collector-a1"])
			return err
		}); err == nil {
		t.Fatal("compound tenant/context FK accepted tenant B's entity")
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a.ID)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
                VALUES ($1,$2,$3,$4,$3::uuid::text,$4::uuid::text)`,
				b.ID, uuid.NewString(), siteID, defaultVRF)
			return err
		}); err == nil {
		t.Fatal("FORCE RLS accepted tenant B's context from tenant A transaction")
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_evidence`).Scan(&count); err != nil {
			return err
		}
		// Five original rows, two retained unresolved reanchor attempts and
		// the post-assignment observation all belong to tenant A.
		if count != 8 {
			t.Fatalf("predicate-free forced RLS count=%d, want 8", count)
		}
		tag, err := sc.Q.Exec(ctx, `DELETE FROM entity_evidence WHERE tenant_id=$1`, b.ID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 0 {
			t.Fatal("tenant A deleted tenant B evidence")
		}
		return nil
	})
	entityConflict := uuid.NewString()
	const bmpRouterID, bmpRouterSerial = "bmp-router-a1", "a1b2c3"
	bmpSenderSerial := strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := NewAgentIdentities(pool).Record(ctx, a.ID, "bmp-a1",
		crypto.EntitySPIFFEID(a.ID, "bmp-a1"), bmpSenderSerial,
		time.Now().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	if err := NewAgentIdentities(pool).Record(ctx, a.ID, bmpRouterID,
		crypto.BMPSPIFFEID(a.ID, bmpRouterID), bmpRouterSerial,
		time.Now().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
			(tenant_id,agent_id,context_id) VALUES ($1,'bmp-a1',$2)`, a.ID, ctxA1); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
			(tenant_id,agent_id,source_kind,source_ref,context_id)
			VALUES ($1,'bmp-a1','bmp_peer',$3,$2)`, a.ID, ctxA1, bmpRouterID); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entities
			(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'device','other-router')`,
			a.ID, ctxA1, entityConflict); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
			SET anchor_entity_id=$1 WHERE tenant_id=$2 AND agent_id='bmp-a1'`,
			entityConflict, a.ID); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO entity_evidence
			(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,source,source_ref,
			 agent_id,source_kind,configured_ref,observed_at,sender_serial,origin_serial)
			VALUES ($1,$2,$3,$3,$4,'address','10.42.0.1','bmp','other-peer',
			        'bmp-a1','bmp_peer',$5,clock_timestamp(),$6,$7)`,
			a.ID, ctxA1, uuid.NewString(), entityConflict, bmpRouterID, bmpSenderSerial, bmpRouterSerial)
		return err
	})
	result, err = repo.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
		entity.Scope{TenantID: a.ID, ContextID: ctxA1}, key)
	if err != nil || result.Status != entity.Conflict || result.EntityID != "" || len(result.Candidates) != 2 {
		t.Fatalf("conflicting evidence selected a router: %+v err=%v", result, err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
			SET assigned_at=clock_timestamp()-interval '2 hours',
			    expires_at=clock_timestamp()-interval '1 hour'
			WHERE tenant_id=$1 AND agent_id='bmp-a1' AND source_kind='bmp_peer'`, a.ID)
		return err
	})
	result, err = repo.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
		entity.Scope{TenantID: a.ID, ContextID: ctxA1}, key)
	if err != nil || result.Status != entity.Resolved || result.EntityID != entityA1 || len(result.Candidates) != 1 {
		t.Fatalf("revoked BMP source still contributed evidence: %+v err=%v", result, err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
			SET assigned_at=clock_timestamp(), expires_at=NULL
			WHERE tenant_id=$1 AND agent_id='bmp-a1' AND source_kind='bmp_peer'`, a.ID)
		return err
	})
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_evidence
			SET observed_at = clock_timestamp() - interval '2 hours',
			    expires_at = clock_timestamp() - interval '1 hour'
			WHERE tenant_id=$1 AND context_id=$2`, a.ID, ctxA1)
		return err
	})
	result, err = repo.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
		entity.Scope{TenantID: a.ID, ContextID: ctxA1}, key)
	if err != nil || result.Status != entity.Unresolved || result.EntityID != "" || len(result.Candidates) != 0 {
		t.Fatalf("expired evidence continued to resolve: %+v err=%v", result, err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO entity_evidence
			(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,source,source_ref,
			 agent_id,source_kind,configured_ref,observed_at,sender_serial)
			VALUES ($1,$2,$3,$3,$4,'address','10.42.0.1','snmp','future-poll',
			        'collector-a1','device_target','10.42.0.1',clock_timestamp()+interval '1 hour',$5)`,
			a.ID, ctxA1, uuid.NewString(), entityA1, serials[a.ID+"collector-a1"])
		return err
	})
	result, err = repo.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
		entity.Scope{TenantID: a.ID, ContextID: ctxA1}, key)
	if err != nil || result.Status != entity.Unresolved {
		t.Fatalf("future-dated evidence resolved early: %+v err=%v", result, err)
	}
	// A writer can enter with an active source and then wait on the row lock.
	// Expiry during that wait must be evaluated after the lock is acquired.
	bound := tenancy.WithTenant(ctx, tenancy.ID(a.ID))
	type writeResult struct {
		accepted, unresolved int
		err                  error
	}
	written := make(chan writeResult, 1)
	err = tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
		var held int
		if err := sc.Q.QueryRow(ctx, `SELECT 1 FROM entity_source_contexts
			WHERE tenant_id=$1 AND agent_id='collector-a1' AND source_kind='device_target'
			FOR UPDATE`, a.ID).Scan(&held); err != nil {
			return err
		}
		fresh := entity.Observation{ID: uuid.NewString(),
			Source: entity.SourceKey{AgentID: "collector-a1", Kind: entity.DeviceTarget,
				SourceRef: "10.42.0.1"},
			Alias: key, SourceRef: "snmp:post-lock", ObservedAt: time.Now().UTC()}
		go func() {
			accepted, unresolved, err := repo.WriteEvidenceBatch(bound, "collector-a1",
				serials[a.ID+"collector-a1"], []entity.Observation{fresh})
			written <- writeResult{accepted, unresolved, err}
		}()
		deadline := time.Now().Add(3 * time.Second)
		for {
			var waiting bool
			if err := pool.QueryRow(ctx, `SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity
				WHERE wait_event_type='Lock' AND query LIKE '%FOR UPDATE OF m,a%')`).Scan(&waiting); err != nil {
				return err
			}
			if waiting {
				break
			}
			select {
			case result := <-written:
				return fmt.Errorf("writer finished before source-lock race: %+v", result)
			default:
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("writer never waited on source row lock")
			}
			time.Sleep(10 * time.Millisecond)
		}
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
			SET expires_at=clock_timestamp()
			WHERE tenant_id=$1 AND agent_id='collector-a1' AND source_kind='device_target'`, a.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-written:
		if result.err != nil || result.accepted != 0 || result.unresolved != 1 {
			t.Fatalf("source expiry during lock wait created a current claim: %+v", result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("source-expiry writer did not finish")
	}
}
