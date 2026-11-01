// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration || isolation

package silo

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestEntityRegistrySiloForeignKeysRejectForeignContext proves the constraints
// that CREATE TABLE LIKE does not copy. These checks use the migration login
// directly, so RLS or a handler predicate cannot hide a missing foreign key.
func TestEntityRegistrySiloForeignKeysRejectForeignContext(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := context.Background()
	stamp := fmt.Sprintf("%d", time.Now().UnixNano())
	a := mkTenant(t, pool, "entity-silo-a-"+stamp, "siloed", "")
	b := mkTenant(t, pool, "entity-silo-b-"+stamp, "siloed", "")
	prov := NewProvisioner(pool, CHPlanes{}, nil, 0,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, tenant := range []string{a, b} {
		if err := prov.Provision(ctx, tenant, "", tenancy.IsolationSiloed); err != nil {
			t.Fatalf("provision entity silo: %v", err)
		}
	}
	t.Cleanup(func() {
		for _, tenant := range []string{a, b} {
			if err := prov.Teardown(context.Background(), tenant, "", tenancy.IsolationSiloed); err != nil {
				t.Errorf("teardown entity silo: %v", err)
			}
		}
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove entity silo fixture tenants: %v", err)
		}
	})
	contextA, contextOther := uuid.NewString(), uuid.NewString()
	site, vrf := uuid.NewString(), uuid.NewString()
	entityA, entityOther, entityB := uuid.NewString(), uuid.NewString(), uuid.NewString()
	seed := func(tenant, routingContext, vrfID, entityID string) {
		t.Helper()
		schema := quoteIdent(SchemaName(tenant))
		agentID := "device-agent"
		if routingContext == contextOther {
			agentID = "device-agent-other"
		} else if tenant == b && routingContext != contextA {
			agentID = "device-agent-foreign"
		}
		if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.entity_contexts
			(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
                VALUES ($1,$2,$3,$4,$3::uuid::text,$4::uuid::text)`,
			tenant, routingContext, site, vrfID); err != nil {
			t.Fatalf("seed silo context: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.entity_agent_contexts
			(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`,
			tenant, agentID, routingContext); err != nil {
			t.Fatalf("seed silo agent context: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.entity_source_contexts
			(tenant_id,agent_id,source_kind,source_ref,context_id)
			VALUES ($1,$2,'device_target','10.42.0.1',$3)`,
			tenant, agentID, routingContext); err != nil {
			t.Fatalf("seed silo source context: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO `+schema+`.entities
			(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'device','router')`,
			tenant, routingContext, entityID); err != nil {
			t.Fatalf("seed silo entity: %v", err)
		}
	}
	seed(a, contextA, vrf, entityA)
	seed(a, contextOther, uuid.NewString(), entityOther)
	seed(b, contextA, vrf, entityB) // Same context UUID in another tenant.
	foreignContext := uuid.NewString()
	seed(b, foreignContext, uuid.NewString(), uuid.NewString())
	schemaA := quoteIdent(SchemaName(a))
	testA, testB := uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.tests
		(id,tenant_id,name,target) VALUES ($1,$2,'entity-path-a','10.42.0.1')`, testA, a); err != nil {
		t.Fatalf("seed own path test: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+quoteIdent(SchemaName(b))+`.tests
		(id,tenant_id,name,target) VALUES ($1,$2,'entity-path-b','10.42.0.1')`, testB, b); err != nil {
		t.Fatalf("seed other tenant path test: %v", err)
	}
	for name, row := range map[string]struct{ test, context string }{
		"other tenant test":    {testB, contextA},
		"other tenant context": {testA, foreignContext},
		"missing context":      {testA, uuid.NewString()},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.entity_path_test_contexts
			(tenant_id,test_id,context_id,path_target) VALUES ($1,$2,$3,'10.42.0.1')`,
			a, row.test, row.context); err == nil {
			t.Fatalf("silo accepted %s path binding", name)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.entity_path_test_contexts
		(tenant_id,test_id,context_id,path_target) VALUES ($1,$2,$3,'10.42.0.1')`,
		a, testA, contextA); err != nil {
		t.Fatalf("silo rejected own path binding: %v", err)
	}
	schemaB := quoteIdent(SchemaName(b))
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaB+`.entity_path_test_contexts
		(tenant_id,test_id,context_id,path_target) VALUES ($1,$2,$3,'10.42.0.1')`,
		b, testB, contextA); err != nil {
		t.Fatalf("other silo rejected its own same-address path binding: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE `+schemaA+`.tests SET target='10.42.0.2'
		WHERE tenant_id=$1 AND id=$2`, a, testA); err != nil {
		t.Fatalf("retarget silo test: %v", err)
	}
	for _, fixture := range []struct {
		schema, tenant, test string
		want                 int
	}{
		{schemaA, a, testA, 0}, {schemaB, b, testB, 1},
	} {
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+fixture.schema+`.entity_path_test_contexts
			WHERE tenant_id=$1 AND test_id=$2`, fixture.tenant, fixture.test).Scan(&count); err != nil || count != fixture.want {
			t.Fatalf("retarget trigger crossed silo boundary: tenant=%s count=%d want=%d err=%v",
				fixture.tenant, count, fixture.want, err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.entity_agent_contexts
		(tenant_id,agent_id,context_id) VALUES ($1,'site-agent',$2)`, a, contextA); err != nil {
		t.Fatalf("seed site agent context: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.entity_agent_contexts
		(tenant_id,agent_id,context_id) VALUES ($1,'unassigned-agent',$2)`, a, foreignContext); err == nil {
		t.Fatal("silo accepted an agent bound to another tenant's context")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.entity_source_contexts
		(tenant_id,agent_id,source_kind,source_ref,context_id)
		VALUES ($1,'site-agent','agent_site','other-vrf',$2)`, a, contextOther); err == nil {
		t.Fatal("silo accepted a second context for one evidence agent")
	}
	for name, routingContext := range map[string]string{
		"foreign tenant context": foreignContext,
		"missing context":        uuid.NewString(),
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.entity_source_contexts
			(tenant_id,agent_id,source_kind,source_ref,context_id)
			VALUES ($1,'site-agent','agent_site','site',$2)`, a, routingContext); err == nil {
			t.Fatalf("silo accepted %s source assignment", name)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.entity_source_contexts
		(tenant_id,agent_id,source_kind,source_ref,context_id)
		VALUES ($1,'site-agent','agent_site','site',$2)`, b, contextA); err == nil {
		t.Fatal("silo accepted another tenant's source assignment with a shared context UUID")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.entity_source_contexts
		(tenant_id,agent_id,source_kind,source_ref,context_id)
		VALUES ($1,'site-agent','agent_site','site',$2)`, a, contextA); err != nil {
		t.Fatalf("silo rejected own source assignment: %v", err)
	}
	for name, anchor := range map[string]string{
		"another tenant's canonical entity": entityB,
		"another VRF's canonical entity":    entityOther,
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.entity_source_contexts
			(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
			VALUES ($1,'site-agent','agent_site',$2,$3,$4)`,
			a, name, contextA, anchor); err == nil {
			t.Fatalf("silo accepted %s as a source anchor", name)
		}
	}
	insertEvidence := func(entityID string) (string, error) {
		id := uuid.NewString()
		_, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.entity_evidence
			(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,source,source_ref,
			 agent_id,source_kind,configured_ref,observed_at,sender_serial)
			VALUES ($1,$2,$3,$3,$4,'address','10.42.0.1','snmp','router',
			        'device-agent','device_target','10.42.0.1',clock_timestamp(),'ab1234')`,
			a, contextA, id, entityID)
		return id, err
	}
	for name, foreign := range map[string]string{"same-tenant other VRF": entityOther, "other tenant same VRF": entityB} {
		if _, err := insertEvidence(foreign); err == nil {
			t.Fatalf("silo accepted %s entity reference", name)
		}
	}
	evidenceA, err := insertEvidence(entityA)
	if err != nil {
		t.Fatalf("silo rejected own context-bound evidence: %v", err)
	}
	evidenceB := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaB+`.entity_evidence
		(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,
		 source,source_ref,agent_id,source_kind,configured_ref,observed_at,sender_serial)
		VALUES ($1,$2,$3,$3,$4,'address','10.42.0.1','snmp','router',
		        'device-agent','device_target','10.42.0.1',clock_timestamp(),'ab1234')`,
		b, contextA, evidenceB, entityB); err != nil {
		t.Fatalf("seed foreign tenant support evidence: %v", err)
	}
	insertInferred := func(supportID string) error {
		id := uuid.NewString()
		_, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.entity_evidence
			(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,
			 source,source_ref,agent_id,source_kind,configured_ref,observed_at,
			 sender_serial,support_evidence_id)
			VALUES ($1,$2,$3,$3,$4,'flow_exporter_id','10.42.0.1/ipfix/99',
			        'flow','flow:ipfix:domain:99','flow-agent','flow_exporter',
			        '10.42.0.1',clock_timestamp(),'ab1234',$5)`,
			a, contextA, id, entityA, supportID)
		return err
	}
	if err := insertInferred(evidenceB); err == nil {
		t.Fatal("silo accepted another tenant's SNMP support evidence")
	}
	if err := insertInferred(evidenceA); err != nil {
		t.Fatalf("silo rejected its own context-bound SNMP support: %v", err)
	}
	neighborA := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.entities
		(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'device','neighbor')`,
		a, contextA, neighborA); err != nil {
		t.Fatalf("seed own link target: %v", err)
	}
	insertLink := func(from, to, evidence string) error {
		_, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.entity_links
			(tenant_id,context_id,id,from_entity_id,to_entity_id,evidence_id,kind,observed_at)
			VALUES ($1,$2,$3,$4,$5,$6,'physical',clock_timestamp())`,
			a, contextA, uuid.NewString(), from, to, evidence)
		return err
	}
	for name, link := range map[string]struct{ from, to, evidence string }{
		"other tenant target": {entityA, entityB, evidenceA},
		"other VRF target":    {entityA, entityOther, evidenceA},
		"other tenant source": {entityB, neighborA, evidenceA},
		"missing evidence":    {entityA, neighborA, uuid.NewString()},
	} {
		if err := insertLink(link.from, link.to, link.evidence); err == nil {
			t.Fatalf("silo accepted %s link", name)
		}
	}
	if err := insertLink(entityA, neighborA, evidenceA); err != nil {
		t.Fatalf("silo rejected own evidence-backed link: %v", err)
	}
	incidentA, incidentB := uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.incidents
		(tenant_id,id,title,entity_context_id,entity_id,identity_lookup_attempted)
		VALUES ($1,$2,'own incident',$3,$4,true)`, a, incidentA, contextA, entityA); err != nil {
		t.Fatalf("silo rejected own verified incident: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaB+`.incidents
		(tenant_id,id,title,entity_context_id,entity_id,identity_lookup_attempted)
		VALUES ($1,$2,'other incident',$3,$4,true)`, b, incidentB, contextA, entityB); err != nil {
		t.Fatalf("seed other silo incident: %v", err)
	}
	insertFaultReceipt := func(incidentID string) error {
		_, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.entity_fault_receipts
			(tenant_id,agent_id,observation_id,source_kind,source_ref,payload_fingerprint,incident_id)
			VALUES ($1,'device-agent',$2,'device_target','10.42.0.1',$3,$4)`,
			a, uuid.NewString(), fmt.Sprintf("%064x", 1), incidentID)
		return err
	}
	if err := insertFaultReceipt(incidentB); err == nil {
		t.Fatal("silo accepted a fault receipt pointing at another tenant's incident")
	}
	if err := insertFaultReceipt(incidentA); err != nil {
		t.Fatalf("silo rejected its own incident fault receipt: %v", err)
	}
	for name, identity := range map[string]struct{ context, entity string }{
		"other tenant entity":    {contextA, entityB},
		"other VRF entity":       {contextA, entityOther},
		"entity without context": {"", entityA},
	} {
		if name == "entity without context" {
			if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.incidents
				(tenant_id,id,title,entity_id) VALUES ($1,$2,'invalid',$3)`,
				a, uuid.NewString(), identity.entity); err == nil {
				t.Fatal("silo accepted an entity ID without its verified context")
			}
			continue
		}
		if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.incidents
			(tenant_id,id,title,entity_context_id,entity_id,identity_lookup_attempted)
			VALUES ($1,$2,'invalid',$3,$4,true)`,
			a, uuid.NewString(), identity.context, identity.entity); err == nil {
			t.Fatalf("silo accepted %s on incident", name)
		}
	}
	insertSignal := func(incidentID, identityID string) error {
		_, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.incident_signals
			(tenant_id,incident_id,plane,kind,entity_context_id,entity_id,identity_lookup_attempted)
			VALUES ($1,$2,'device','alert.firing',$3,$4,true)`,
			a, incidentID, contextA, identityID)
		return err
	}
	if err := insertSignal(incidentB, entityA); err == nil {
		t.Fatal("silo accepted a tenant A signal pointing to tenant B's incident")
	}
	if err := insertSignal(incidentA, entityB); err == nil {
		t.Fatal("silo accepted a tenant B entity on tenant A's signal")
	}
	if err := insertSignal(incidentA, entityA); err != nil {
		t.Fatalf("silo rejected own verified signal: %v", err)
	}
	var signalA string
	if err := pool.QueryRow(ctx, `SELECT id::text FROM `+schemaA+`.incident_signals
		WHERE tenant_id=$1 AND incident_id=$2 LIMIT 1`, a, incidentA).Scan(&signalA); err != nil {
		t.Fatalf("read own silo incident signal: %v", err)
	}
	var signalB string
	if err := pool.QueryRow(ctx, `INSERT INTO `+schemaB+`.incident_signals
		(tenant_id,incident_id,plane,kind,entity_context_id,entity_id,identity_lookup_attempted)
		VALUES ($1,$2,'device','alert.firing',$3,$4,true) RETURNING id::text`,
		b, incidentB, contextA, entityB).Scan(&signalB); err != nil {
		t.Fatalf("seed other silo incident signal: %v", err)
	}
	detachedA := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.incidents
		(tenant_id,id,title,entity_context_id,entity_id,identity_lookup_attempted)
		VALUES ($1,$2,'detached incident',$3,$4,true)`, a, detachedA, contextA, entityA); err != nil {
		t.Fatalf("seed own detached incident: %v", err)
	}
	insertOverride := func(sourceIncident, detached, sourceSignal, entityID string) error {
		_, err := pool.Exec(ctx, `INSERT INTO `+schemaA+`.incident_correlation_overrides
			(tenant_id,source_incident_id,detached_incident_id,source_signal_id,
			 plane,kind,target,prefix,reason,created_by,
			 entity_context_id,entity_id,identity_lookup_attempted)
			VALUES ($1,$2,$3,$4,'device','alert.firing','10.42.0.1','',
			        'separate fault','operator-a',$5,$6,true)`,
			a, sourceIncident, detached, sourceSignal, contextA, entityID)
		return err
	}
	if err := insertOverride(incidentB, detachedA, signalA, entityA); err == nil {
		t.Fatal("silo accepted an override sourced from another tenant's incident")
	}
	if err := insertOverride(incidentA, incidentB, signalA, entityA); err == nil {
		t.Fatal("silo accepted an override detached to another tenant's incident")
	}
	if err := insertOverride(incidentA, detachedA, signalB, entityA); err == nil {
		t.Fatal("silo accepted an override citing another tenant's signal")
	}
	if err := insertOverride(incidentA, detachedA, signalA, entityB); err == nil {
		t.Fatal("silo accepted another tenant's canonical entity on an override")
	}
	if err := insertOverride(incidentA, detachedA, signalA, entityA); err != nil {
		t.Fatalf("silo rejected its own verified override: %v", err)
	}
	assertEntityRegistrySiloFKs(t, pool, SchemaName(a))
	// Simulate a pre-FX-2 silo that retained the raw-address-only unique
	// override index. Catch-up must rebuild the scoped one online, then remove
	// the old one; a repeated catch-up must remain idempotent.
	var scopedIndex string
	if err := pool.QueryRow(ctx, `SELECT x.relname FROM pg_index i
		JOIN pg_class x ON x.oid=i.indexrelid
		JOIN pg_class r ON r.oid=i.indrelid
		JOIN pg_namespace n ON n.oid=r.relnamespace
		WHERE n.nspname=$1 AND r.relname='incident_correlation_overrides'
		  AND i.indisunique AND i.indnkeyatts=9 LIMIT 1`, SchemaName(a)).Scan(&scopedIndex); err != nil {
		t.Fatalf("find new silo override index: %v", err)
	}
	if _, err := pool.Exec(ctx, `DROP INDEX CONCURRENTLY `+schemaA+`.`+quoteIdent(scopedIndex)); err != nil {
		t.Fatalf("simulate old silo override index: %v", err)
	}
	if _, err := pool.Exec(ctx, `CREATE UNIQUE INDEX CONCURRENTLY "legacy_override_raw_idx"
		ON `+schemaA+`.incident_correlation_overrides
		(tenant_id,source_incident_id,plane,kind,target,prefix) WHERE active`); err != nil {
		t.Fatalf("install old silo override index: %v", err)
	}
	if err := prov.CatchUp(ctx, a); err != nil {
		t.Fatalf("first entity silo catch-up: %v", err)
	}
	if err := prov.CatchUp(ctx, a); err != nil {
		t.Fatalf("idempotent entity silo catch-up: %v", err)
	}
	assertEntityRegistrySiloFKs(t, pool, SchemaName(a))
	var scopedCount, legacyCount int
	if err := pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE i.indisvalid AND i.indnkeyatts=9),
		count(*) FILTER (WHERE i.indnkeyatts=6)
		FROM pg_index i
		JOIN pg_class r ON r.oid=i.indrelid
		JOIN pg_namespace n ON n.oid=r.relnamespace
		WHERE n.nspname=$1 AND r.relname='incident_correlation_overrides'
		  AND i.indisunique AND i.indpred IS NOT NULL`, SchemaName(a)).Scan(&scopedCount, &legacyCount); err != nil ||
		scopedCount != 1 || legacyCount != 0 {
		t.Fatalf("silo override catch-up index repair: scoped=%d legacy=%d err=%v",
			scopedCount, legacyCount, err)
	}
	for name, foreign := range map[string]string{"same-tenant other VRF": entityOther, "other tenant same VRF": entityB} {
		if _, err := insertEvidence(foreign); err == nil {
			t.Fatalf("caught-up silo accepted %s entity reference", name)
		}
	}
}

func assertEntityRegistrySiloFKs(t *testing.T, pool *pgxpool.Pool, schema string) {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM pg_constraint c
		JOIN pg_class r ON r.oid=c.conrelid
		JOIN pg_namespace n ON n.oid=r.relnamespace
		WHERE n.nspname=$1 AND c.contype='f'
		AND c.conname=ANY($2::text[])`, schema, []string{
		"fx2_context_tenant_fk", "fx2_path_test_fk", "fx2_path_context_fk",
		"fx2_agent_context_fk", "fx2_source_context_fk",
		"fx2_source_agent_context_fk", "fx2_source_anchor_fk",
		"fx2_entity_context_fk", "fx2_interface_parent_fk", "fx2_evidence_entity_fk",
		"fx2_evidence_support_fk",
		"fx2_link_from_fk", "fx2_link_to_fk", "fx2_link_evidence_fk",
		"fx2_incident_entity_fk", "fx2_signal_entity_fk", "fx2_signal_incident_fk",
		"fx2_override_entity_fk", "fx2_override_source_fk",
		"fx2_override_detached_fk", "fx2_override_signal_fk",
	}).Scan(&count); err != nil || count != 21 {
		t.Fatalf("registry silo foreign keys=%d, want 21: %v", count, err)
	}
}
