// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
)

type dependencyHealthPopulationRow struct {
	alert.DependencyNodeInput
	Target, EvidenceID, ObservationID string
	Measurement                       *entity.ICMPMeasurement
}

func TestDependencyHealthCompleteTwentyThousandCurrentSourcePopulation(t *testing.T) {
	d := seedDependencyRoutingFixture(t)
	observedPool := dependencyPopulationObservedPool(t, d.f.pool)
	// Bulk cleanup is confined to these fixture tenants and runs before their
	// parent cleanup. It does not stand in for tenant-lifecycle acceptance.
	t.Cleanup(func() {
		for _, query := range []string{
			`DELETE FROM entity_source_contexts WHERE tenant_id=ANY($1::uuid[])`,
			`DELETE FROM entity_path_test_contexts WHERE tenant_id=ANY($1::uuid[])`,
			`DELETE FROM entity_test_contexts WHERE tenant_id=ANY($1::uuid[])`,
		} {
			if _, err := d.f.pool.Exec(context.Background(), query, d.f.tenants); err != nil {
				t.Error(err)
			}
		}
	})
	for lane, tenant := range d.f.tenants {
		rows, graph := seedDependencyHealthPopulation(t, d, tenant, 20_000)
		t.Logf("seeded complete current-source population: tenant lane %d", lane)
		err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), observedPool, func(ctx context.Context, sc tenancy.Scope) error {
			policy := &alert.DependencyPolicy{ContextID: d.f.contextID, FreshnessSeconds: 300, Graph: graph}
			snapshot, health, err := d.f.server.dependencyHealthSnapshot(ctx, sc, policy, 512<<20)
			if err != nil || !snapshot.Complete || len(snapshot.Vertices) != len(rows) || len(health) != len(rows) || len(snapshot.Causes) != 1 {
				t.Fatal("complete current source population was refused or shortened", len(health), err)
			}
			t.Logf("read complete current-source population: tenant lane %d", lane)
			decider, err := alert.PrepareDependencyNotifications(ctx, snapshot, 512<<20, 512<<20)
			if err != nil {
				t.Fatal(err)
			}
			for i, row := range rows {
				value := health[row.EntityID]
				if value.State != "down" || value.EvidenceID != row.EvidenceID || value.Observation.ID != row.ObservationID || value.Observation.Source.SourceRef != row.TestID || value.SenderSerial != d.serials[tenant] {
					t.Fatal("source population lost its exact current evidence", i)
				}
				attempt := alert.DependencyAttempt{Alert: alert.Alert{TenantID: tenant, RuleID: d.rules[tenant].ID, State: alert.StateFiring,
					Labels: map[string]string{"test_id": row.TestID, "agent_id": row.AgentID}}}
				decision, err := decider.Decide(ctx, attempt, row.EntityID, true)
				if err != nil || decision.Held() != (i > 0) {
					t.Fatal("full source-backed series population lost a decision", i, err)
				}
				if i > 0 {
					causes := decision.Causes()
					if len(causes) != 1 || causes[0].IncidentID != d.cases[tenant] || causes[0].TenantID != tenant {
						t.Fatal("series borrowed a foreign or incomplete root cause", i)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Log("real-integration: all 20,000 current source/alias/canonical-case reads and decisions in each RLS tenant; evidence and initial cases modeled, not physical senders or durable full-population publication")
}

func seedDependencyHealthPopulation(t *testing.T, d *dependencyRoutingFixture, tenant string, count int) ([]dependencyHealthPopulationRow, *alert.DependencyGraphInput) {
	t.Helper()
	rows := make([]dependencyHealthPopulationRow, count)
	graph := &alert.DependencyGraphInput{}
	for i := range rows {
		node := alert.DependencyNodeInput{EntityID: gouuid.NewString(), AgentID: d.graphs[tenant].Nodes[0].AgentID, TestID: gouuid.NewString(), Parents: []string{}}
		if i == 0 {
			node.EntityID = d.graphs[tenant].Nodes[0].EntityID
		} else {
			node.Parents = []string{rows[i-1].EntityID}
		}
		rows[i] = dependencyHealthPopulationRow{DependencyNodeInput: node, Target: fmt.Sprintf("2001:db8::%x", i+1), EvidenceID: gouuid.NewString(), ObservationID: gouuid.NewString()}
		graph.Nodes = append(graph.Nodes, node)
	}
	seed, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		for _, query := range []string{
			`INSERT INTO entities(tenant_id,context_id,id,kind,label) SELECT $1,$2,ref.entity_id,'device','dependency device' FROM jsonb_to_recordset($3::jsonb) AS ref(entity_id uuid) ON CONFLICT DO NOTHING`,
			`INSERT INTO tests(tenant_id,id,name,type,target,interval_seconds,timeout_seconds,params,enabled) SELECT $1,ref.test_id,'dependency ICMP '||ref.test_id::text,'icmp',ref."Target",30,2,'{"allow_private_targets":"true","count":"1"}',true FROM jsonb_to_recordset($3::jsonb) AS ref(test_id uuid,"Target" text) WHERE $2::uuid IS NOT NULL`,
			`INSERT INTO entity_test_contexts(tenant_id,context_id,test_id) SELECT $1,$2,ref.test_id FROM jsonb_to_recordset($3::jsonb) AS ref(test_id uuid)`,
			`INSERT INTO entity_path_test_contexts(tenant_id,context_id,test_id,path_target) SELECT $1,$2,ref.test_id,ref."Target" FROM jsonb_to_recordset($3::jsonb) AS ref(test_id uuid,"Target" text)`,
			`INSERT INTO entity_source_contexts(tenant_id,context_id,agent_id,source_kind,source_ref,anchor_entity_id) SELECT $1,$2,ref.agent_id::text,'path_agent',ref.test_id::text,ref.entity_id FROM jsonb_to_recordset($3::jsonb) AS ref(agent_id uuid,test_id uuid,entity_id uuid)`,
		} {
			if _, err := sc.Q.Exec(ctx, query, tenant, d.f.contextID, seed); err != nil {
				return err
			}
		}
		var at time.Time
		if err := sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
			return err
		}
		at = at.UTC().Truncate(time.Microsecond) // same canonical form as the evidence writer
		for i := range rows {
			row := &rows[i]
			definition := testspec.ExecutableDefinition{ID: row.TestID, Type: "icmp", Target: row.Target, IntervalSeconds: 30, TimeoutSeconds: 2,
				Params: map[string]string{"allow_private_targets": "true", "count": "1"}}
			digest, err := testspec.DefinitionHash(definition)
			if err != nil {
				return err
			}
			row.Measurement = &entity.ICMPMeasurement{Version: 1, DefinitionHash: digest, StartedAt: at, CompletedAt: at, Requested: 1, Attempted: 1, Transmitted: 1, ReadComplete: true, Responders: []string{}}
		}
		body, err := json.Marshal(rows)
		if err != nil {
			return err
		}
		_, err = sc.Q.Exec(ctx, `INSERT INTO entity_evidence(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,source,source_ref,agent_id,source_kind,configured_ref,observed_at,expires_at,sender_serial,icmp_measurement)
 SELECT $1,$2,r."EvidenceID",r."ObservationID",r.entity_id,'address',r."Target",'path_agent','icmp:configured-test',r.agent_id::text,'path_agent',r.test_id::text,$4,$4::timestamptz+interval '1 hour',$5,r."Measurement"
 FROM jsonb_to_recordset($3::jsonb) AS r(entity_id uuid,agent_id uuid,test_id uuid,"Target" text,"EvidenceID" uuid,"ObservationID" uuid,"Measurement" jsonb)`, tenant, d.f.contextID, body, at, d.serials[tenant])
		return err
	})
	return rows, graph
}
