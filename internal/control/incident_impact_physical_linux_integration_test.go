// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && linux

package control

import (
	"context"
	"strconv"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/slo"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func prepareDependencyPhysicalImpact(t *testing.T, d *dependencyRoutingFixture) {
	t.Helper()
	definitions := []slo.SLO{}
	for _, tenant := range d.f.tenants {
		d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permFlowRead, permTestRead, permTagsRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, d.f.roles[tenant], permission); err != nil {
					return err
				}
			}
			tag := gouuid.NewString()
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES($1,$2,'customer')`, tenant, tag); err != nil {
				return err
			}
			for _, node := range d.graphs[tenant].Nodes {
				if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_assignments(tenant_id,context_id,id,tag_id,target_kind,test_id,value,source) VALUES($1,$2,$3,$4,'test',$5,$6,'manual')`, tenant, d.f.contextID, gouuid.NewString(), tag, node.TestID, "physical-customer-"+tenant); err != nil {
					return err
				}
				definitions = append(definitions, slo.SLO{TenantID: tenant, Name: "physical-objective-" + node.TestID, CanaryType: "icmp", TestID: node.TestID, Objective: 0.999, Window: 24 * time.Hour})
			}
			return nil
		})
	}
	d.f.server.WithSLO(slo.NewEngine(definitions))
}

// The network fault, collector IO and issued mTLS receipts already belong to
// this lab. No SQL inserts or historical-clock changes manufacture an outcome.
func assertDependencyPhysicalImpact(t *testing.T, d *dependencyRoutingFixture, lane *dependencyPhysicalLane, client *sdk.Client, id string) {
	t.Helper()
	include := true
	response, err := client.GetIncidentImpact(t.Context(), sdk.GetIncidentImpactRequest{Id: id, Body: &sdk.IncidentImpactInput{
		From: lane.impactFrom.Format(time.RFC3339Nano), To: time.Now().UTC().Format(time.RFC3339Nano), IncludeTests: &include, CustomerTagKey: "customer",
	}})
	if err != nil || response == nil || len(response.Tests) != len(d.graphs[lane.tenant].Nodes) || response.ValidUntil == "" {
		t.Fatal("real-sender impact lost complete test membership or current validity", response, err)
	}
	allOriginal, failedOriginal := map[string]bool{}, map[string]bool{}
	originalTests := map[string]string{}
	objectives := map[string]int{}
	for _, test := range response.Tests {
		index := -1
		for i, node := range d.graphs[lane.tenant].Nodes {
			if test.TestId == node.TestID && test.EntityId == node.EntityID && test.AgentId == node.AgentID && test.ContextId == d.f.contextID {
				index = i
			}
		}
		if index < 0 || len(test.Current.Observations) != len(lane.measured) || len(test.Previous.Observations) != 0 || test.Previous.Coverage != "no_retained_observations" {
			t.Fatal("real-sender impact borrowed another source or invented baseline coverage", test)
		}
		expected := map[string]dependencyPhysicalMeasurement{}
		for _, batch := range lane.measured {
			if index >= len(batch) || batch[index].EvidenceID == "" {
				t.Fatal("physical sender did not retain its acknowledged original receipt")
			}
			expected[batch[index].EvidenceID] = batch[index]
		}
		failed := 0
		for _, observation := range test.Current.Observations {
			original, found := expected[observation.EvidenceId]
			if !found {
				t.Fatal("impact substituted a modeled, duplicate or foreign receipt", observation)
			}
			delete(expected, observation.EvidenceId)
			m := original.Measurement
			at, err := time.Parse(time.RFC3339Nano, observation.ObservedAt)
			if err != nil || !at.Equal(m.CompletedAt.UTC().Truncate(time.Microsecond)) || len(observation.Digest) != 64 || observation.Packets.Requested != strconv.Itoa(m.Expected) || observation.Packets.Transmitted != strconv.Itoa(m.Transmitted) || observation.Packets.Received != strconv.Itoa(m.Replies) || observation.Packets.Lost != strconv.Itoa(m.Transmitted-m.Replies) {
				t.Fatal("impact changed original physical observation clocks or packet counters", observation, m, err)
			}
			status := "failed"
			if original.Result.Success {
				status = "successful"
			} else {
				failed++
				failedOriginal[observation.EvidenceId] = true
			}
			if observation.Status != status {
				t.Fatal("impact changed the original collector outcome", observation, original.Result)
			}
			allOriginal[observation.EvidenceId] = true
			originalTests[observation.EvidenceId] = test.TestId
		}
		if len(expected) != 0 || test.Current.Failed != failed || test.Current.Unknown != 0 {
			t.Fatal("impact omitted original physical measurements", expected, test.Current)
		}
		objectives["physical-objective-"+test.TestId] = failed
	}
	if len(response.Slos) != len(objectives) {
		t.Fatal("real-sender impact lost failed SLO input populations", response.Slos, objectives)
	}
	sloEvidence := map[string]bool{}
	for _, objective := range response.Slos {
		expected, found := objectives[objective.Name]
		if !found || objective.Current.FailedInputs != expected || objective.Previous.FailedInputs != 0 || objective.Basis != "observed_failed_sli_inputs_only_not_a_rolling_budget_verdict" {
			t.Fatal("physical SLO inputs borrowed another tenant or invented a rolling verdict", objective, objectives)
		}
		for _, source := range objective.Current.Sources {
			if objective.Name != "physical-objective-"+source.TestId || source.ContextId != d.f.contextID {
				t.Fatal("physical SLO citation lost its original source", source)
			}
			for _, evidence := range source.EvidenceIds {
				if !failedOriginal[evidence] || sloEvidence[evidence] || originalTests[evidence] != source.TestId {
					t.Fatal("physical SLO citation was not one distinct failed original input", evidence)
				}
				sloEvidence[evidence] = true
			}
		}
	}
	if len(sloEvidence) != len(failedOriginal) || len(response.Customers) != 1 {
		t.Fatal("real-sender impact omitted failed-input/customer attribution", response.Slos, response.Customers)
	}
	customer := response.Customers[0]
	if customer.Value != "physical-customer-"+lane.tenant || customer.ContextId != d.f.contextID || len(customer.TestIds) != len(objectives) || len(customer.SloIds) != len(objectives) || len(customer.TagIds) != 1 || customer.CurrentObservedTotals.RawBytes != "" || customer.PreviousObservedTotals.RawBytes != "" || len(customer.EvidenceIds) != len(failedOriginal) {
		t.Fatal("real-sender customer attribution invented traffic or changed measured membership", customer)
	}
	for _, evidence := range customer.EvidenceIds {
		if !failedOriginal[evidence] || !allOriginal[evidence] {
			t.Fatal("physical customer citation borrowed an unmeasured or foreign outcome", evidence)
		}
		delete(failedOriginal, evidence)
	}
	if len(failedOriginal) != 0 {
		t.Fatal("physical customer attribution omitted or duplicated original failed inputs", failedOriginal)
	}
	t.Log("real-integration: physical ICMP through issued mTLS and app-role PG/RLS to HTTPS SDK impact, exact original clocks/counters/IDs, failed SLO inputs and owned customer tags; G4a real-flow/week-baseline proof remains owed")
}
