// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowstore

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestKubernetesExplorerRealClockJoinsKeepUnknownsAndTwoTenants(t *testing.T) {
	backend := explorerIntegrationStore(t)
	t.Cleanup(func() { _ = backend.Close() })
	memory := NewMemory()
	tenants := []string{uuid.NewString(), uuid.NewString()}
	const contextID = "33333333-3333-4333-8333-333333333333"
	var projections [2]*KubernetesQueryData
	var plans [2]flow.QueryPlan
	for lane, tenant := range tenants {
		t.Cleanup(func() { cleanupExplorerFixtureTenant(t, backend, tenant) })
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		rows, _ := routingReferencePopulation(t, tenant, 3)
		facts := make([]KubernetesFlowProjection, 0, 2)
		for i := range rows {
			row := &rows[i]
			row.ClockBasis = flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL
			row.StartTS = row.TS.Add(-time.Second)
			row.BytesScaled = uint64(i + 1)
			if i == 2 {
				continue // The raw flow has no Kubernetes address witness.
			}
			ref, err := routingReadFromRow(*row)
			if err != nil {
				t.Fatal(err)
			}
			ref.Timing = FlowCaptureTiming{Start: row.StartTS, End: row.TS, Basis: row.ClockBasis}
			if i == 1 {
				ref.Timing.Start = ref.Timing.Start.Add(-time.Millisecond)
			}
			facts = append(facts, KubernetesFlowProjection{
				Scope: entity.Scope{TenantID: tenant, ContextID: contextID}, Capture: ref,
				Source:      KubernetesFlowEndpoint{Cluster: contextID, Namespace: fmt.Sprintf("lane-%d", lane), Pod: "web", PodUID: "pod-one"},
				Destination: KubernetesFlowEndpoint{Cluster: contextID, Namespace: fmt.Sprintf("lane-%d", lane), Service: "frontend", ServiceUID: "svc-one"},
			})
		}
		for _, receiver := range []Store{backend, memory} {
			if err := receiver.Insert(ctx, rows); err != nil {
				t.Fatal(err)
			}
		}
		var err error
		projections[lane], err = NewKubernetesQueryData(ctx, tenant, facts, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		plans[lane] = flow.QueryPlan{From: rows[0].TS.Add(-time.Minute), To: rows[0].TS.Add(time.Minute),
			View: "matrix", GroupBy: []string{"src_k8s_namespace"}, MatrixWith: []string{"dst_k8s_service"},
			Metrics: []flow.QueryMetric{{Measure: "flows", Calculation: "total", Role: "primary"}}}
	}
	for lane, tenant := range tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		expectedNamespace := fmt.Sprintf("lane-%d", lane)
		for _, store := range []PlanStore{memory, backend} {
			query := PlanQuery{TenantID: tenant, Plan: plans[lane], Kubernetes: projections[lane]}
			result, err := store.ExplorePlan(ctx, query)
			if err != nil || result.Totals["flows:total"] != "3" || len(result.Matrix) != 2 {
				t.Fatal("Kubernetes join lost traffic or changed matrix cardinality", err, result)
			}
			for _, cell := range result.Matrix {
				switch namespace := cell.Row["src_k8s_namespace"]; namespace {
				case expectedNamespace:
					if cell.Column["dst_k8s_service"] != "frontend" || cell.Metrics["flows:total"] != "1" {
						t.Fatal("the original flow clock did not select exactly one owned Service", cell)
					}
				case "":
					if cell.Column["dst_k8s_service"] != "" || cell.Metrics["flows:total"] != "2" {
						t.Fatal("the unmatched or shifted clock was attributed", cell)
					}
				default:
					t.Fatal("matrix exposed a different namespace", namespace)
				}
			}
			query.Plan.Filter = &flow.QueryFilterGroup{Groups: []flow.QueryFilterGroup{{Mode: "exclude", Conditions: []flow.QueryPredicate{
				{Field: "src_k8s_namespace", Op: flow.QueryEqual, Values: []string{"unrelated"}},
			}}}}
			filtered, err := store.ExplorePlan(ctx, query)
			if err != nil || filtered.Totals["flows:total"] != "1" {
				t.Fatal("ordinary exclusion converted unknown Kubernetes values to matches", filtered, err)
			}
			query.Kubernetes = projections[1-lane]
			if _, err := store.ExplorePlan(ctx, query); !errors.Is(err, ErrKubernetesQueryScope) {
				t.Fatal("sibling lookup was consumed in a tenant query", err)
			}
		}
	}
}
