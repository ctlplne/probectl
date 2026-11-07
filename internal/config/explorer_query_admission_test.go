// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
)

func TestDefaultQueryAdmissionKeepsCompleteExplorerWorkflowAndTenantFairness(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FairnessQueriesPerMin <= 0 || cfg.FairnessQueryConcurrency <= 0 {
		t.Fatal("default explorer admission became unbounded")
	}
	gate := fairness.NewGate(fairness.Policy{QueriesPerMin: cfg.FairnessQueriesPerMin, QueryConcurrency: cfg.FairnessQueryConcurrency}, nil).WithNow(func() time.Time { return time.Unix(1700000000, 0) })
	// One complete registry sweep: original value, own-value filter and foreign
	// negative for every dimension, then all 8x8 cells and native/UI controls.
	workload := 3*len(flow.QueryFields()) + 8*8 + 8
	for i := 0; i < workload; i++ {
		release, err := gate.BeginQuery(t.Context(), "red")
		if err != nil {
			t.Fatalf("default query admission stopped complete explorer workflow at %d/%d: %v", i, workload, err)
		}
		release()
	}
	for i := workload; i < int(cfg.FairnessQueriesPerMin); i++ {
		release, err := gate.BeginQuery(t.Context(), "red")
		if err != nil {
			t.Fatal("configured query allowance was truncated", i, err)
		}
		release()
	}
	if _, err := gate.BeginQuery(t.Context(), "red"); !errors.Is(err, fairness.ErrQueryBudget) {
		t.Fatal("complete explorer admission lost its finite resource bound", err)
	}
	release, err := gate.BeginQuery(t.Context(), "blue")
	if err != nil {
		t.Fatal("query debt crossed tenants", err)
	}
	release()
	override, err := Load(envFunc(map[string]string{"PROBECTL_FAIRNESS_QUERIES_PER_MIN": "2400"}))
	if err != nil || override.FairnessQueriesPerMin != 2400 {
		t.Fatal("operator query allowance was clamped", err)
	}
}
