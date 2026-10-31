// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantlife"
)

type snapshotPolicyProbe struct {
	fakeTenantLifecycle
	fail, foreign bool
	seen          string
}

func (p *snapshotPolicyProbe) RetentionFor(_ context.Context, tenant string) (tenantlife.RetentionPolicy, error) {
	p.seen = tenant
	if p.fail {
		return tenantlife.RetentionPolicy{}, errors.New("private database diagnostic")
	}
	policy := p.policy
	policy.TenantID = tenant
	if p.foreign {
		policy.TenantID = "foreign"
	}
	return policy, nil
}

type snapshotCoverageProbe struct {
	flowstore.Store
	seen  string
	calls int
	fail  bool
}

func (p *snapshotCoverageProbe) VerifySnapshotInputs(_ context.Context, tenant string, _ flowstore.SnapshotInputs) error {
	p.seen = tenant
	p.calls++
	if p.fail {
		return flowstore.ErrSnapshotInputs
	}
	return nil
}

func snapshotSourceFixture() (*flowSnapshotSource, *snapshotPolicyProbe, *snapshotCoverageProbe, flowstore.PlanResult) {
	oldest := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	result := flowstore.PlanResult{Source: "raw", OldestInput: oldest, TotalGroups: 1, Query: flow.QueryPlan{From: oldest.AddDate(-100, 0, 0), To: oldest.Add(time.Hour), BucketSeconds: 60, GroupBy: []string{"protocol"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}}
	policy := &snapshotPolicyProbe{}
	coverage := &snapshotCoverageProbe{Store: flowstore.NewMemory()}
	source := &flowSnapshotSource{server: &Server{tenantLife: policy, flowStore: coverage}, deploymentDays: 1, lifetime: 15 * time.Minute, now: func() time.Time { return oldest.Add(24*time.Hour - time.Second) }}
	return source, policy, coverage, result
}

func TestFlowSnapshotSourceReceiptUsesActualInputAndRechecksPolicy(t *testing.T) {
	source, policy, coverage, result := snapshotSourceFixture()
	scope := flowsnapshot.Scope{TenantID: "tenant-a", Owner: "alice"}
	proof, until, err := source.receipt(t.Context(), scope, result)
	if err != nil {
		t.Fatal(err)
	}
	if !until.Equal(result.OldestInput.Add(24 * time.Hour)) {
		t.Fatalf("input clock used empty century-long prefix or cache TTL: %s", until)
	}
	if err := source.validate(t.Context(), scope, proof); err != nil {
		t.Fatal(err)
	}
	if policy.seen != scope.TenantID || coverage.seen != scope.TenantID {
		t.Fatal("policy/source validation crossed tenant scope")
	}
	source.now = func() time.Time { return until }
	before := coverage.calls
	if err := source.validate(t.Context(), scope, proof); err == nil {
		t.Fatal("cached response extended source input expiry")
	}
	if coverage.calls != before {
		t.Fatal("expired proof reached the data-plane reader")
	}
	// A tighter policy is re-read; a deployment optout never overrides it.
	source.deploymentDays = 0
	if err := source.validate(t.Context(), scope, proof); err != nil {
		t.Fatalf("explicit deployment optout: %v", err)
	}
	day := 1
	policy.policy.FlowRetentionDays = &day
	if err := source.validate(t.Context(), scope, proof); err == nil {
		t.Fatal("deployment optout bypassed tighter tenant retention")
	}
}

func TestFlowSnapshotSourceRefusesPolicyErrorsMalformedProofAndCoverageLoss(t *testing.T) {
	for _, name := range []string{"policy unavailable", "foreign policy", "bad JSON", "extra JSON", "unknown field", "coverage expired", "missing tenant"} {
		t.Run(name, func(t *testing.T) {
			source, policy, coverage, result := snapshotSourceFixture()
			scope := flowsnapshot.Scope{TenantID: "tenant-a", Owner: "alice"}
			proof, _, err := source.receipt(t.Context(), scope, result)
			if err != nil {
				t.Fatal(err)
			}
			beforeReader := true
			switch name {
			case "policy unavailable":
				policy.fail = true
			case "foreign policy":
				policy.foreign = true
			case "bad JSON":
				proof = json.RawMessage(`{"version":`)
			case "extra JSON":
				proof = append(proof, []byte(` {}`)...)
			case "unknown field":
				proof = append(proof[:len(proof)-1], []byte(`,"tenant_id":"foreign"}`)...)
			case "coverage expired":
				coverage.fail = true
				beforeReader = false
			case "missing tenant":
				scope.TenantID = ""
			}
			err = source.validate(t.Context(), scope, proof)
			if err == nil {
				t.Fatal("unsafe source proof accepted")
			}
			if name == "missing tenant" && !errors.Is(err, tenancy.ErrNoTenant) {
				t.Fatalf("missing tenant error: %v", err)
			}
			if beforeReader && coverage.calls != 0 {
				t.Fatal("refused source proof read telemetry")
			}
		})
	}
}

func TestFlowComparisonSnapshotRequiresBothSourceClocks(t *testing.T) {
	source, _, coverage, current := snapshotSourceFixture()
	previous := current
	previous.OldestInput = current.OldestInput.Add(-time.Second)
	source.now = func() time.Time { return current.OldestInput.Add(24*time.Hour - 2*time.Second) }
	scope := flowsnapshot.Scope{TenantID: "tenant-a", Owner: "alice"}
	proof, until, err := source.receipt(t.Context(), scope, current, previous)
	if err != nil || !until.Equal(previous.OldestInput.Add(24*time.Hour)) {
		t.Fatalf("comparison input clock: %s %v", until, err)
	}
	if err := source.validate(t.Context(), scope, proof); err != nil || coverage.calls != 2 {
		t.Fatalf("both inputs not checked: %d %v", coverage.calls, err)
	}
	source.now = func() time.Time { return until }
	if err := source.validate(t.Context(), scope, proof); err == nil {
		t.Fatal("expired previous input replayed")
	}
}
