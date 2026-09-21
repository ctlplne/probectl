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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/config"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const testPolicyYAML = `name: pci-segmentation
zones:
  - name: cde
    cidrs: ["10.10.0.0/16"]
  - name: corp
    cidrs: ["10.20.0.0/16"]
rules:
  - id: corp-to-cde
    from: corp
    to: cde
    bidirectional: true
    frameworks:
      pci-dss: "Req 1.3 — network segmentation of the CDE"
`

func complianceTestEngine(t *testing.T) *compliance.Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pci.yaml"), []byte(testPolicyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, on, err := BuildCompliance(&config.Config{ComplianceEnabled: true, CompliancePolicyDir: dir}, intelTestLog())
	if err != nil || !on {
		t.Fatalf("BuildCompliance: on=%v err=%v", on, err)
	}
	return eng
}

func TestBuildComplianceDisabledAndFailClosed(t *testing.T) {
	if _, on, err := BuildCompliance(&config.Config{ComplianceEnabled: false}, intelTestLog()); on || err != nil {
		t.Fatalf("disabled: on=%v err=%v", on, err)
	}
	if _, _, err := BuildCompliance(&config.Config{ComplianceEnabled: true, CompliancePolicyDir: "/does/not/exist"}, intelTestLog()); err == nil {
		t.Fatal("missing policy dir must fail startup")
	}
}

// Flow batch with a forbidden conversation → violation verdict + a correlated
// incident (the S46 'Done when', end to end at the consumer).
func TestComplianceConsumerFlagsViolation(t *testing.T) {
	eng := complianceTestEngine(t)
	correlator := incident.NewCorrelator(incident.NewMemoryStore(), time.Hour, intelTestLog())
	cc := NewComplianceConsumer(nil, eng, correlator, intelTestLog())

	batch := &flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{{
		TenantId:           "t1",
		SourceAddress:      "10.20.1.5", // corp
		DestinationAddress: "10.10.2.9", // cde — forbidden
		DestinationPort:    443,
		Bytes:              4096,
		EndUnixNano:        time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC).UnixNano(),
	}, {
		// Unscoped record: dropped (guardrail 1).
		SourceAddress: "10.20.1.5", DestinationAddress: "10.10.2.9",
	}}}
	raw, err := proto.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	if err := cc.handleFlow(context.Background(), bus.Message{Value: raw}); err != nil {
		t.Fatal(err)
	}

	results := eng.Results("t1")
	if len(results) != 1 || results[0].Verdict != compliance.VerdictViolation || results[0].Violations != 1 {
		t.Fatalf("results = %+v", results)
	}
	if results[0].Samples[0].Src != "10.20.1.5" || results[0].Samples[0].Source != "flow" {
		t.Fatalf("evidence sample = %+v", results[0].Samples)
	}
}

func TestComplianceEndpointsAndIsolation(t *testing.T) {
	eng := complianceTestEngine(t)
	tid := tenancy.DefaultTenantID.String()
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	// A violation for the default tenant; another tenant stays clean.
	eng.Observe(tid, compliance.FlowObs{Src: "10.20.1.5", Dst: "10.10.2.9", DstPort: 443, Source: "flow", At: at})
	eng.Observe("other-tenant", compliance.FlowObs{Src: "10.20.9.9", Dst: "10.10.9.9", DstPort: 443, Source: "flow", At: at})

	srv := testServer(fakePinger{}).WithCompliance(eng)
	rec := do(srv, http.MethodGet, "/v1/compliance")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Running  bool                    `json:"compliance_running"`
		Items    []compliance.RuleResult `json:"items"`
		Coverage compliance.Coverage     `json:"coverage"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Running || len(resp.Items) != 1 || resp.Items[0].Verdict != compliance.VerdictViolation {
		t.Fatalf("resp = %+v", resp)
	}
	// TENANT ISOLATION: only the caller's violations/coverage appear.
	if resp.Coverage.Observations != 1 {
		t.Fatalf("cross-tenant observations leaked: %+v", resp.Coverage)
	}
	// Coverage honesty rides the response.
	if !strings.Contains(strings.Join(resp.Coverage.Notes, " "), "not proof") {
		t.Fatalf("coverage notes = %v", resp.Coverage.Notes)
	}

	// Evidence export verifies and carries the framework mapping.
	rec = do(srv, http.MethodGet, "/v1/compliance/evidence")
	if rec.Code != http.StatusOK {
		t.Fatalf("evidence status = %d", rec.Code)
	}
	var ev compliance.Evidence
	if err := json.Unmarshal(rec.Body.Bytes(), &ev); err != nil {
		t.Fatal(err)
	}
	if err := compliance.VerifyEvidence(ev); err != nil {
		t.Fatalf("exported evidence failed verification: %v", err)
	}
	if !strings.Contains(rec.Body.String(), "Req 1.3") {
		t.Fatal("PCI mapping missing from evidence")
	}
}

func TestComplianceHonestyWhenUnwired(t *testing.T) {
	srv := testServer(fakePinger{})
	rec := do(srv, http.MethodGet, "/v1/compliance")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"compliance_running":false`) {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestComplianceEnabledWithoutPoliciesReturnsArray(t *testing.T) {
	srv := testServer(fakePinger{}).WithCompliance(compliance.NewEngine(nil))
	rec := do(srv, http.MethodGet, "/v1/compliance")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"compliance_running":true`) ||
		!strings.Contains(rec.Body.String(), `"items":[]`) {
		t.Fatalf("enabled empty response must preserve the array contract: %s", rec.Body.String())
	}
}

type fakeComplianceGate struct {
	claims []string
	won    bool
	err    error
}

func (g *fakeComplianceGate) Claim(_ context.Context, tenant, policy, rule string, _ time.Time) (bool, error) {
	g.claims = append(g.claims, tenant+"|"+policy+"|"+rule)
	return g.won, g.err
}

func complianceViolationBatch(t *testing.T) bus.Message {
	t.Helper()
	raw, err := proto.Marshal(&flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{{
		TenantId: "t1", SourceAddress: "10.20.1.5", DestinationAddress: "10.10.2.9", DestinationPort: 443, Bytes: 4096,
		EndUnixNano: time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC).UnixNano(),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return bus.Message{Value: raw}
}

// DPR-073: every replica evaluates the same traffic (view groups), so the
// side effects of a violation go through a cluster-wide once-only gate — the
// replica that wins the claim files the incident, the others (and a replay
// after a rollout) keep the verdict but stay quiet; a gate outage fails open.
func TestComplianceExportIsGatedOnceAcrossReplicas(t *testing.T) {
	incidentsFor := func(gate *fakeComplianceGate) (int, []string) {
		store := incident.NewMemoryStore()
		correlator := incident.NewCorrelator(store, time.Hour, intelTestLog())
		cc := NewComplianceConsumer(nil, complianceTestEngine(t), correlator, intelTestLog()).WithAlertGate(gate)
		if err := cc.handleFlow(context.Background(), complianceViolationBatch(t)); err != nil {
			t.Fatal(err)
		}
		list, err := store.OpenIncidents(context.Background(), "t1")
		if err != nil {
			t.Fatal(err)
		}
		return len(list), gate.claims
	}
	if n, claims := incidentsFor(&fakeComplianceGate{won: true}); n != 1 || len(claims) != 1 || claims[0] != "t1|pci-segmentation|corp-to-cde" {
		t.Fatalf("winning replica: incidents=%d claims=%v", n, claims)
	}
	if n, claims := incidentsFor(&fakeComplianceGate{won: false}); n != 0 || len(claims) != 1 {
		t.Fatalf("losing replica must keep quiet: incidents=%d claims=%v", n, claims)
	}
	if n, _ := incidentsFor(&fakeComplianceGate{err: errors.New("db down")}); n != 1 {
		t.Fatalf("a gate outage must fail open (export locally): incidents=%d", n)
	}
	// The verdict itself is never gated: the losing replica still serves it.
	eng := complianceTestEngine(t)
	cc := NewComplianceConsumer(nil, eng, nil, intelTestLog()).WithAlertGate(&fakeComplianceGate{won: false})
	if err := cc.handleFlow(context.Background(), complianceViolationBatch(t)); err != nil {
		t.Fatal(err)
	}
	if res := eng.Results("t1"); len(res) != 1 || res[0].Verdict != compliance.VerdictViolation {
		t.Fatalf("losing replica lost the verdict: %+v", res)
	}
}

type groupRecordingBus struct {
	mu     sync.Mutex
	groups []string
}

func (b *groupRecordingBus) Publish(context.Context, string, []byte, []byte) error { return nil }
func (b *groupRecordingBus) Subscribe(ctx context.Context, _, group string, _ bus.Handler) error {
	b.mu.Lock()
	b.groups = append(b.groups, group)
	b.mu.Unlock()
	<-ctx.Done()
	return nil
}
func (b *groupRecordingBus) Close() error { return nil }

// DPR-073: the compliance lanes are per-replica view groups (like the topology
// and TLS-posture views), so every replica holds the full verdict state
// instead of one partition owner.
func TestComplianceLanesArePerReplicaViewGroups(t *testing.T) {
	prev := instanceGroupSuffix
	SetInstanceGroupSuffix("control-0")
	t.Cleanup(func() { SetInstanceGroupSuffix(prev) })
	fb := &groupRecordingBus{}
	cc := NewComplianceConsumer(fb, complianceTestEngine(t), nil, intelTestLog()).
		WithNamespaceTenants(map[string]string{"t-acme": "t1"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- cc.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		fb.mu.Lock()
		n := len(fb.groups)
		fb.mu.Unlock()
		if n >= 4 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"compliance-flow-control-0": true, "compliance-flow-control-0-t-acme": true,
		"compliance-ebpf-control-0": true, "compliance-ebpf-control-0-t-acme": true,
	}
	for _, g := range fb.groups {
		delete(want, g)
	}
	if len(want) != 0 {
		t.Fatalf("missing per-replica groups %v (got %v)", want, fb.groups)
	}
}

// TestTheComplianceGateReArmsWhenTheWindowRollsOver (DPR-110): keyed by the
// (policy, rule) pair alone, a segmentation violation could raise its incident
// and SIEM event exactly once for the life of the deployment — remediate, watch
// the same traffic come back, hear nothing. The claim is keyed by period, so
// replicas and replays inside the window still collapse to one export and the
// next window re-arms the pair.
func TestTheComplianceGateReArmsWhenTheWindowRollsOver(t *testing.T) {
	at := time.Date(2026, 9, 17, 13, 40, 0, 0, time.UTC)
	day := compliancePeriod(at, 24*time.Hour)
	if same := compliancePeriod(at.Add(9*time.Hour), 24*time.Hour); same != day {
		t.Errorf("two observations on the same UTC day must share a claim period: %q vs %q", day, same)
	}
	if next := compliancePeriod(at.Add(24*time.Hour), 24*time.Hour); next == day {
		t.Error("the next window must re-arm the pair")
	}
	// A shorter window re-arms sooner; the bucket is UTC so replicas in
	// different zones race for the same claim.
	if a, b := compliancePeriod(at, time.Hour), compliancePeriod(at.Add(70*time.Minute), time.Hour); a == b {
		t.Error("a one-hour window must re-arm within the same day")
	}
	if compliancePeriod(at, 0) != compliancePeriod(at, DefaultComplianceRealert) {
		t.Error("a zero window must mean the default, never a claim per nanosecond")
	}
	local := at.In(time.FixedZone("UTC+9", 9*3600))
	if compliancePeriod(local, 24*time.Hour) != day {
		t.Error("the period must be computed in UTC so every replica agrees")
	}
}
