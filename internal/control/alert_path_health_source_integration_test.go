// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Real application-role Postgres/RLS and original-receipt validation. Counter
// rows and issued sender identities are modeled; no physical sender is claimed.
func TestPathHealthAlertSourceUsesCurrentOriginalsAndWithholdsLateGrantWithdrawal(t *testing.T) {
	proof := newPathHealthAPIFixture(t)
	f := proof.fixture
	history := &capacityCounterHistoryProbe{Memory: flowstore.NewMemory()}
	f.server.WithFlowStore(history)
	rules := map[string]*alert.Rule{}
	for lane, tenant := range f.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		reader := store.NewDeviceCounterCaptures(f.pool)
		start := time.Now().UTC().Add(-100 * time.Millisecond)
		// Both lanes wrap the 32-bit word. Only the first has a climb.
		words := []uint64{4294967288, 4294967289, 4294967290, 4294967291, 15}
		if lane == 1 {
			words = []uint64{4294967292, 4294967293, 4294967294, 4294967295, 0}
		}
		for poll, value := range words {
			at := start.Add(time.Duration(poll) * 20 * time.Millisecond)
			input := entity.CounterCaptureInput{ConfiguredTarget: "192.0.2.1", PollStartedAt: at, PollCompletedAt: at, PointCount: uint32(len(pathHealthMetricNames))}
			digest := [32]byte{150, byte(lane + 1), byte(poll + 1)}
			capture, err := reader.CaptureAuthenticated(ctx, "role-snmp", f.serials[tenant+"role-snmp"], digest, input, 128<<20)
			if err != nil {
				t.Fatal(err)
			}
			witness, err := reader.LookupWitness(ctx, "role-snmp", digest, input)
			if err != nil {
				t.Fatal(err)
			}
			var rows []flowstore.CounterRow
			for metric, name := range pathHealthMetricNames {
				word, width := uint64(100+poll), uint32(32)
				if metric < 2 {
					word, width = 1<<53+1+uint64(poll)*1000, 64
				}
				if name == "probectl.device.if.in.fcs.errors" {
					word = value
				}
				rows = append(rows, flowstore.CounterRow{TenantID: tenant,
					CounterSource: flowstore.CounterSource{ContextID: f.contextID, DeviceID: f.routerID, AgentID: "role-snmp", SourceRef: input.ConfiguredTarget, SourceAssignedAt: witness.SourceAssignedAt, AgentAssignedAt: witness.AgentAssignedAt},
					SenderSerial:  witness.SenderSerial, CaptureKey: capture.Key, RawDigest: digest, CapturedAt: capture.CapturedAt, PollStartedAt: at, PollCompletedAt: at, Population: input.PointCount,
					IfIndex: 7, Name: name, Value: word, Width: width, UptimeKnown: true, UptimeTicks: 10000 + uint32(poll)*2, DiscontinuityKnown: true})
			}
			if err := history.InsertCounterPoll(ctx, rows, flowstore.CounterBudget{MemoryBytes: 128 << 20, WorkUnits: 128 << 20, Timeout: time.Minute}); err != nil {
				t.Fatal(err)
			}
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			input, err := alert.NormalizePathHealthSource(alert.PathHealthSourceInput{TestID: proof.tests[tenant], InterfaceID: f.interfaceID, Metric: "probectl.device.if.in.fcs.errors"})
			if err != nil {
				return err
			}
			source := alert.PathHealthSource{PathHealthSourceInput: input, Version: 1, OwnerUserID: f.users[tenant], ReadGrants: []alert.QueryReadGrant{
				{Permission: "test.read", ScopeType: auth.ScopeTenant}, {Permission: "entities.read", ScopeType: auth.ScopeTenant}, {Permission: "metrics.read", ScopeType: auth.ScopeTenant}}}
			rule, err := (store.AlertRules{}).Create(ctx, sc, alert.Rule{Name: "Current owned FCS climb", Enabled: true, Metric: alert.PathHealthMetric, Type: alert.Threshold, Comparison: alert.GTE, Threshold: 1, ForN: 1, Severity: alert.SeverityWarning})
			if err != nil {
				return err
			}
			rules[tenant], err = (store.AlertRules{}).SetPathHealthSource(ctx, sc, rule.ID, rule.UpdatedAt, &source, 64<<20, func(ctx context.Context, _ tenancy.Scope) error { return ctx.Err() })
			return err
		})
	}
	writer, err := tsdb.New("memory", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	var delivered []alert.Alert
	build := func(tenant string) *alert.Evaluator {
		t.Helper()
		evaluator, ok := BuildAlertEvaluator(f.pool, writer, alert.ChannelDeps{}, time.Second, tenancy.ID(tenant),
			func(_ context.Context, event alert.Alert) { delivered = append(delivered, event) },
			f.server.log, AlertTagDependencies{Gate: f.server.fairnessGate, FlowStore: f.server.flowStore, Queries: f.server})
		if !ok {
			t.Fatal("shipped path-health evaluator is unavailable")
		}
		return evaluator
	}
	groups := map[string]bool{}
	for lane, tenant := range f.tenants {
		want := 1 - lane
		read, err := f.server.readAlertPathHealthRule(t.Context(), tenant, *rules[tenant])
		if err != nil || len(read.Samples) != 1 || read.Samples[0].Value != float64(want) || read.QuerySelection == nil || !read.QuerySelection.Complete {
			t.Fatal("wrapped original words did not produce the expected owned decision", err, read)
		}
		group := read.Samples[0].Labels["path_health_group"]
		if groups[group] {
			t.Fatal("paired tenant decisions shared an episode identity")
		}
		groups[group] = true
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		before := len(delivered)
		evaluator := build(tenant)
		acted, err := evaluator.Engine().Evaluate(ctx, *rules[tenant])
		if err != nil || len(acted) != want || len(delivered)-before != want {
			t.Fatalf("wrapped counter decision delivered %d events, want %d: %v", len(delivered)-before, want, err)
		}
		if want == 1 && (delivered[before].TenantID != tenant || delivered[before].RuleID != rules[tenant].ID ||
			delivered[before].State != alert.StateFiring || delivered[before].Labels["path_health_group"] != group) {
			t.Fatal("wrapped climb was not delivered under the owned episode identity")
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			stored, err := (store.AlertNotifications{}).List(ctx, sc)
			if err == nil && (len(stored) != want || want == 1 && stored[0].LastNotified.IsZero()) {
				t.Fatal("tenant did not retain its expected notification state")
			}
			return err
		})
		// A new evaluator restores notification state from this tenant's
		// PostgreSQL scope. The retained climb must not fire a second time.
		if acted, err := build(tenant).Engine().Evaluate(ctx, *rules[tenant]); err != nil || len(acted) != 0 || len(delivered)-before != want {
			t.Fatal("evaluator replacement repeated a held notification", err)
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	if read, err := f.server.readAlertPathHealthRule(tenancy.WithTenant(t.Context(), tenancy.ID(b)), a, *rules[a]); err == nil || len(read.Samples) != 0 {
		t.Fatal("foreign tenant context reached the stored alert source", err)
	}
	before := history.calls
	foreignActor := auth.WithPrincipal(t.Context(), &auth.Principal{TenantID: a, UserID: f.users[b]})
	if read, err := f.server.readAlertPathHealthRule(foreignActor, a, *rules[a]); err == nil || len(read.Samples) != 0 || history.calls != before {
		t.Fatal("different user context adopted the stored owner's source authority", err)
	}
	history.after = func() {
		history.after = nil
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, "DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='metrics.read'", a, f.roles[a])
			return err
		})
	}
	if read, err := f.server.readAlertPathHealthRule(t.Context(), a, *rules[a]); err == nil || len(read.Samples) != 0 || read.QuerySelection != nil {
		t.Fatal("late source-grant withdrawal published a firing or healthy prefix", err)
	}
	if read, err := f.server.readAlertPathHealthRule(t.Context(), b, *rules[b]); err != nil || len(read.Samples) != 1 || read.Samples[0].Value != 0 {
		t.Fatal("one tenant withdrawal changed its sibling source", err)
	}
}
