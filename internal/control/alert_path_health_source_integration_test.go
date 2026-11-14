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
		for poll, value := range []uint64{4294967288, 4294967289, 4294967290, 4294967291, 15} {
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
	groups := map[string]bool{}
	for _, tenant := range f.tenants {
		read, err := f.server.readAlertPathHealthRule(t.Context(), tenant, *rules[tenant])
		if err != nil || len(read.Samples) != 1 || read.Samples[0].Value != 1 || read.QuerySelection == nil || !read.QuerySelection.Complete {
			t.Fatal("current original climb did not produce its complete owned decision", err, read)
		}
		group := read.Samples[0].Labels["path_health_group"]
		if groups[group] {
			t.Fatal("paired tenant decisions shared an episode identity")
		}
		groups[group] = true
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
	if read, err := f.server.readAlertPathHealthRule(t.Context(), b, *rules[b]); err != nil || len(read.Samples) != 1 || read.Samples[0].Value != 1 {
		t.Fatal("one tenant withdrawal changed its sibling source", err)
	}
}
