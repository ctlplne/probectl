// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type pathAlertRuleSourceForTest struct{ read alert.RuleMetricRead }

func (*pathAlertRuleSourceForTest) Current(context.Context, string, map[string]string) ([]alert.Sample, error) {
	return nil, errors.New("owned path condition must not fall back to a TSDB alias")
}

func (s *pathAlertRuleSourceForTest) CurrentRule(context.Context, alert.Rule) (alert.RuleMetricRead, error) {
	return s.read, nil
}

// Simulation: original wrapped words pass through the actual rate/model
// projection and existing notification engine; source authority is separate.
func TestOwnedPathWrappedErrorClimbFiresOnceAndHoldsResetUntilProvenRecovery(t *testing.T) {
	const testID = "41111111-1111-4111-8111-111111111111"
	const interfaceID = "42111111-1111-4111-8111-111111111111"
	const userID = "43111111-1111-4111-8111-111111111111"
	const ruleID = "44111111-1111-4111-8111-111111111111"
	groups := map[string]bool{}
	for _, tenant := range []string{"51111111-1111-4111-8111-111111111111", "61111111-1111-4111-8111-111111111111"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		base := pathHealthProjectionRows()[0]
		var rows []flowstore.CounterRow
		for i, value := range []uint64{4294967288, 4294967289, 4294967290, 4294967291, 15} {
			point := base
			point.TenantID, point.Name, point.Value, point.Width = tenant, "probectl.device.if.in.fcs.errors", value, 32
			point.PollStartedAt = base.PollStartedAt.Add(time.Duration(i) * time.Second)
			point.PollCompletedAt = point.PollStartedAt.Add(time.Millisecond)
			point.UptimeTicks += uint32(i) * 100
			point.CaptureKey[0], point.RawDigest[0] = byte(i+1), byte(i+10)
			rows = append(rows, point)
		}
		input, err := alert.NormalizePathHealthSource(alert.PathHealthSourceInput{TestID: testID, InterfaceID: interfaceID, Metric: rows[0].Name, PollGapSeconds: 60})
		if err != nil {
			t.Fatal(err)
		}
		configuration := alert.PathHealthSource{PathHealthSourceInput: input, Version: 1, OwnerUserID: userID,
			ReadGrants: []alert.QueryReadGrant{{Permission: "metrics.read", ScopeType: auth.ScopeTenant}}}
		rule := alert.Rule{ID: ruleID, TenantID: tenant, Name: "Owned FCS climb", Enabled: true, Metric: alert.PathHealthMetric, Type: alert.Threshold, Comparison: alert.GTE, Threshold: 1, ForN: 1, Severity: alert.SeverityWarning}
		query := &pathHealthOperation{op: capacityForecastOperation{actor: &auth.Principal{TenantID: tenant, UserID: userID}},
			checks: []pathHealthCheck{{target: store.DeviceCounterInterface{InterfaceID: interfaceID, IfIndex: 7, Source: base.CounterSource}}}}
		snapshot := pathHealthSnapshot{result: pathHealthResult{TestID: testID, Status: "current", Items: []pathEntityHop{{Health: &pathInterfaceHealth{InterfaceID: interfaceID}}}}}
		read := func() alert.RuleMetricRead {
			t.Helper()
			query.options.to = rows[len(rows)-1].PollCompletedAt
			trends, err := projectPathHealthErrorTrends(ctx, rows, query.options.to, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			snapshot.result.Items[0].Health.ErrorTrends = trends
			result, err := pathHealthAlertSelection(query, snapshot, rule, configuration)
			if err != nil {
				t.Fatal(err)
			}
			return result
		}
		source := &pathAlertRuleSourceForTest{read: read()}
		if len(source.read.Samples) != 1 || source.read.Samples[0].Value != 1 {
			t.Fatal("planted wrapped climb did not reach the condition source")
		}
		group := source.read.Samples[0].Labels["path_health_group"]
		if groups[group] {
			t.Fatal("paired tenants shared an episode identity")
		}
		groups[group] = true
		engine := alert.NewEngine(source, nil, nil)
		for i := range 2 {
			acted, err := engine.Evaluate(ctx, rule)
			want := 1
			if i == 1 {
				want = 0
			}
			if err != nil || len(acted) != want || len(acted) == 1 && acted[0].State != alert.StateFiring {
				t.Fatal("one wrapped climb emitted duplicate firing", acted, err)
			}
		}
		rows[4].DiscontinuityTicks++
		source.read = read()
		if !source.read.Skip {
			t.Fatal("reset observations became a healthy or firing condition")
		}
		if acted, err := engine.Evaluate(ctx, rule); err != nil || len(acted) != 0 {
			t.Fatal("unproven reset advanced an episode", acted, err)
		}
		rows[4].DiscontinuityTicks--
		recovery := rows[4]
		recovery.Value, recovery.UptimeTicks = 16, recovery.UptimeTicks+100
		recovery.PollStartedAt = recovery.PollStartedAt.Add(time.Second)
		recovery.PollCompletedAt = recovery.PollStartedAt.Add(time.Millisecond)
		recovery.CaptureKey[0], recovery.RawDigest[0] = 6, 15
		rows = append(rows, recovery)
		source.read = read()
		if len(source.read.Samples) != 1 || source.read.Samples[0].Value != 0 || source.read.Samples[0].Labels["path_health_group"] != group {
			t.Fatal("proven recovery changed the stable source episode or stayed unavailable")
		}
		if acted, err := engine.Evaluate(ctx, rule); err != nil || len(acted) != 1 || acted[0].State != alert.StateResolved {
			t.Fatal("proven current recovery did not resolve once", acted, err)
		}
		query.op.actor.TenantID = "foreign"
		if _, err := pathHealthAlertSelection(query, snapshot, rule, configuration); err == nil {
			t.Fatal("foreign source actor minted a path episode")
		}
	}
}
