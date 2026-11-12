// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type dependencyEngineFixture struct {
	tenant      string
	now         time.Time
	down        bool
	independent bool
	source      *fakeSource
	mail        *fakeMail
	rule        Rule
	persisted   map[string]NotifyState
	writes      int
	visible     map[string]Alert
	ordinary    []Alert
	mutate      func([]DependencyOutcome) ([]DependencyOutcome, error)
}

func newDependencyEngineFixture(tenant string) *dependencyEngineFixture {
	return &dependencyEngineFixture{tenant: tenant, now: time.Now().UTC(), down: true,
		source: &fakeSource{samples: []Sample{sample(0, map[string]string{"tenant_id": tenant, "test_id": dependencyTarget})}},
		mail:   &fakeMail{}, persisted: map[string]NotifyState{}, visible: map[string]Alert{},
		rule: Rule{ID: dependencyRoom, TenantID: tenant, Name: "Reachability", Enabled: true, Metric: "probectl_probe_success",
			HasDependencyPolicy: true, Type: Threshold, Comparison: EQ, Threshold: 0, ForN: 1,
			Channels: []ChannelSpec{{Type: "email", Recipients: []string{"operator@example.test"}}}},
	}
}

func (f *dependencyEngineFixture) graph() dependencySnapshot {
	graph := dependencyFixture(f.tenant)
	graph.At = f.now
	for i := range graph.Vertices {
		graph.Vertices[i].FreshUntil = f.now.Add(time.Minute)
	}
	for i := range graph.Causes {
		graph.Causes[i].ObservedAt = f.now.Add(-time.Second)
		graph.Causes[i].FreshUntil = f.now.Add(time.Minute)
	}
	if !f.down {
		graph.Causes = nil
	}
	return graph
}

func (f *dependencyEngineFixture) leader(t *testing.T) *Engine {
	t.Helper()
	router := func(ctx context.Context, rule Rule, attempts []DependencyAttempt) ([]DependencyOutcome, error) {
		if rule.TenantID != f.tenant {
			t.Fatal("router received another tenant's rule")
		}
		out := make([]DependencyOutcome, len(attempts))
		for i, attempt := range attempts {
			decision, err := decideDependencyNotification(ctx, attempt, f.graph(), dependencyTarget, !f.independent, 1<<20, 1<<20)
			if err != nil {
				return nil, err
			}
			published := decision.Held() || attempt.PreviouslyHeld
			if published {
				a := attempt.Alert
				a.Dependency = &decision
				f.visible[stateKey(a.RuleID, a.Labels)] = a
			}
			out[i] = DependencyOutcome{Decision: decision, IncidentPublished: published, NotificationStatePublished: decision.Held()}
		}
		if f.mutate != nil {
			return f.mutate(out)
		}
		return out, nil
	}
	en := NewEngine(f.source, NewNotifier(ChannelDeps{Mail: f.mail}, discard()), discard(), withDependencyRouter(router), WithAlertSink(func(_ context.Context, a Alert) {
		if a.TenantID != f.tenant {
			t.Fatal("ordinary incident sink crossed its tenant")
		}
		f.ordinary = append(f.ordinary, a)
	}))
	en.clock = func() time.Time { return f.now }
	en.SetNotifyHook(func(key string, state NotifyState) {
		f.persisted[key] = state
		f.writes++
	})
	return en
}

func (f *dependencyEngineFixture) evaluate(t *testing.T, en *Engine) []Alert {
	t.Helper()
	acted, err := en.Evaluate(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenant)), f.rule)
	if err != nil {
		t.Fatal(err)
	}
	return acted
}

func TestTopologyDependencyEngineKeepsDetectionVisibleAndReleasesPersistentEpisodes(t *testing.T) {
	for _, tenant := range []string{dependencyTenantA, dependencyTenantB} {
		f := newDependencyEngineFixture(tenant)
		en := f.leader(t)
		first := f.evaluate(t, en)
		key := stateKey(f.rule.ID, f.source.samples[0].Labels)
		if len(first) != 1 || first[0].Dependency == nil || !first[0].Dependency.Held() || f.mail.sent != 0 || len(en.Active()) != 1 || len(f.visible) != 1 || len(f.ordinary) != 0 || !f.persisted[key].LastNotified.IsZero() || !f.persisted[key].FiringSince.Equal(f.now) {
			t.Fatal("held firing was delivered, hidden or recorded as externally notified", first, en.Active(), f.mail.sent, f.persisted)
		}
		f.now = f.now.Add(10 * time.Second)
		if repeated := f.evaluate(t, en); len(repeated) != 0 || f.mail.sent != 0 || f.writes != 1 || len(f.visible) != 1 {
			t.Fatal("steady held episode duplicated notification state or lost visible identity", repeated, f.mail.sent, f.writes)
		}
		f.down = false
		f.now = f.now.Add(time.Second)
		f.evaluate(t, en)
		if f.mail.sent != 1 || !f.persisted[key].LastNotified.Equal(f.now) || len(en.Active()) != 1 {
			t.Fatal("persistent downstream firing did not release exactly once", f.mail.sent, f.persisted, en.Active())
		}
		f.now = f.now.Add(time.Second)
		f.evaluate(t, en)
		if f.mail.sent != 1 {
			t.Fatal("released notify-once episode was sent again")
		}
		f.source.samples[0].Value = 1
		f.evaluate(t, en)
		if f.mail.sent != 2 || len(en.Active()) != 0 || len(f.ordinary) != 1 || f.ordinary[0].State != StateResolved {
			t.Fatal("delivered episode lost its ordinary resolution", f.mail.sent, en.Active(), f.ordinary)
		}
	}
}

func TestTopologyDependencyEngineRestoresHeldClockWithoutFalseResolution(t *testing.T) {
	for _, tenant := range []string{dependencyTenantA, dependencyTenantB} {
		f := newDependencyEngineFixture(tenant)
		f.evaluate(t, f.leader(t))
		since := f.now
		f.now = f.now.Add(time.Minute)
		restarted := f.leader(t)
		restarted.RestoreNotifications(f.persisted)
		f.evaluate(t, restarted)
		active := restarted.Active()
		if f.mail.sent != 0 || len(active) != 1 || !active[0].Since.Equal(since) {
			t.Fatal("restart re-notified or restarted a held firing episode", f.mail.sent, active)
		}
		// A fresh leader first sees recovery, rather than another failing
		// sample. It closes the visible episode without inventing a prior
		// external firing notification.
		f.source.samples[0].Value = 1
		f.now = f.now.Add(time.Second)
		recovered := f.leader(t)
		recovered.RestoreNotifications(f.persisted)
		acted := f.evaluate(t, recovered)
		if len(acted) != 1 || acted[0].State != StateResolved || len(recovered.Active()) != 0 || f.mail.sent != 0 {
			t.Fatal("held recovery after restart emitted a false resolution or stayed firing", acted, recovered.Active(), f.mail.sent)
		}
	}
}

func TestTopologyDependencyEngineKeepsIndependentAndUnverifiedDeliveryOrdinary(t *testing.T) {
	mutations := map[string]func([]DependencyOutcome) ([]DependencyOutcome, error){
		"unpersisted": func(out []DependencyOutcome) ([]DependencyOutcome, error) {
			out[0].NotificationStatePublished = false
			return out, nil
		},
		"unpublished": func(out []DependencyOutcome) ([]DependencyOutcome, error) {
			out[0].IncidentPublished = false
			return out, nil
		},
		"prefix": func(out []DependencyOutcome) ([]DependencyOutcome, error) { return out[:1], nil },
		"moved": func(out []DependencyOutcome) ([]DependencyOutcome, error) {
			out[0], out[1] = out[1], out[0]
			return out, nil
		},
		"foreign": func(out []DependencyOutcome) ([]DependencyOutcome, error) {
			out[0].Decision.tenant = dependencyContext
			return out, nil
		},
		"revision": func(out []DependencyOutcome) ([]DependencyOutcome, error) {
			out[0].Decision.ruleUpdatedAt = time.Unix(1, 0)
			return out, nil
		},
		"expired": func(out []DependencyOutcome) ([]DependencyOutcome, error) {
			out[0].Decision.validUntil = out[0].Decision.selection.At
			return out, nil
		},
		"unavailable": func([]DependencyOutcome) ([]DependencyOutcome, error) {
			return nil, errors.New("owned evidence unavailable")
		},
	}
	for _, tenant := range []string{dependencyTenantA, dependencyTenantB} {
		for name, mutate := range mutations {
			t.Run(tenant+"/"+name, func(t *testing.T) {
				f := newDependencyEngineFixture(tenant)
				f.source.samples = append(f.source.samples, sample(0, map[string]string{"tenant_id": tenant, "test_id": dependencyBackup}))
				f.mutate = mutate
				en := f.leader(t)
				acted := f.evaluate(t, en)
				if f.mail.sent != 2 || len(f.ordinary) != 2 || len(en.Active()) != 2 || len(acted) != 2 || acted[0].Dependency != nil || acted[1].Dependency != nil {
					t.Fatal("invalid or partial routing hid a series or exposed a moved reference", f.mail.sent, f.ordinary, en.Active(), acted)
				}
			})
		}
		f := newDependencyEngineFixture(tenant)
		f.independent = true
		en := f.leader(t)
		f.evaluate(t, en)
		if f.mail.sent != 1 || len(f.ordinary) != 1 || len(f.visible) != 0 {
			t.Fatal("an independent failure was suppressed by physical adjacency", f.mail.sent, f.ordinary, f.visible)
		}
	}
}

func TestTopologyDependencyDecisionBindsExactLabelsBeyondTheLegacyStateKey(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(dependencyTenantA))
	graph := dependencyFixture(dependencyTenantA)
	a := Alert{TenantID: dependencyTenantA, RuleID: dependencyRoom, State: StateFiring, Labels: map[string]string{"a": "b;c=d"}}
	b := a
	b.Labels = map[string]string{"a": "b", "c": "d"}
	if stateKey(a.RuleID, a.Labels) != stateKey(b.RuleID, b.Labels) {
		t.Fatal("fixture no longer exercises the legacy state-key ambiguity")
	}
	decision, err := decideDependencyNotification(ctx, DependencyAttempt{Alert: a}, graph, dependencyTarget, true, 1<<20, 1<<20)
	if err != nil || !decision.matches(a, graph.At) || decision.matches(b, graph.At) {
		t.Fatal("dependency authority moved between distinct label populations", err)
	}
}

func TestTopologyDependencyDecisionAdmitsCompleteLabelBytesBeforeCopying(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(dependencyTenantA))
	graph := dependencyFixture(dependencyTenantA)
	a := Alert{TenantID: dependencyTenantA, RuleID: dependencyRoom, State: StateFiring, Labels: map[string]string{"complete_value": strings.Repeat("x", 1<<20)}}
	attempt := DependencyAttempt{Alert: a}
	if _, err := decideDependencyNotification(ctx, attempt, graph, dependencyTarget, true, 64<<10, 64<<10); !errors.Is(err, ErrDependencyEvidence) {
		t.Fatal("complete label bytes bypassed operation admission", err)
	}
	decision, err := decideDependencyNotification(ctx, attempt, graph, dependencyTarget, true, 16<<20, 16<<20)
	if err != nil || !decision.Held() || !decision.matches(a, graph.At) {
		t.Fatal("raising operator admission did not retain the complete original value", err)
	}
}

func TestTopologyDependencyEnginePreservesSilenceAndExistingRenotifyCadence(t *testing.T) {
	f := newDependencyEngineFixture(dependencyTenantA)
	f.down = false
	f.rule.RenotifySeconds = 60
	en := f.leader(t)
	f.evaluate(t, en)
	key := stateKey(f.rule.ID, f.source.samples[0].Labels)
	original := f.persisted[key].LastNotified
	f.down = true
	f.now = f.now.Add(10 * time.Second)
	f.evaluate(t, en)
	f.now = f.now.Add(time.Minute)
	f.evaluate(t, en)
	if f.mail.sent != 1 || !f.persisted[key].LastNotified.Equal(original) || len(f.visible) != 1 {
		t.Fatal("holding an existing firing advanced its delivery clock or hid it", f.mail.sent, f.persisted, f.visible)
	}
	if _, err := en.Silence(key, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	f.down = false
	f.now = f.now.Add(time.Second)
	f.evaluate(t, en)
	if f.mail.sent != 1 {
		t.Fatal("dependency recovery bypassed an operator silence")
	}
	f.now = f.now.Add(40 * time.Second)
	f.evaluate(t, en)
	if f.mail.sent != 2 || !f.persisted[key].LastNotified.Equal(f.now) {
		t.Fatal("the owed renotification did not resume once after the silence", f.mail.sent, f.persisted)
	}
}

func TestTopologyDependencyExpiredTrapWithoutPriorDeliveryOnlyClosesTheIncident(t *testing.T) {
	for _, tenant := range []string{dependencyTenantA, dependencyTenantB} {
		rule := trapRule()
		rule.ID, rule.TenantID = dependencyRoom, tenant
		rule.Channels = []ChannelSpec{{Type: "email", Recipients: []string{"operator@example.test"}}}
		mail := &fakeMail{}
		var visible []Alert
		en := NewEngine(nil, NewNotifier(ChannelDeps{Mail: mail}, discard()), discard(), WithTrapSource(&fakeTrapSource{}), WithAlertSink(func(_ context.Context, a Alert) { visible = append(visible, a) }))
		labels := map[string]string{"device": "192.0.2.1", "trap_oid": rule.Trap.TrapOID}
		en.RestoreNotifications(map[string]NotifyState{stateKey(rule.ID, labels): {FiringSince: time.Now().Add(-time.Hour)}})
		acted, err := en.Evaluate(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), rule)
		if err != nil || len(acted) != 1 || acted[0].State != StateResolved || len(visible) != 1 || visible[0].TenantID != tenant || mail.sent != 0 {
			t.Fatal("expired unnotified trap sent a false resolution or lost its incident closure", acted, visible, mail.sent, err)
		}
	}
}

// The source adapter is not wired yet; keep the test-only engine installer
// private until a shipping caller supplies trusted current dependency evidence.
func withDependencyRouter(router DependencyRouter) EngineOption {
	return func(en *Engine) { en.dependencyRouter = router }
}
