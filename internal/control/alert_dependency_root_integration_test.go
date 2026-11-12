// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestDependencyRouterCreatesCanonicalRootBeforeHoldingChildren(t *testing.T) {
	d := seedDependencyRoutingFixture(t)
	for _, tenant := range d.f.tenants {
		d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM incidents WHERE tenant_id=$1 AND id=$2`, tenant, d.cases[tenant])
			return err
		})
		mail, ordinary := &dependencyRoutingMail{}, 0
		var rows []tsdb.Series
		for i, node := range d.graphs[tenant].Nodes {
			rows = append(rows, tsdb.Series{Metric: d.rules[tenant].Metric, Labels: map[string]string{"tenant_id": tenant, "test_id": node.TestID, "agent_id": node.AgentID, "server_address": fmt.Sprintf("192.0.2.%d", i+1)}, Value: 0})
		}
		leader := func() *alert.Evaluator {
			eval, ok := BuildAlertEvaluator(d.f.pool, fakeQuerier{rows: rows}, alert.ChannelDeps{Mail: mail}, time.Second, tenancy.ID(tenant), func(context.Context, alert.Alert) { ordinary++ }, d.f.server.log,
				AlertTagDependencies{Gate: d.f.server.fairnessGate, FlowStore: d.f.server.flowStore, Queries: d.f.server})
			if !ok {
				t.Fatal("shipping evaluator unavailable")
			}
			return eval
		}
		eval := leader()
		evaluate := func() {
			t.Helper()
			if _, err := eval.Engine().Evaluate(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), *d.rules[tenant]); err != nil {
				t.Fatal(err)
			}
		}
		evaluate()
		if len(mail.subjects) != 1 || ordinary != 0 || len(eval.Engine().Active()) != len(rows) {
			t.Fatal("first source-backed outage lacked one root delivery and visible held child", mail.subjects, ordinary)
		}
		var parent string
		d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var roots, signals, held int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*),COALESCE(min(id::text),'') FROM incidents WHERE tenant_id=$1 AND entity_context_id=$2 AND entity_id=$3 AND identity_lookup_attempted`, tenant, d.f.contextID, d.graphs[tenant].Nodes[0].EntityID).Scan(&roots, &parent); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE attributes->>'dependency.state'='held') FROM incident_signals WHERE tenant_id=$1 AND incident_id=$2`, tenant, parent).Scan(&signals, &held); err != nil {
				return err
			}
			if roots != 1 || signals != 2 || held != 1 || parent == d.cases[tenant] {
				t.Fatal("canonical root and held child were not durably published together", roots, signals, held)
			}
			return nil
		})
		eval = leader()
		evaluate()
		if len(mail.subjects) != 1 || ordinary != 0 {
			t.Fatal("leader reload duplicated the source-backed episode", mail.subjects, ordinary)
		}
		// Recovery attaches to the original canonical case, even when it has
		// been quiet longer than the ordinary cross-plane correlation window.
		d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE incidents SET started_at=now()-interval '1 hour',last_seen_at=now()-interval '1 hour' WHERE tenant_id=$1 AND id=$2`, tenant, parent)
			return err
		})
		d.observe(t, tenant, 0, true)
		rows[0].Value = 1
		evaluate()
		if len(mail.subjects) != 3 || ordinary != 0 {
			t.Fatal("recovery lost the child release or emitted an anonymous duplicate case", mail.subjects, ordinary)
		}
		d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var roots, resolved int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE tenant_id=$1 AND entity_context_id=$2 AND entity_id=$3`, tenant, d.f.contextID, d.graphs[tenant].Nodes[0].EntityID).Scan(&roots); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM incident_signals WHERE tenant_id=$1 AND incident_id=$2 AND kind='alert.resolved' AND entity_id=$3`, tenant, parent, d.graphs[tenant].Nodes[0].EntityID).Scan(&resolved); err != nil {
				return err
			}
			if roots != 1 || resolved != 1 {
				t.Fatal("source-backed recovery opened another root instead of updating its case", roots, resolved)
			}
			return nil
		})
	}
}

func TestDependencyRootObserverRequiresCommitAndCurrentTenant(t *testing.T) {
	d := seedDependencyRoutingFixture(t)
	for _, tenant := range d.f.tenants {
		observed := 0
		observer := func(_ context.Context, inc *incident.Incident, _ bool) {
			if inc.TenantID != tenant || inc.IdentityContextID != d.f.contextID || inc.IdentityEntityID != d.graphs[tenant].Nodes[0].EntityID {
				t.Fatal("observer received foreign or unverified identity")
			}
			d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
				var count int
				if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM incident_signals WHERE tenant_id=$1 AND incident_id=$2 AND kind='alert.firing' AND entity_id=$3`, tenant, inc.ID, inc.IdentityEntityID).Scan(&count); err != nil {
					return err
				}
				if count != 1 {
					t.Fatal("observer ran before the outer tenant transaction committed", count)
				}
				return nil
			})
			observed++
		}
		node := d.graphs[tenant].Nodes[0]
		attempt := alert.DependencyAttempt{Alert: alert.Alert{TenantID: tenant, RuleID: d.rules[tenant].ID, RuleName: d.rules[tenant].Name, Metric: d.rules[tenant].Metric, State: alert.StateFiring, At: time.Now(), Labels: map[string]string{"test_id": node.TestID, "agent_id": node.AgentID}}, NotificationDue: true, FiringSince: time.Now(), RuleUpdatedAt: d.rules[tenant].UpdatedAt}
		router := d.f.server.alertDependencyRouter(tenancy.ID(tenant), dependencyIncidentPublication{observer: observer})
		abort := errors.New("deliberate late publication failure")
		var staged []dependencyIncidentEvent
		staging := &dependencyIncidentPublication{pending: &staged}
		err := tenancy.InTenant(tenancy.WithSiloTableLock(tenancy.WithTenant(t.Context(), tenancy.ID(tenant))), d.f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.AlertRules{}).WithDependencyPublication(ctx, sc, attempt.Alert.RuleID, attempt.RuleUpdatedAt, 8<<20, func(ctx context.Context, sc tenancy.Scope, policy *alert.DependencyPolicy) error {
				if _, err := d.f.server.publishDependencyAttempts(ctx, sc, *d.rules[tenant], policy, []alert.DependencyAttempt{attempt}, 32<<20, staging); err != nil {
					return err
				}
				if len(staged) != 1 || observed != 0 {
					t.Fatal("root observer was not deferred until commit", len(staged), observed)
				}
				return abort
			})
		})
		if !errors.Is(err, abort) || observed != 0 {
			t.Fatal("late failure lost rollback or dispatched an observer", err)
		}
		bad := attempt
		bad.Alert.TenantID = dependencyOtherTenant(d.f.tenants, tenant)
		if out, err := router(t.Context(), *d.rules[tenant], []alert.DependencyAttempt{attempt, bad}); err == nil || len(out) != 0 || observed != 0 {
			t.Fatal("failed batch dispatched or acknowledged a root prefix", observed, err)
		}
		d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			inc, err := (store.Incidents{}).Get(ctx, sc, d.cases[tenant])
			if err == nil && inc.SignalCount != 0 {
				t.Fatal("failed batch retained a staged root signal")
			}
			return err
		})
		if out, err := router(t.Context(), *d.rules[tenant], []alert.DependencyAttempt{attempt}); err != nil || len(out) != 1 || !out[0].IncidentPublished || observed != 1 {
			t.Fatal("committed source root missed its observer", observed, err)
		}
	}
}

func TestDependencyRootRecoveryFirstAppearsAfterLeaderRestart(t *testing.T) {
	d := seedDependencyRoutingFixture(t)
	for _, tenant := range d.f.tenants {
		mail, ordinary := &dependencyRoutingMail{}, 0
		var rows []tsdb.Series
		for i, node := range d.graphs[tenant].Nodes {
			rows = append(rows, tsdb.Series{Metric: d.rules[tenant].Metric, Labels: map[string]string{"tenant_id": tenant, "test_id": node.TestID, "agent_id": node.AgentID, "server_address": fmt.Sprintf("192.0.2.%d", i+1)}, Value: 0})
		}
		leader := func() *alert.Evaluator {
			eval, ok := BuildAlertEvaluator(d.f.pool, fakeQuerier{rows: rows}, alert.ChannelDeps{Mail: mail}, time.Second, tenancy.ID(tenant), func(context.Context, alert.Alert) { ordinary++ }, d.f.server.log,
				AlertTagDependencies{Gate: d.f.server.fairnessGate, FlowStore: d.f.server.flowStore, Queries: d.f.server})
			if !ok {
				t.Fatal("shipping evaluator unavailable")
			}
			return eval
		}
		evaluate := func(eval *alert.Evaluator) {
			t.Helper()
			if _, err := eval.Engine().Evaluate(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), *d.rules[tenant]); err != nil {
				t.Fatal(err)
			}
		}
		evaluate(leader())
		if len(mail.subjects) != 1 || ordinary != 0 {
			t.Fatal("initial root and held child were not source-backed", mail.subjects, ordinary)
		}
		d.observe(t, tenant, 0, true)
		rows[0].Value = 1
		evaluate(leader()) // no intervening failed sample on the replacement leader
		if len(mail.subjects) != 3 || ordinary != 0 {
			t.Fatal("leader restart lost the root recovery or child's first delivery", mail.subjects, ordinary)
		}
		d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var rootRecovery, childRelease int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FILTER(WHERE kind='alert.resolved' AND entity_id=$3),count(*) FILTER(WHERE attributes->>'dependency.state'='released') FROM incident_signals WHERE tenant_id=$1 AND incident_id=$2`, tenant, d.cases[tenant], d.graphs[tenant].Nodes[0].EntityID).Scan(&rootRecovery, &childRelease); err != nil {
				return err
			}
			if rootRecovery != 1 || childRelease != 1 {
				t.Fatal("restart recovery did not close the original visible history", rootRecovery, childRelease)
			}
			return nil
		})
	}
}
