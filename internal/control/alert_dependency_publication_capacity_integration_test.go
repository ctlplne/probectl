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
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Reading and deciding a complete population does not establish that its
// notification state and visible incident signals can actually be committed.
// Exercise the shipping router's admission, locks and final authority check.
func TestDependencyRouterCompleteTwentyThousandDurableHolds(t *testing.T) {
	d := seedDependencyRoutingFixture(t)
	t.Cleanup(func() {
		for _, query := range []string{
			`DELETE FROM entity_source_contexts WHERE tenant_id=ANY($1::uuid[])`,
			`DELETE FROM entity_path_test_contexts WHERE tenant_id=ANY($1::uuid[])`,
			`DELETE FROM entity_test_contexts WHERE tenant_id=ANY($1::uuid[])`,
		} {
			if _, err := d.f.pool.Exec(context.Background(), query, d.f.tenants); err != nil {
				t.Error(err)
			}
		}
	})
	for lane, tenant := range d.f.tenants {
		seededAt := time.Now()
		rows, graph := seedDependencyHealthPopulation(t, d, tenant, 20_000)
		d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			rule := d.rules[tenant]
			policy, err := (store.AlertRules{}).GetDependencyPolicy(ctx, sc, rule.ID, rule.UpdatedAt, 256<<20)
			if err != nil {
				return err
			}
			policy.Graph = graph
			ceiling, err := policy.CredentialCeiling(tenant)
			if err != nil {
				return err
			}
			d.rules[tenant], err = (store.AlertRules{}).SetDependencyPolicy(ctx, sc, rule.ID, rule.UpdatedAt, policy, 256<<20,
				func(ctx context.Context, sc tenancy.Scope) error {
					return d.f.server.dependencyContextAuthority(ctx, sc, ceiling, policy.ContextID, true, graph, 256<<20)
				})
			return err
		})
		t.Logf("complete publication source/policy setup: tenant lane %d, elapsed %s", lane, time.Since(seededAt))
		attempts := make([]alert.DependencyAttempt, len(rows))
		for i, row := range rows {
			attempts[i] = alert.DependencyAttempt{
				Alert: alert.Alert{TenantID: tenant, RuleID: d.rules[tenant].ID, RuleName: d.rules[tenant].Name,
					Metric: d.rules[tenant].Metric, State: alert.StateFiring, At: row.Measurement.CompletedAt,
					Labels: map[string]string{"tenant_id": tenant, "agent_id": row.AgentID, "test_id": row.TestID, "server_address": row.Target}},
				NotificationDue: true, FiringSince: row.Measurement.CompletedAt, RuleUpdatedAt: d.rules[tenant].UpdatedAt,
			}
		}
		publicationStarted := time.Now()
		out, err := d.f.server.alertDependencyRouter(tenancy.ID(tenant))(t.Context(), *d.rules[tenant], attempts)
		if err != nil || len(out) != len(rows) {
			t.Fatal("complete durable publication was refused or shortened", len(out), time.Since(publicationStarted), err)
		}
		d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			notifications, err := (store.AlertNotifications{}).List(ctx, sc)
			if err != nil {
				return err
			}
			if len(notifications) != len(rows)-1 {
				t.Fatal("complete child notification state was not durable", len(notifications))
			}
			byKey := make(map[string]store.AlertNotification, len(notifications))
			for _, row := range notifications {
				byKey[row.Fingerprint] = row
			}
			for i, outcome := range out {
				if outcome.Decision.Held() != (i > 0) || !outcome.IncidentPublished {
					t.Fatal("complete publication lost an exact decision or incident", i)
				}
				if i == 0 {
					continue
				}
				n := byKey[outcome.Decision.NotificationFingerprint()]
				causes := outcome.Decision.Causes()
				if !outcome.NotificationStatePublished || n.Dependency == nil || !n.Dependency.Held || n.Dependency.TransitionID == "" || !n.LastNotified.IsZero() ||
					!n.FiringSince.Equal(attempts[i].FiringSince) || len(causes) != 1 || causes[0].TenantID != tenant || causes[0].IncidentID != d.cases[tenant] {
					t.Fatal("durable child state lost its exact episode or owned cause", i)
				}
			}
			var signals, held, identities int
			err = sc.Q.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE attributes->>'dependency.state'='held'),
				count(DISTINCT entity_id) FROM incident_signals
				WHERE tenant_id=$1 AND incident_id=$2 AND entity_context_id=$3 AND identity_lookup_attempted`,
				tenant, d.cases[tenant], d.f.contextID).Scan(&signals, &held, &identities)
			if err == nil && (signals != len(rows) || held != len(rows)-1 || identities != len(rows)) {
				t.Fatal("complete publication lost visible canonical children", signals, held, identities)
			}
			return err
		})
	}
	t.Log("real-integration: complete 20,000-source publication in each RLS tenant through shipping admission/current-authority/incident/notification storage; sender observations and initial parent cases modeled, no physical delivery claim")
}
