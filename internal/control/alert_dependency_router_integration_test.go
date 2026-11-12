// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	guuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/pkg/sdk"
)

type dependencyRoutingFixture struct {
	f       *roleExplanationAPIFixture
	rules   map[string]*alert.Rule
	graphs  map[string]*alert.DependencyGraphInput
	cases   map[string]string
	serials map[string]string
}

func seedDependencyRoutingFixture(t *testing.T) *dependencyRoutingFixture {
	t.Helper()
	f, rules, graphs := seedDependencyGraphFixture(t)
	d := &dependencyRoutingFixture{f: f, rules: rules, graphs: graphs, cases: map[string]string{}, serials: map[string]string{}}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], "incident.read"); err != nil {
				return err
			}
			in := *rules[tenant]
			in.ForN = 1
			in.Channels = []alert.ChannelSpec{{Type: "email", Recipients: []string{"operator@example.test"}}}
			var err error
			rules[tenant], err = (store.AlertRules{}).Update(ctx, sc, in.ID, in)
			if err != nil {
				return err
			}
			root := graphs[tenant].Nodes[0]
			inc, err := (store.Incidents{}).Create(ctx, sc, incident.Incident{TenantID: tenant, Severity: incident.SeverityWarning, Title: "Existing upstream case", Target: "192.0.2.1", StartedAt: time.Now(), LastSeenAt: time.Now(), IdentityContextID: f.contextID, IdentityEntityID: root.EntityID, IdentityLookupAttempted: true})
			if err == nil {
				d.cases[tenant] = inc.ID
			}
			return err
		})
		serial := strings.ReplaceAll(guuid.NewString(), "-", "")
		d.serials[tenant] = serial
		agent := graphs[tenant].Nodes[0].AgentID
		if err := store.NewAgentIdentities(f.pool).Record(t.Context(), tenant, agent, crypto.EntitySPIFFEID(tenant, agent), serial, time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		for i := range graphs[tenant].Nodes {
			d.observe(t, tenant, i, false)
		}
		input := alert.DependencyPolicyInput{ContextID: f.contextID, FreshnessSeconds: 300, Graph: graphs[tenant]}
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		var body sdk.AlertDependencyPolicyInput
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		if _, err := client.SetAlertDependencyPolicy(t.Context(), sdk.SetAlertDependencyPolicyRequest{Id: rules[tenant].ID, Body: &body}); err != nil {
			t.Fatal(err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			rules[tenant], err = (store.AlertRules{}).Get(ctx, sc, rules[tenant].ID)
			return err
		})
	}
	return d
}

// Modeled complete echo data with a registered evidence identity; this helper
// proves real application-role storage/source validation, not a physical sender.
func (d *dependencyRoutingFixture) observe(t *testing.T, tenant string, index int, up bool) {
	t.Helper()
	node := d.graphs[tenant].Nodes[index]
	var definition testspec.ExecutableDefinition
	d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		var params []byte
		if err := sc.Q.QueryRow(ctx, `SELECT id::text,type,target,interval_seconds,timeout_seconds,params FROM tests WHERE tenant_id=$1 AND id=$2`, tenant, node.TestID).Scan(&definition.ID, &definition.Type, &definition.Target, &definition.IntervalSeconds, &definition.TimeoutSeconds, &params); err != nil {
			return err
		}
		return json.Unmarshal(params, &definition.Params)
	})
	digest, err := testspec.DefinitionHash(definition)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := canary.NewICMP(canary.Config{Type: definition.Type, Target: definition.Target, Interval: time.Duration(definition.IntervalSeconds) * time.Second, Timeout: time.Duration(definition.TimeoutSeconds) * time.Second, Params: definition.Params})
	if err != nil {
		t.Fatal(err)
	}
	n := uint32(canary.ICMPRequestedPackets(probe))
	at := d.f.observedAt(tenant)
	m := &entity.ICMPMeasurement{Version: 1, DefinitionHash: digest, StartedAt: at, CompletedAt: at, Requested: n, Attempted: n, Transmitted: n, ReadComplete: true, Responders: []string{}}
	if up {
		m.Replies = n
		m.Responders = []string{definition.Target}
	}
	claim := entity.Observation{ID: guuid.NewString(), Source: entity.SourceKey{AgentID: node.AgentID, Kind: entity.PathAgent, SourceRef: node.TestID}, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: definition.Target}, SourceRef: "icmp:configured-test", ObservedAt: at, ICMP: m}
	receipt, err := store.NewEntityRegistry(d.f.pool).WriteEvidenceBatchReceipt(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), node.AgentID, d.serials[tenant], []entity.Observation{claim})
	if err != nil || receipt.Accepted != 1 || receipt.Unresolved != 0 || receipt.ICMPMeasurements != 1 {
		t.Fatal("modeled current health was not retained", receipt, err)
	}
}

type dependencyRoutingMail struct{ subjects []string }

func (m *dependencyRoutingMail) Send(_ context.Context, _ []string, subject, _ string) error {
	m.subjects = append(m.subjects, subject)
	return nil
}

func TestDependencyRouterPublishesCurrentTwoTenantHoldsAndReleases(t *testing.T) {
	d := seedDependencyRoutingFixture(t)
	for _, tenant := range d.f.tenants {
		mail := &dependencyRoutingMail{}
		var rows []tsdb.Series
		for i, node := range d.graphs[tenant].Nodes {
			rows = append(rows, tsdb.Series{Metric: d.rules[tenant].Metric, Labels: map[string]string{"tenant_id": tenant, "test_id": node.TestID, "agent_id": node.AgentID, "server_address": fmt.Sprintf("192.0.2.%d", i+1)}, Value: 0})
		}
		ordinary := 0
		leader := func() *alert.Evaluator {
			eval, ok := BuildAlertEvaluator(d.f.pool, fakeQuerier{rows: rows}, alert.ChannelDeps{Mail: mail}, time.Second, tenancy.ID(tenant), func(_ context.Context, a alert.Alert) {
				if a.TenantID != tenant {
					t.Fatal("ordinary sink crossed tenant")
				}
				ordinary++
			}, d.f.server.log, AlertTagDependencies{Gate: d.f.server.fairnessGate, FlowStore: d.f.server.flowStore, Queries: d.f.server})
			if !ok {
				t.Fatal("shipping evaluator could not be built")
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
		countHeld := func() int {
			t.Helper()
			var count int
			d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
				return sc.Q.QueryRow(ctx, `SELECT count(*) FROM incident_signals WHERE tenant_id=$1 AND incident_id=$2 AND attributes->>'dependency.state'='held'`, tenant, d.cases[tenant]).Scan(&count)
			})
			return count
		}
		evaluate()
		if len(mail.subjects) != 1 || ordinary != 0 || len(eval.Engine().Active()) != 2 || countHeld() != 1 {
			t.Fatal("router did not keep one upstream delivery and visible held downstream", mail.subjects, ordinary, len(eval.Engine().Active()), countHeld())
		}
		d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var root int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM incident_signals WHERE tenant_id=$1 AND incident_id=$2 AND kind='alert.firing' AND entity_id=$3 AND identity_lookup_attempted`, tenant, d.cases[tenant], d.graphs[tenant].Nodes[0].EntityID).Scan(&root); err != nil {
				return err
			}
			if root != 1 {
				t.Fatal("ordinary root was acknowledged without a canonical persisted signal", root)
			}
			var held int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM alert_notifications WHERE tenant_id=$1 AND firing_since IS NOT NULL AND last_notified='0001-01-01'::timestamptz`, tenant).Scan(&held); err != nil {
				return err
			}
			if held != 1 {
				t.Fatal("held signal was not committed with exactly one undelivered notification state", held)
			}
			return nil
		})
		eval = leader()
		evaluate()
		if len(mail.subjects) != 1 || countHeld() != 1 {
			t.Fatal("restart duplicated notification or visible held signal", mail.subjects, countHeld())
		}
		d.observe(t, tenant, 0, true)
		rows[0].Value = 1
		evaluate()
		if len(mail.subjects) != 3 || len(eval.Engine().Active()) != 1 {
			t.Fatal("upstream recovery did not release the persistent child once", mail.subjects, eval.Engine().Active())
		}
		d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var released int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM incident_signals WHERE tenant_id=$1 AND incident_id=$2 AND attributes->>'dependency.state'='released'`, tenant, d.cases[tenant]).Scan(&released); err != nil {
				return err
			}
			if released != 1 {
				t.Fatal("upstream recovery lost the child's original visible relationship", released)
			}
			return nil
		})
		evaluate()
		if len(mail.subjects) != 3 {
			t.Fatal("released child was notified twice", mail.subjects)
		}
	}
	t.Log("real-integration: shipping evaluator, verified HTTPS configuration and actual app-role Postgres/RLS hold/restart/release with overlapping canonical tenant identities; echo data, initial parent cases and mail sink are modeled; physical router and live delivery proof remain separate")
}

func TestDependencyRouterRefusesWithdrawnForeignAndAmbiguousAuthority(t *testing.T) {
	d := seedDependencyRoutingFixture(t)
	a, b := d.f.tenants[0], d.f.tenants[1]
	node := d.graphs[a].Nodes[1]
	attempt := alert.DependencyAttempt{Alert: alert.Alert{TenantID: a, RuleID: d.rules[a].ID, RuleName: d.rules[a].Name, Metric: d.rules[a].Metric, State: alert.StateFiring, Labels: map[string]string{"tenant_id": a, "test_id": node.TestID, "agent_id": node.AgentID, "server_address": "192.0.2.2"}, At: time.Now()}, NotificationDue: true, FiringSince: time.Now(), RuleUpdatedAt: d.rules[a].UpdatedAt}
	router := d.f.server.alertDependencyRouter(tenancy.ID(a))
	out, err := router(t.Context(), *d.rules[a], []alert.DependencyAttempt{attempt})
	if err != nil || len(out) != 1 || !out[0].Decision.Held() || !out[0].IncidentPublished || !out[0].NotificationStatePublished || out[0].Decision.Causes()[0].IncidentID != d.cases[a] {
		t.Fatal("positive tenant control did not establish a durable owned hold", out, err)
	}
	counts := func(tenant string) (int, int) {
		t.Helper()
		var signals, notifications int
		d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM incident_signals WHERE tenant_id=$1 AND attributes->>'dependency.state'='held'`, tenant).Scan(&signals); err != nil {
				return err
			}
			return sc.Q.QueryRow(ctx, `SELECT count(*) FROM alert_notifications WHERE tenant_id=$1`, tenant).Scan(&notifications)
		})
		return signals, notifications
	}
	if sig, n := counts(b); sig != 0 || n != 0 {
		t.Fatal("owned hold touched sibling state", sig, n)
	}
	refuse := func(name string, rule alert.Rule, in alert.DependencyAttempt) {
		t.Helper()
		beforeS, beforeN := counts(a)
		out, err := router(t.Context(), rule, []alert.DependencyAttempt{in})
		if err != nil && len(out) != 0 {
			t.Fatal(name, "returned an uncommitted prefix")
		}
		for _, item := range out {
			if item.Decision.Held() || len(item.Decision.Causes()) != 0 {
				t.Fatal(name, "disclosed or accepted hold authority", out)
			}
		}
		afterS, afterN := counts(a)
		if beforeS != afterS || beforeN != afterN {
			t.Fatal(name, "changed durable hold state", beforeS, afterS, beforeN, afterN)
		}
	}
	foreign := attempt
	foreign.Alert.TenantID = b
	refuse("foreign attempt", *d.rules[a], foreign)
	refuse("foreign rule", *d.rules[b], attempt)
	old := *d.rules[a]
	old.UpdatedAt = old.UpdatedAt.Add(-time.Second)
	refuse("old policy revision", old, attempt)
	foreign = attempt
	foreign.Alert.Labels = map[string]string{"test_id": d.graphs[b].Nodes[1].TestID, "agent_id": d.graphs[b].Nodes[1].AgentID}
	refuse("foreign source nomination", *d.rules[a], foreign)
	d.f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='incident.read'`, a, d.f.roles[a])
		return err
	})
	refuse("current read withdrawal", *d.rules[a], attempt)
	d.f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.Roles{}).AddPermission(ctx, sc, d.f.roles[a], "incident.read")
	})
	d.f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		if err := tenancy.LockTenantAuditStream(ctx, sc.Q, a); err != nil {
			return err
		}
		return sourceepoch.InvalidateSourceGenerationInScope(ctx, sc)
	})
	refuse("active observation erasure", *d.rules[a], attempt)
	d.f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE flow_snapshot_epochs SET invalidating=false,transition_token=NULL WHERE tenant_id=$1`, a)
		return err
	})
	d.observe(t, a, 0, false)
	d.observe(t, a, 1, false)
	// A failure after both effects were staged must roll back the whole scope.
	beforeS, beforeN := counts(b)
	rollback := errors.New("required late publication refusal")
	err = tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(b)), d.f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.AlertRules{}).WithDependencyPublication(ctx, sc, d.rules[b].ID, d.rules[b].UpdatedAt, 128<<20, func(ctx context.Context, sc tenancy.Scope, policy *alert.DependencyPolicy) error {
			own := attempt
			own.Alert.TenantID = b
			own.Alert.RuleID = d.rules[b].ID
			own.Alert.Labels = map[string]string{"test_id": d.graphs[b].Nodes[1].TestID, "agent_id": d.graphs[b].Nodes[1].AgentID}
			own.RuleUpdatedAt = d.rules[b].UpdatedAt
			out, err := d.f.server.publishDependencyAttempts(ctx, sc, *d.rules[b], policy, []alert.DependencyAttempt{own}, 256<<20)
			if err != nil {
				return err
			}
			if len(out) != 1 || !out[0].Decision.Held() {
				t.Fatal("late-refusal control never staged a real hold")
			}
			return rollback
		})
	})
	if !errors.Is(err, rollback) {
		t.Fatal("late publication did not refuse", err)
	}
	if sig, n := counts(b); sig != beforeS || n != beforeN {
		t.Fatal("late refusal committed a successful prefix", sig, n, beforeS, beforeN)
	}
	// A second current source attesting the child's address as a different
	// canonical device makes identity ambiguous; never choose a UUID winner.
	claim := entity.Observation{ID: guuid.NewString(), Source: entity.SourceKey{AgentID: "role-snmp", Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"}, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "192.0.2.2"}, SourceRef: "snmp:ifIndex:7", ObservedAt: d.f.observedAt(a)}
	if receipt, err := store.NewEntityRegistry(d.f.pool).WriteEvidenceBatchReceipt(tenancy.WithTenant(t.Context(), tenancy.ID(a)), "role-snmp", d.f.serials[a+"role-snmp"], []entity.Observation{claim}); err != nil || receipt.Accepted != 1 {
		t.Fatal("ambiguity control was not retained", receipt, err)
	}
	refuse("current canonical ambiguity", *d.rules[a], attempt)
	d.f.in(b, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND serial=$2`, b, d.serials[b])
		return err
	})
	other := d.f.server.alertDependencyRouter(tenancy.ID(b))
	own := attempt
	own.Alert.TenantID = b
	own.Alert.RuleID = d.rules[b].ID
	own.Alert.Labels = map[string]string{"test_id": d.graphs[b].Nodes[1].TestID}
	own.RuleUpdatedAt = d.rules[b].UpdatedAt
	if out, err := other(t.Context(), *d.rules[b], []alert.DependencyAttempt{own}); err == nil || len(out) != 0 {
		t.Fatal("revoked issued source produced hold authority", out, err)
	}
	t.Log("real-integration: paired app-role PG/RLS, current source/owner/credential ceiling, foreign tuple, erasure, canonical ambiguity, revocation and atomic late-refusal controls; issued identities and echo facts are modeled")
}

func TestDependencyRouterTracksRepeatedHoldsAfterDeliveredRestart(t *testing.T) {
	d := seedDependencyRoutingFixture(t)
	for _, tenant := range d.f.tenants {
		mail := &dependencyRoutingMail{}
		node := d.graphs[tenant].Nodes[1]
		rows := []tsdb.Series{{Metric: d.rules[tenant].Metric, Labels: map[string]string{"tenant_id": tenant, "test_id": node.TestID, "agent_id": node.AgentID, "server_address": "192.0.2.2"}, Value: 0}}
		leader := func() *alert.Evaluator {
			eval, ok := BuildAlertEvaluator(d.f.pool, fakeQuerier{rows: rows}, alert.ChannelDeps{Mail: mail}, time.Second, tenancy.ID(tenant), nil, d.f.server.log, AlertTagDependencies{Gate: d.f.server.fairnessGate, FlowStore: d.f.server.flowStore, Queries: d.f.server})
			if !ok {
				t.Fatal("shipping evaluator could not be built")
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
		count := func(state string) int {
			t.Helper()
			var n int
			d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
				return sc.Q.QueryRow(ctx, `SELECT count(*) FROM incident_signals WHERE tenant_id=$1 AND incident_id=$2 AND attributes->>'dependency.state'=$3`, tenant, d.cases[tenant], state).Scan(&n)
			})
			return n
		}
		// A child can already have been delivered before its upstream fails.
		d.observe(t, tenant, 0, true)
		evaluate()
		if len(mail.subjects) != 1 {
			t.Fatal("independent delivered-episode control never notified", mail.subjects)
		}
		d.observe(t, tenant, 0, false)
		evaluate()
		if count("held") != 1 || len(mail.subjects) != 1 {
			t.Fatal("upstream failure did not hold the already-delivered episode", count("held"), mail.subjects)
		}
		d.observe(t, tenant, 0, true)
		eval = leader() // recovery first appears after leadership reload
		evaluate()
		if count("released") != 1 || len(mail.subjects) != 1 {
			t.Fatal("restart lost the held marker or renotified an already-delivered episode", count("released"), mail.subjects)
		}
		d.observe(t, tenant, 0, false)
		evaluate()
		d.observe(t, tenant, 0, true)
		evaluate()
		if count("held") != 2 || count("released") != 2 || len(mail.subjects) != 1 {
			t.Fatal("a second upstream outage lost its own visible hold/release transition", count("held"), count("released"), mail.subjects)
		}
	}
}

func TestDependencyRouterClosesHeldResolutionBeforeDroppingState(t *testing.T) {
	d := seedDependencyRoutingFixture(t)
	for _, tenant := range d.f.tenants {
		node := d.graphs[tenant].Nodes[1]
		mail := &dependencyRoutingMail{}
		rows := []tsdb.Series{{Metric: d.rules[tenant].Metric, Labels: map[string]string{"tenant_id": tenant, "test_id": node.TestID, "agent_id": node.AgentID, "server_address": "192.0.2.2"}, Value: 0}}
		eval, ok := BuildAlertEvaluator(d.f.pool, fakeQuerier{rows: rows}, alert.ChannelDeps{Mail: mail}, time.Second, tenancy.ID(tenant), nil, d.f.server.log, AlertTagDependencies{Gate: d.f.server.fairnessGate, FlowStore: d.f.server.flowStore, Queries: d.f.server})
		if !ok {
			t.Fatal("shipping evaluator could not be built")
		}
		evaluate := func() {
			t.Helper()
			if _, err := eval.Engine().Evaluate(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), *d.rules[tenant]); err != nil {
				t.Fatal(err)
			}
		}
		evaluate()
		d.observe(t, tenant, 1, true)
		rows[0].Value = 1
		evaluate()
		if len(mail.subjects) != 0 || len(eval.Engine().Active()) != 0 {
			t.Fatal("never-delivered held episode sent a false resolution", mail.subjects, eval.Engine().Active())
		}
		d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var closed, pending int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM incident_signals WHERE tenant_id=$1 AND incident_id=$2 AND attributes->>'dependency.state'='resolved'`, tenant, d.cases[tenant]).Scan(&closed); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM alert_notifications WHERE tenant_id=$1`, tenant).Scan(&pending); err != nil {
				return err
			}
			if closed != 1 || pending != 0 {
				t.Fatal("resolution dropped its transition before closing the visible child or retained the old episode", closed, pending)
			}
			return nil
		})
		// The old resolve callback must have finished before the next episode.
		d.observe(t, tenant, 1, false)
		rows[0].Value = 0
		evaluate()
		d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var pending int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM alert_notifications WHERE tenant_id=$1 AND dependency_held AND dependency_transition IS NOT NULL`, tenant).Scan(&pending); err != nil {
				return err
			}
			if pending != 1 {
				t.Fatal("a prior cleanup deleted the next episode's durable hold", pending)
			}
			return nil
		})
	}
}

func TestDependencyHealthPopulationKeepsExactSourcesAndTenantScope(t *testing.T) {
	d := seedDependencyRoutingFixture(t)
	for _, tenant := range d.f.tenants {
		d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			scope := entity.Scope{TenantID: tenant, ContextID: d.f.contextID}
			registry := store.NewEntityRegistry(d.f.pool)
			var requests []store.ICMPHealthRequest
			var aliases []entity.AliasKey
			for _, node := range d.graphs[tenant].Nodes {
				requests = append(requests, store.ICMPHealthRequest{EntityID: node.EntityID,
					Source: entity.SourceKey{AgentID: node.AgentID, Kind: entity.PathAgent, SourceRef: node.TestID}})
			}
			values, err := registry.ReadICMPHealthPopulationInScope(ctx, sc, scope, requests, time.Minute, 1<<20)
			if err != nil || len(values) != len(requests) {
				t.Fatal("complete population unavailable", err)
			}
			for i, request := range requests {
				one, err := registry.ReadICMPHealthInScope(ctx, sc, scope, request.Source, request.EntityID, time.Minute, 1<<20)
				if err != nil || values[i].State != "down" || values[i].EvidenceID != one.EvidenceID || values[i].SenderSerial != one.SenderSerial || !reflect.DeepEqual(values[i].Observation, one.Observation) || !values[i].FreshUntil.Equal(one.FreshUntil) {
					t.Fatal("pipelining changed exact current-source evidence", i, err)
				}
				single, err := registry.ReadICMPHealthPopulationInScope(ctx, sc, scope, []store.ICMPHealthRequest{request}, time.Minute, 1<<20)
				if err != nil || len(single) != 1 || single[0].EvidenceID != one.EvidenceID || !reflect.DeepEqual(single[0].Observation, one.Observation) {
					t.Fatal("single-source population changed exact current-source evidence", i, err)
				}
				aliases = append(aliases, values[i].Observation.Alias)
			}
			resolved, err := store.ResolveAliasPopulationInScope(ctx, sc, scope, aliases, 1<<20)
			if err != nil || len(resolved) != len(requests) {
				t.Fatal("complete alias population unavailable", err)
			}
			var entityIDs []string
			for i, resolution := range resolved {
				one, err := store.ResolveAliasInScope(ctx, sc, scope, aliases[i])
				if err != nil || !reflect.DeepEqual(resolution, one) || resolution.Status != entity.Resolved || resolution.EntityID != requests[i].EntityID {
					t.Fatal("pipelining changed canonical ambiguity/support", i, err)
				}
				entityIDs = append(entityIDs, requests[i].EntityID)
			}
			cases, err := (store.Incidents{}).DependencyCauseIncidents(ctx, sc, scope.ContextID, entityIDs, 1<<20)
			if err != nil || len(cases) != 1 || cases[requests[0].EntityID] != d.cases[tenant] {
				t.Fatal("case population borrowed another tenant or lost its root", err)
			}
			foreign := tenancy.WithTenant(ctx, tenancy.ID(dependencyOtherTenant(d.f.tenants, tenant)))
			if out, err := registry.ReadICMPHealthPopulationInScope(foreign, sc, scope, requests, time.Minute, 1<<20); err == nil || len(out) != 0 {
				t.Fatal("foreign context borrowed a storage scope")
			}
			if out, err := store.ResolveAliasPopulationInScope(foreign, sc, scope, aliases, 1<<20); err == nil || len(out) != 0 {
				t.Fatal("foreign alias context borrowed a storage scope")
			}
			requests[len(requests)-1].Source.SourceRef = guuid.NewString()
			unknown, err := registry.ReadICMPHealthPopulationInScope(ctx, sc, scope, requests, time.Minute, 1<<20)
			if err != nil || unknown[len(unknown)-1].State != "unknown" {
				t.Fatal("missing source inherited a different source's health", err)
			}
			requests[len(requests)-1].Source.SourceRef = d.graphs[tenant].Nodes[len(requests)-1].TestID
			requests[0].Source.SourceRef = guuid.NewString()
			unknown, err = registry.ReadICMPHealthPopulationInScope(ctx, sc, scope, requests, time.Minute, 1<<20)
			if err != nil || unknown[0].State != "unknown" || unknown[len(unknown)-1].Observation.Source.SourceRef != requests[len(requests)-1].Source.SourceRef {
				t.Fatal("sparse source rows changed another request's evidence", err)
			}
			sparse := []entity.AliasKey{aliases[0], {Kind: entity.AddressAlias, Value: "203.0.113.254"}, aliases[len(aliases)-1]}
			missing, err := store.ResolveAliasPopulationInScope(ctx, sc, scope, sparse, 1<<20)
			if err != nil || len(missing) != len(sparse) || missing[0].EntityID != d.graphs[tenant].Nodes[0].EntityID || missing[1].Status == entity.Resolved || missing[2].EntityID != d.graphs[tenant].Nodes[len(requests)-1].EntityID {
				t.Fatal("sparse alias rows borrowed another request's identity", err)
			}
			aliases[len(aliases)-1] = entity.AliasKey{Kind: entity.AddressAlias, Value: "invalid-address"}
			if out, err := store.ResolveAliasPopulationInScope(ctx, sc, scope, aliases, 1<<20); err == nil || len(out) != 0 {
				t.Fatal("invalid final alias returned a successful prefix")
			}
			return nil
		})
	}
}

func dependencyOtherTenant(tenants []string, own string) string {
	for _, tenant := range tenants {
		if tenant != own {
			return tenant
		}
	}
	return ""
}
