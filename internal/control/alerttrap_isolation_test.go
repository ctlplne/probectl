// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type trapAlertCapture struct {
	mu     sync.Mutex
	alerts []alert.Alert
}

func (c *trapAlertCapture) sink(_ context.Context, a alert.Alert) {
	c.mu.Lock()
	c.alerts = append(c.alerts, a)
	c.mu.Unlock()
}

func (c *trapAlertCapture) take() []alert.Alert {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.alerts
	c.alerts = nil
	return out
}

// TestTrapAlertRulesAreTenantIsolated is the isolation receipt for
// trap-driven alert rules (D-61) on real Postgres, through the production
// evaluator wiring (BuildAlertEvaluator: rules from alert_rules, traps from
// device_traps, both under the tenant's forced row security). Two tenants hold
// the SAME rule (linkDown on 10.0.0.1, cleared by linkUp) and their devices
// share that address. A trap stored for B never fires A's rule; A's own trap
// fires A's rule only; A's linkUp resolves it; a rule with a short hold
// resolves when the hold runs out.
func TestTrapAlertRulesAreTenantIsolated(t *testing.T) {
	ctx := context.Background()
	db := trapIsolationDB(t)
	suffix := time.Now().UnixNano()
	ids := map[string]string{}
	for _, name := range []string{"a", "b"} {
		tn, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("trap-alert-%s-%d", name, suffix), "Trap alert "+name)
		if err != nil {
			t.Fatal(err)
		}
		ids[name] = tn.ID
	}
	const linkDown, linkUp = ".1.3.6.1.6.3.1.1.5.3", ".1.3.6.1.6.3.1.1.5.4"
	createRule := func(tenant, name string, m alert.TrapMatch) string {
		t.Helper()
		rule := alert.Rule{Name: name, Enabled: true, Type: alert.Trap, Severity: alert.SeverityCritical, Trap: &m}
		if err := rule.Validate(); err != nil {
			t.Fatal(err)
		}
		alert.NormalizeTrapRule(&rule)
		var id string
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			created, err := store.AlertRules{}.Create(ctx, sc, rule)
			if err != nil {
				return err
			}
			if created.Trap == nil || created.Trap.TrapOID != linkDown || created.Type != alert.Trap {
				t.Fatalf("stored trap rule read back as %+v", created)
			}
			id = created.ID
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	match := alert.TrapMatch{TrapOID: linkDown, ClearTrapOID: linkUp, Device: "10.0.0.1",
		VarBindOID: ".1.3.6.1.2.1.2.2.1.1.2", VarBindValue: "2", HoldSeconds: 3600}
	ruleA := createRule(ids["a"], "uplink down", match)
	ruleB := createRule(ids["b"], "uplink down", match)
	short := match
	short.ClearTrapOID, short.HoldSeconds = "", alert.MinTrapHoldSeconds
	ruleAShort := createRule(ids["a"], "uplink down (no clear)", short)

	traps := store.NewDeviceTraps(db.Pool())
	seq := 0
	sendTrap := func(tenant, oid string, at time.Time) {
		t.Helper()
		seq++
		if _, err := traps.RecordTrapEvent(ctx, tenant, device.TrapRecord{
			TenantID: tenant, AgentID: "agent-1", DeviceAddress: "10.0.0.1", Version: "snmpv2c",
			Kind: "snmp.trap", Severity: "warning", TrapOID: oid, Fingerprint: fmt.Sprintf("fp-%d", seq),
			ObservedAt: at, ReceivedAt: at,
			VarBinds: []device.TrapVarBind{{OID: ".1.3.6.1.2.1.2.2.1.1.2", Type: "Integer", Value: "2"}},
		}); err != nil {
			t.Fatal(err)
		}
	}

	log := logging.New(io.Discard, "error", "json")
	captures := map[string]*trapAlertCapture{"a": {}, "b": {}}
	evals := map[string]*alert.Evaluator{}
	for name, id := range ids {
		ev, ok := BuildAlertEvaluator(db.Pool(), tsdb.NewMemory(), alert.ChannelDeps{}, time.Second, tenancy.ID(id), captures[name].sink, log)
		if !ok {
			t.Fatal("BuildAlertEvaluator refused the in-memory TSDB")
		}
		evals[name] = ev
	}
	tick := func() {
		t.Helper()
		for _, name := range []string{"a", "b"} {
			if err := evals[name].Tick(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	firing := func(alerts []alert.Alert, rule string, state alert.State) bool {
		for _, a := range alerts {
			if a.RuleID == rule && a.State == state {
				return true
			}
		}
		return false
	}
	now := time.Now().UTC()

	// B's device sends linkDown: only B's rule fires.
	sendTrap(ids["b"], linkDown, now.Add(-10*time.Second))
	tick()
	gotA, gotB := captures["a"].take(), captures["b"].take()
	if len(gotA) != 0 {
		t.Fatalf("CROSS-TENANT TRAP ALERT: tenant B's trap fired tenant A's rules: %+v", gotA)
	}
	if !firing(gotB, ruleB, alert.StateFiring) || len(gotB) != 1 || gotB[0].TenantID != ids["b"] ||
		gotB[0].Labels["device"] != "10.0.0.1" || gotB[0].Metric != alert.TrapMetric {
		t.Fatalf("tenant B's own trap did not fire exactly its rule: %+v", gotB)
	}

	// A's device sends linkDown: A's two rules fire, B sees nothing new.
	sendTrap(ids["a"], linkDown, now.Add(-5*time.Second))
	tick()
	gotA, gotB = captures["a"].take(), captures["b"].take()
	if !firing(gotA, ruleA, alert.StateFiring) || !firing(gotA, ruleAShort, alert.StateFiring) || len(gotA) != 2 {
		t.Fatalf("tenant A's trap fired %+v, want both of A's rules", gotA)
	}
	for _, a := range gotA {
		if a.TenantID != ids["a"] {
			t.Fatalf("tenant A's alert names tenant %s", a.TenantID)
		}
	}
	if len(gotB) != 0 {
		t.Fatalf("CROSS-TENANT TRAP ALERT: tenant A's trap re-notified tenant B: %+v", gotB)
	}

	// Still held: nothing re-notifies.
	tick()
	if got := captures["a"].take(); len(got) != 0 {
		t.Fatalf("a held trap re-notified: %+v", got)
	}

	// Ninety seconds pass (the stored receive time moves back): the 60-second
	// hold of the no-clear rule runs out and it resolves; the one-hour rule holds.
	if _, err := db.Pool().Exec(ctx, `UPDATE device_traps SET received_at = received_at - interval '90 seconds' WHERE tenant_id = $1`, ids["a"]); err != nil {
		t.Fatal(err)
	}
	tick()
	gotA = captures["a"].take()
	if !firing(gotA, ruleAShort, alert.StateResolved) || len(gotA) != 1 {
		t.Fatalf("after the hold ran out A acted %+v, want only the short-hold rule resolved", gotA)
	}

	// A's linkUp resolves A's clear-trap rule only.
	sendTrap(ids["a"], linkUp, now)
	tick()
	gotA, gotB = captures["a"].take(), captures["b"].take()
	if !firing(gotA, ruleA, alert.StateResolved) || len(gotA) != 1 {
		t.Fatalf("tenant A's linkUp resolved %+v, want only A's clear-trap rule", gotA)
	}
	if len(gotB) != 0 {
		t.Fatalf("tenant A's linkUp touched tenant B: %+v", gotB)
	}
	if active := evals["b"].Engine().Active(); len(active) != 1 {
		t.Fatalf("tenant B's rule should still be firing, active = %+v", active)
	}
}
