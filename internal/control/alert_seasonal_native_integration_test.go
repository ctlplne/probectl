// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestSeasonalNativeSourceKeepsTenantAndOriginalAuthority(t *testing.T) {
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(wire, func(t *testing.T) { proveSeasonalNativeSource(t, wire) })
	}
}

func proveSeasonalNativeSource(t *testing.T, wire string) {
	t.Helper()
	f := newRoleExplanationAPIFixture(t)
	seedInterfaceRoleMCPConsent(f)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	rules, tests := map[string]string{}, map[string]string{}
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permAIQuery, permAlertRead, permAlertWrite, "test.read"} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			test, err := (store.Tests{}).Create(ctx, sc, store.TestInput{Name: "Owned latency test", Type: "icmp", Target: "192.0.2.5", IntervalSeconds: 60, TimeoutSeconds: 5, Enabled: true})
			if err == nil {
				tests[tenant] = test.ID
			}
			return err
		})
		raw := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPost, "/v1/alerts", map[string]any{
			"name": "Owned latency baseline", "metric": "probectl_probe_rtt_avg_ms", "type": "baseline", "window": 20, "sensitivity": 3,
		}, http.StatusCreated)
		var rule alert.Rule
		if err := json.Unmarshal(raw, &rule); err != nil || rule.ID == "" {
			t.Fatal("could not read created rule", err)
		}
		rules[tenant] = rule.ID
	}

	const get, set, clear = "alert_seasonal_source_get", "alert_seasonal_source_set", "alert_seasonal_source_clear"
	direction := map[string]alert.SeasonalDirection{f.tenants[0]: alert.SeasonalAbove, f.tenants[1]: alert.SeasonalBelow}
	getArgs := func(tenant string) map[string]any { return map[string]any{"rule_id": rules[tenant]} }
	setArgs := func(ruleTenant, testTenant string) map[string]any {
		return map[string]any{"rule_id": rules[ruleTenant], "input": alert.SeasonalBaselineInput{
			Cadence: anomaly.SeasonalHourly, Direction: direction[ruleTenant], Timezone: "America/New_York",
			MinimumChange: 5, Holidays: []string{"2026-11-26"}, TestID: tests[testTenant],
		}}
	}
	assertOwned := func(tenant string, state alert.SeasonalSourceState) {
		t.Helper()
		if state.RuleID != rules[tenant] || !state.Configured || !state.Enabled || state.Source == nil || state.Source.TestID != tests[tenant] ||
			state.Source.Cadence != anomaly.SeasonalHourly || state.Source.Direction != direction[tenant] || state.Source.Timezone != "America/New_York" ||
			state.Source.MinimumChange != 5 || len(state.Source.Holidays) != 1 || state.Source.Holidays[0] != "2026-11-26" {
			t.Fatal("native response lost the owned source or its local clock")
		}
	}
	call := interfaceRoleNativeTLSCaller(t, f, wire)
	a, b := f.tenants[0], f.tenants[1]
	call(a, set, setArgs(a, b), nil, false)
	call(a, set, setArgs(b, a), nil, false)
	call(b, get, getArgs(a), nil, false)
	call(b, clear, map[string]any{"rule_id": rules[a], "confirmed": true}, nil, false)
	cfg := &config.Config{AIRedactIPs: true, AIRedactHostnames: true, AIRedactPII: true}
	server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, f.server.pathStore, 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), AISources{NativeFlow: f.server})
	authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
	streams := map[string]*interfaceRoleStdioClient{}
	for _, tenant := range f.tenants {
		var state alert.SeasonalSourceState
		call(tenant, set, setArgs(tenant, tenant), &state, true)
		assertOwned(tenant, state)
		streams[tenant] = openInterfaceRoleStdio(t, server, authenticator, f.tokens[tenant], wire)
		streams[tenant].call(t, wire, get, getArgs(tenant), &state, true)
		assertOwned(tenant, state)
	}
	streams[b].call(t, wire, get, getArgs(a), nil, false)
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, "DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='test.read'", a, f.roles[a])
		return err
	})
	streams[a].call(t, wire, get, getArgs(a), nil, false)
	streams[a].call(t, wire, set, setArgs(a, a), nil, false)
	streams[a].call(t, wire, clear, getArgs(a), nil, false)
	var cleared, sibling alert.SeasonalSourceState
	streams[a].call(t, wire, clear, map[string]any{"rule_id": rules[a], "confirmed": true}, &cleared, true)
	if cleared.Configured || cleared.Source != nil || cleared.Enabled {
		t.Fatal("confirmed clear left the seasonal source or rule enabled")
	}
	streams[b].call(t, wire, get, getArgs(b), &sibling, true)
	assertOwned(b, sibling)
}
