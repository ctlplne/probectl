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

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type opticalPublicationSnapshot struct {
	*tsdb.Memory
	after func()
}

func (s *opticalPublicationSnapshot) Snapshot() []tsdb.Series {
	rows := s.Memory.Snapshot()
	if s.after != nil {
		after := s.after
		s.after = nil
		after()
	}
	return rows
}

// Real TLS MCP and current Postgres/RLS authority, with modeled device gauges.
func TestOpticalFleetNativeTLSAndStdioKeepCurrentTenantMetricAuthority(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	writer := &opticalPublicationSnapshot{Memory: tsdb.NewMemory()}
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], "ai.query")
		})
		if err := writer.Write(t.Context(), opticalFleetSamples(tenant, lane)); err != nil {
			t.Fatal(err)
		}
	}
	f.server.WithTSDB(writer)
	seedInterfaceRoleMCPConsent(f)
	args := map[string]any{"limit": 50000}
	check := func(lane int, result nativeDeviceMetrics) {
		t.Helper()
		if len(result.Items) != 5632 || result.EffectiveLimit != 50000 || !result.MetricsRunning {
			t.Fatal("native optical result lost its complete admitted fleet", len(result.Items), result.EffectiveLimit)
		}
		seen := map[string]bool{}
		for _, item := range result.Items {
			want := -3.25 - float64(lane*1000) - map[string]float64{"": 0, "0": 1, "1": 2}[item.PhysicalChannel]
			if item.Value != want || item.IfIndex != "" || item.IfName != "" || seen[item.ID] {
				t.Fatal("native optical value crossed tenant/channel scope or became a port")
			}
			seen[item.ID] = true
		}
	}
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		for lane, tenant := range f.tenants {
			var result nativeDeviceMetrics
			call(tenant, "device_metrics", args, &result, true)
			check(lane, result)
			call(tenant, "device_metrics", map[string]any{"tenant_id": f.tenants[1-lane], "limit": 50000}, nil, false)
		}
	}
	cfg := &config.Config{AIRedactIPs: true, AIRedactHostnames: true, AIRedactPII: true}
	server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, f.server.pathStore, 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), f.server.aiSources())
	authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
	streams := map[string]*interfaceRoleStdioClient{}
	const wire = "2026-07-28"
	for lane, tenant := range f.tenants {
		streams[tenant] = openInterfaceRoleStdio(t, server, authenticator, f.tokens[tenant], wire)
		var result nativeDeviceMetrics
		streams[tenant].call(t, wire, "device_metrics", args, &result, true)
		check(lane, result)
	}
	a, b := f.tenants[0], f.tenants[1]
	writer.after = func() {
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, "DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='metrics.read'", a, f.roles[a])
			return err
		})
	}
	streams[a].call(t, wire, "device_metrics", args, nil, false)
	var sibling nativeDeviceMetrics
	streams[b].call(t, wire, "device_metrics", args, &sibling, true)
	check(1, sibling)
}
