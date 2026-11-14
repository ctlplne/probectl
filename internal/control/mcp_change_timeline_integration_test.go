// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"testing"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestChangeTimelineNativePagesKeepCompleteOriginalsTenantAndSourceAuthority(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	originals := map[string]change.Event{}
	for lane, tenant := range f.tenants {
		seedInternetRoutingView(t, f, tenant, uint32(64497+lane))
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permChangeRead, "events.read", "ai.query"} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			events, err := (store.ChangeEvents{}).List(ctx, sc, 200)
			if err != nil {
				return err
			}
			if len(events) != 1 || events[0].Routing == nil {
				t.Fatal("missing original route")
			}
			originals[tenant] = events[0]
			_, err = sc.Q.Exec(ctx, `INSERT INTO change_events(tenant_id,source,kind,title,occurred_at)
 SELECT $1,'generic','deploy','fixture deployment '||n,$2 FROM generate_series(1,500) n`, tenant, events[0].OccurredAt)
			return err
		})
	}
	seedInterfaceRoleMCPConsent(f)
	type page struct {
		Items      []change.Event `json:"items"`
		NextCursor string         `json:"next_cursor"`
		Truncated  bool           `json:"truncated"`
	}
	checkPages := func(tenant string, call func(any, *page)) {
		t.Helper()
		seen := map[string]bool{}
		cursor := ""
		found := false
		for pages := 0; ; pages++ {
			var result page
			call(map[string]any{"limit": 137, "cursor": cursor}, &result)
			if len(result.Items) == 0 {
				t.Fatal("native continuation returned an empty prefix")
			}
			for _, item := range result.Items {
				if item.TenantID != tenant || seen[item.ID] {
					t.Fatal("native paging borrowed or repeated an original")
				}
				seen[item.ID] = true
				if item.Routing != nil {
					if item.ID != originals[tenant].ID || *item.Routing != *originals[tenant].Routing {
						t.Fatal("native full redaction changed an exact original")
					}
					found = true
				}
			}
			if !result.Truncated {
				if result.NextCursor != "" {
					t.Fatal("exhausted history retained a cursor")
				}
				break
			}
			if result.NextCursor == "" || result.NextCursor == cursor || pages > 500 {
				t.Fatal("native continuation was lost or never exhausted")
			}
			cursor = result.NextCursor
		}
		if len(seen) != 501 || !found {
			t.Fatal("native page size became a population limit", len(seen), found)
		}
	}
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		for lane, tenant := range f.tenants {
			checkPages(tenant, func(args any, result *page) { call(tenant, "changes_list", args, result, true) })
			call(tenant, "changes_list", map[string]any{"tenant_id": f.tenants[1-lane]}, nil, false)
		}
	}
	cfg := &config.Config{AIRedactIPs: true, AIRedactHostnames: true, AIRedactPII: true}
	server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, f.server.pathStore, 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), f.server.aiSources())
	authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
	streams := map[string]*interfaceRoleStdioClient{}
	const wire = "2026-07-28"
	for _, tenant := range f.tenants {
		stream := openInterfaceRoleStdio(t, server, authenticator, f.tokens[tenant], wire)
		streams[tenant] = stream
		checkPages(tenant, func(args any, result *page) { stream.call(t, wire, "changes_list", args, result, true) })
	}
	a, b := f.tenants[0], f.tenants[1]
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_source_contexts WHERE tenant_id=$1 AND agent_id='role-listener' AND source_kind='bmp_peer' AND source_ref='role-router'`, a)
		return err
	})
	streams[a].call(t, wire, "changes_list", map[string]any{"limit": 1000}, nil, false)
	checkPages(b, func(args any, result *page) { streams[b].call(t, wire, "changes_list", args, result, true) })
}
