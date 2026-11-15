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
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

// Real app-role PostgreSQL/FORCE-RLS, sessions and HTTPS SDK. The original
// publisher-format input is QA-authored, not downloaded publisher evidence.
func TestPublishedServiceRangeAPIKeepsTwoCurrentTenantReadersAndOfflineStartup(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	fetched := time.Now().UTC().Add(-time.Minute)
	document := map[string]any{"version": 1, "sources": []any{map[string]any{
		"publisher": "aws", "complete": true, "fetched_at": fetched,
		"data": map[string]any{"syncToken": "qa-original", "createDate": fetched.Add(-time.Hour).Format("2006-01-02-15-04-05"),
			"prefixes": []any{map[string]string{"ip_prefix": "192.0.2.0/24", "service": "S3", "region": "us-east-1"}}, "ipv6_prefixes": []any{}},
	}}}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "complete.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{FlowEnrichServiceFile: path, FlowEnrichServiceMaxAge: time.Hour, FlowEnrichServiceMemoryBytes: 16 << 20, FlowEnrichCacheMax: 16}
	en, enabled := BuildEnrichment(cfg, statusQuietLog())
	if !enabled || en == nil || len(en.Status()) != 1 {
		t.Fatal("offline source was not wired")
	}
	// The file disappears after ONE startup import; both tenants can only use
	// the shared immutable copy. There is no publisher network fallback.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	f.server.WithOpenDataStatus(en, nil, nil)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	clients := map[string]*sdk.Client{}
	address := "192.0.2.7"
	var first map[string]any
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, scope tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, scope, f.roles[tenant], "flow.read")
		})
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		clients[tenant] = client
		value, err := client.GetOpenDataEnrichment(t.Context(), sdk.GetOpenDataEnrichmentRequest{Ip: &address})
		if err != nil {
			t.Fatal("current tenant cannot read public source", err)
		}
		services, ok := value["services"].([]any)
		if !ok || len(services) != 1 {
			t.Fatal("complete source missing", value)
		}
		status := services[0].(map[string]any)
		matches := status["matches"].([]any)
		if status["publisher"] != "aws" || status["status"] != "matched" || len(matches) != 1 || matches[0].(map[string]any)["service"] != "S3" || status["fetched_at"] != fetched.Format(time.RFC3339Nano) {
			t.Fatal("lost original labels or clock", status)
		}
		if first != nil && !reflect.DeepEqual(first, value) {
			t.Fatal("public cache changed between tenant readers", first, value)
		}
		first = value
	}
	primary, sibling := f.tenants[0], f.tenants[1]
	foreign := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[primary]), sdk.WithTenant(sibling))
	if _, err := foreign.GetOpenDataEnrichment(t.Context(), sdk.GetOpenDataEnrichmentRequest{Ip: &address}); err == nil {
		t.Fatal("shared public data bypassed authenticated tenant boundary")
	}
	f.in(primary, func(ctx context.Context, scope tenancy.Scope) error {
		_, err := scope.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='flow.read'`, primary, f.roles[primary])
		return err
	})
	if _, err := clients[primary].GetOpenDataEnrichment(t.Context(), sdk.GetOpenDataEnrichmentRequest{Ip: &address}); err == nil {
		t.Fatal("cached source bypassed current user permission withdrawal")
	}
	if _, err := clients[sibling].GetOpenDataEnrichment(t.Context(), sdk.GetOpenDataEnrichmentRequest{Ip: &address}); err != nil {
		t.Fatal("sibling lost its current source access", err)
	}
	missing, ok := BuildEnrichment(cfg, statusQuietLog())
	if !ok || missing == nil || missing.Status()[0].Health.Status != "unavailable" {
		t.Fatal("missing offline file disappeared or enabled network fallback")
	}
	value, err := missing.Enrich(t.Context(), address)
	if err != nil || len(value.Services) != 1 || value.Services[0].Status != "unavailable" || len(value.Services[0].Matches) != 0 {
		t.Fatal("missing source did not degrade to visible unknown", value, err)
	}
}
