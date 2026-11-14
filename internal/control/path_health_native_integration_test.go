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
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestPathHealthNativeTLSAndPersistentStdioKeepOriginalsAndCurrentAuthority(t *testing.T) {
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(wire, func(t *testing.T) { provePathHealthNative(t, wire) })
	}
}

func provePathHealthNative(t *testing.T, wire string) {
	t.Helper()
	proof := newPathHealthAPIFixture(t)
	f := proof.fixture
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], "ai.query")
		})
	}
	seedInterfaceRoleMCPConsent(f)
	call := interfaceRoleNativeTLSCaller(t, f, wire)
	args := func(tenant string) map[string]any {
		value := map[string]any{"test_id": proof.tests[tenant]}
		for key, items := range proof.windows[tenant] {
			if key != "include_health" {
				value[key] = items[0]
			}
		}
		return value
	}
	a, b := f.tenants[0], f.tenants[1]
	// The expected public projection is independently read through verified
	// TLS REST. Both native framing revisions must retain every counter word,
	// receipt, clock, exact rational and source assumption after full redaction.
	rest := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(rest.Close)
	originals := map[string]pathHealthResult{}
	for _, tenant := range f.tenants {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rest.URL+"/v1/tests/"+proof.tests[tenant]+"/path/entities?"+proof.windows[tenant].Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		response, err := rest.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatal("native original REST prerequisite failed", response.StatusCode, err)
		}
		var value pathHealthResult
		if err := json.Unmarshal(raw, &value); err != nil || len(value.Items) != 2 || value.Items[0].Health == nil {
			t.Fatal("original health fixture incomplete", err)
		}
		originals[tenant] = value
	}
	check := func(tenant string, value pathHealthResult) {
		t.Helper()
		want := originals[tenant]
		if value.TestID != want.TestID || value.ContextID != f.contextID || len(value.Items) != len(want.Items) || value.Items[0].Health == nil || value.Items[1].Health == nil {
			t.Fatal("native path health lost the owned complete path")
		}
		health := value.Items[0].Health
		if health.ContextID != f.contextID || health.InterfaceID != f.interfaceID || health.DeviceID != f.routerID || health.Status != "observed_originals" || value.Items[1].Health.Status != "identity_unresolved" || !reflect.DeepEqual(health.Counters, want.Items[0].Health.Counters) {
			for i, counter := range health.Counters {
				if i >= len(want.Items[0].Health.Counters) {
					break
				}
				left, right := reflect.ValueOf(counter), reflect.ValueOf(want.Items[0].Health.Counters[i])
				for field := range left.NumField() {
					if !reflect.DeepEqual(left.Field(field).Interface(), right.Field(field).Interface()) {
						t.Log("native original counter difference", i, left.Type().Field(field).Name)
					}
				}
			}
			t.Fatal("native path health changed original words, current source, explicit absence or citations")
		}
		if health.SourceRef == "192.0.2.1" || value.Items[0].IP == "10.42.0.2" {
			t.Fatal("native health source text bypassed shipped IP redaction")
		}
	}
	for _, tenant := range f.tenants {
		var value pathHealthResult
		call(tenant, "path_interface_health", args(tenant), &value, true)
		check(tenant, value)
	}
	foreign := args(a)
	foreign["test_id"] = proof.tests[b]
	call(a, "path_interface_health", foreign, nil, false)
	for _, key := range []string{"tenant_id", "device_id", "if_index", "capture_key"} {
		forged := args(a)
		forged[key] = proof.tests[b]
		call(a, "path_interface_health", forged, nil, false)
	}
	cfg := &config.Config{AIRedactIPs: true, AIRedactHostnames: true, AIRedactPII: true}
	server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, f.server.pathStore, 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), AISources{NativeFlow: f.server})
	authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
	streams := map[string]*interfaceRoleStdioClient{}
	for _, tenant := range f.tenants {
		streams[tenant] = openInterfaceRoleStdio(t, server, authenticator, f.tokens[tenant], wire)
		var value pathHealthResult
		streams[tenant].call(t, wire, "path_interface_health", args(tenant), &value, true)
		check(tenant, value)
	}
	// Withdraw a role after the actual original-history read. The existing
	// authenticated stream must refuse it without re-handshaking or widening
	// its bearer ceiling; the sibling's original result must survive.
	proof.history.after = func() {
		proof.history.after = nil
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='metrics.read'`, a, f.roles[a])
			return err
		})
	}
	streams[a].call(t, wire, "path_interface_health", args(a), nil, false)
	var sibling pathHealthResult
	streams[b].call(t, wire, "path_interface_health", args(b), &sibling, true)
	check(b, sibling)
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], "metrics.read")
	})
	var restored pathHealthResult
	streams[a].call(t, wire, "path_interface_health", args(a), &restored, true)
	check(a, restored)
	t.Log("real-integration: verified TLS REST/native HTTP and authenticated persistent stdio for both framing revisions, PG/RLS/current credential and role grants, full redaction and original counter metadata; SNMP/path/history modeled; physical FRR/SNMP/RCA/lifecycle remain owed")
}
