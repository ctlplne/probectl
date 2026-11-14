// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type boundConfigReadProbe struct {
	*device.PostgresOpsStore
	calls int
	after func(int)
}

func (p *boundConfigReadProbe) ListConfigs(ctx context.Context, tenant string, filter device.OpsFilter) ([]device.ConfigVersion, error) {
	rows, err := p.PostgresOpsStore.ListConfigs(ctx, tenant, filter)
	p.calls++
	if p.after != nil {
		p.after(p.calls)
	}
	return rows, err
}

func TestDeviceConfigBoundReadRechecksCurrentScopeCredentialAndErasure(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	ops := device.NewPostgresOpsStore(f.pool)
	probe := &boundConfigReadProbe{PostgresOpsStore: ops}
	f.server.WithDeviceOps(probe)
	ids := map[string]string{}
	for _, tenant := range f.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		row, err := ops.ArchiveConfig(ctx, device.ConfigVersion{TenantID: tenant, Device: "shared-name", Source: "operator", Content: "hostname private-" + tenant, Binding: &device.ConfigArchiveBinding{ContextID: f.contextID, DeviceEntityID: f.routerID, AgentID: "role-snmp", SourceRef: "192.0.2.1"}})
		if err != nil {
			t.Fatal(err)
		}
		ids[tenant] = row.ID
	}
	a, b := f.tenants[0], f.tenants[1]
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(a))
	if _, err := ops.ArchiveConfig(ctx, device.ConfigVersion{TenantID: b, Device: "forged", Content: "hostname forged", Binding: &device.ConfigArchiveBinding{ContextID: f.contextID, DeviceEntityID: f.routerID, AgentID: "role-snmp", SourceRef: "192.0.2.1"}}); err == nil {
		t.Fatal("bound storage accepted another tenant through a caller tenant argument")
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	otherTenant := func(tenant string) string {
		if tenant == a {
			return b
		}
		return a
	}
	read := func(tenant string, want bool) {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, socket.URL+"/v1/device/configs", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		response, err := socket.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if want {
			if response.StatusCode != http.StatusOK || !strings.Contains(string(raw), "private-"+tenant) || strings.Contains(string(raw), "private-"+otherTenant(tenant)) {
				t.Fatal("bound read lost its own archive or crossed tenants", response.StatusCode)
			}
		} else if response.StatusCode == http.StatusOK || strings.Contains(string(raw), "private-") || strings.Contains(string(raw), "content_hash") {
			t.Fatal("changed archive authority published a body", response.StatusCode)
		}
	}
	read(a, true)
	read(b, true)
	for _, phase := range []int{1, 2} {
		probe.calls = 0
		probe.after = func(call int) {
			if call == phase {
				probe.after = nil
				f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
					_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='entities.read'`, a, f.roles[a])
					return err
				})
			}
		}
		read(a, false)
		read(b, true)
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], "entities.read")
		})
	}
	probe.calls = 0
	probe.after = func(call int) {
		if call == 1 {
			probe.after = nil
			f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `DELETE FROM device_configs WHERE tenant_id=$1 AND id=$2`, a, ids[a])
				return err
			})
		}
	}
	read(a, false)
	read(b, true)
	if _, err := ops.ArchiveConfig(tenancy.WithTenant(t.Context(), tenancy.ID(a)), device.ConfigVersion{TenantID: a, Device: "shared-name", Content: "hostname private-" + a, Binding: &device.ConfigArchiveBinding{ContextID: f.contextID, DeviceEntityID: f.routerID, AgentID: "role-snmp", SourceRef: "192.0.2.1"}}); err != nil {
		t.Fatal(err)
	}
	probe.calls = 0
	probe.after = func(call int) {
		if call == 2 {
			probe.after = nil
			if err := store.NewMCPTokens(f.pool).RevokeForUser(t.Context(), a, f.users[a]); err != nil {
				t.Fatal(err)
			}
		}
	}
	read(a, false)
	read(b, true)
	t.Log("real-integration: bound archive TLS/PG/RLS, exact tenant argument refusal, late context grant withdrawal at both reads, erasure and exact original bearer revocation with sibling survival; content is modeled operator input")
}
