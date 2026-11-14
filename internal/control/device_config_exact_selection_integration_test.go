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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestConfigExactSelectionReadsOldOriginalPairAndRefusesForeignErasedSources(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	ops := device.NewPostgresOpsStore(f.pool)
	f.server.WithDeviceOps(ops)
	originals := map[string][]device.ConfigVersion{}
	for _, tenant := range f.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		for _, value := range []string{"original-before", "original-after"} {
			row, err := ops.ArchiveConfig(ctx, device.ConfigVersion{TenantID: tenant, Device: "shared-router", Content: "hostname " + value + "\nenable secret private-fixture-word", Binding: &device.ConfigArchiveBinding{ContextID: f.contextID, DeviceEntityID: f.routerID, AgentID: "role-snmp", SourceRef: "192.0.2.1"}})
			if err != nil {
				t.Fatal(err)
			}
			originals[tenant] = append(originals[tenant], row)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO device_configs(tenant_id,device,version,content,content_hash,previous_hash,drifted,archived_at)
 SELECT $1,'newer-other-device',n,'newer configuration',lpad(to_hex(n),64,'0'),'',false,clock_timestamp()+n*interval '1 microsecond' FROM generate_series(1,1002) n`, tenant)
			return err
		})
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	read := func(tenant string, ids []string) (int, []byte) {
		t.Helper()
		query := url.Values{"limit": {"2"}, "id": ids}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, socket.URL+"/v1/device/configs?"+query.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		response, err := socket.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, body
	}
	for lane, tenant := range f.tenants {
		own := originals[tenant]
		ids := []string{own[0].ID, own[1].ID}
		code, body := read(tenant, ids)
		var result struct{ Items []device.ConfigVersion }
		if code != http.StatusOK || json.Unmarshal(body, &result) != nil || len(result.Items) != 2 || strings.Contains(string(body), "private-fixture-word") {
			t.Fatal("exact old pair was shortened, unavailable or unredacted", code, string(body))
		}
		byID := map[string]device.ConfigVersion{}
		for _, row := range result.Items {
			byID[row.ID] = row
		}
		for _, row := range own {
			if byID[row.ID].ContentHash != row.ContentHash || byID[row.ID].Content != row.Content || byID[row.ID].TenantID != tenant {
				t.Fatal("exact selection substituted another original")
			}
		}
		foreign := originals[f.tenants[1-lane]][0].ID
		if code, body := read(tenant, []string{own[0].ID, foreign}); code != http.StatusNotFound || strings.Contains(string(body), own[0].ContentHash) {
			t.Fatal("mixed foreign pair returned a partial source", code)
		}
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[1-lane]))
		if rows, err := ops.ListConfigs(ctx, tenant, device.OpsFilter{Limit: 2, ConfigIDs: ids}); err != entity.ErrScopeMismatch || rows != nil {
			t.Fatal("foreign context replaced the requested storage scope", err)
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE device_configs SET content='' WHERE tenant_id=$1 AND id=$2`, a, originals[a][0].ID)
		return err
	})
	if code, _ := read(a, []string{originals[a][0].ID, originals[a][1].ID}); code != http.StatusNotFound {
		t.Fatal("erased predecessor was revived", code)
	}
	if code, _ := read(b, []string{originals[b][0].ID, originals[b][1].ID}); code != http.StatusOK {
		t.Fatal("erasure damaged sibling originals", code)
	}
}
