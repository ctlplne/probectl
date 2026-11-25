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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/topology"
)

func TestCloudTopologyUsesOwnTenantSnapshotAndObservationClock(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	f.server.WithTopology(topology.NewMemoryStore())
	api := httptest.NewTLSServer(f.server.Handler())
	defer api.Close()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	const route = "/v1/topology"
	sources := []topology.CloudInventorySource{
		{Provider: "aws", Account: "111122223333", Location: "eu-west-1"},
		{Provider: "azure", Account: "f24a1602-a736-4f0a-9e9a-938ffcb17288", Location: "global"},
		{Provider: "gcp", Account: "example-owner", Location: "global"},
	}
	networkID := func(provider string, lane int) string { return fmt.Sprintf("%s-network-lane-%d", provider, lane) }
	for i, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], ai.PermTopologyRead); err != nil {
				return err
			}
			inventories := store.CloudTopologyInventories{}
			for _, source := range sources {
				id := networkID(source.Provider, i)
				inv := topology.CloudInventory{Source: source, ObservedAt: at, Resources: []topology.CloudInventoryResource{
					{ID: id, Type: "vpc", Kind: topology.CloudNetwork, CIDRs: []string{"10.0.0.0/16"}},
					{ID: "subnet-shared-name", Type: "subnet", Kind: topology.CloudSubnet, CIDRs: []string{"10.0.1.0/24"}},
				}, Links: []topology.CloudInventoryLink{{From: id, To: "subnet-shared-name", Kind: "cloud_contains"}}}
				if err := inventories.Save(ctx, sc, inv); err != nil {
					return err
				}
				inv.ObservedAt = at.Add(-time.Second)
				err := inventories.Save(ctx, sc, inv)
				if apiErr, ok := apierror.As(err); !ok || apiErr.Kind != apierror.KindConflict {
					t.Fatalf("an older result replaced the active source: %v", err)
				}
			}
			return nil
		})
	}
	for i, tenant := range f.tenants {
		var grants []auth.PermissionGrant
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM cloud_topology_inventories WHERE tenant_id=$1`, f.tenants[1-i]).Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				t.Fatal("cloud inventory table leaked the sibling's row through RLS")
			}
			var err error
			grants, err = (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[tenant])
			return err
		})
		cookie, err := f.server.sessions.Issue(t.Context(), auth.Session{TenantID: tenant, UserID: f.users[tenant],
			MFASatisfied: true, AuthorizationHash: auth.PermissionGrantFingerprint(grants)})
		if err != nil {
			t.Fatal(err)
		}
		wrongTenant, err := http.NewRequestWithContext(t.Context(), http.MethodGet, api.URL+route+"?include_cloud=true", nil)
		if err != nil {
			t.Fatal(err)
		}
		wrongTenant.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: cookie})
		wrongTenant.Header.Set("X-Probectl-Tenant", f.tenants[1-i])
		resp, err := api.Client().Do(wrongTenant)
		if err != nil {
			t.Fatal(err)
		}
		var denied map[string]json.RawMessage
		decodeErr := json.NewDecoder(resp.Body).Decode(&denied)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || decodeErr != nil || denied["nodes"] != nil || denied["edges"] != nil {
			t.Fatalf("stale topology tenant assertion returned status %d, want a data-free 403", resp.StatusCode)
		}
		read := func(path string) (cloud bool, nodes []topology.VizNode, edges []topology.VizEdge) {
			t.Helper()
			var out struct {
				Cloud bool               `json:"cloud_latest_only"`
				Nodes []topology.VizNode `json:"nodes"`
				Edges []topology.VizEdge `json:"edges"`
			}
			body := callSeasonalAPI(t, api, f.tokens[tenant], http.MethodGet, path, nil, http.StatusOK)
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatal(err)
			}
			return out.Cloud, out.Nodes, out.Edges
		}
		if cloud, nodes, edges := read(route); cloud || len(nodes) != 0 || len(edges) != 0 {
			t.Fatal("cloud inventory was added to the observed dependency graph")
		}
		cloud, nodes, edges := read(route + "?include_cloud=true")
		if !cloud || len(nodes) != 2*len(sources) || len(edges) != len(sources) {
			t.Fatalf("tenant %d saw incomplete or foreign cloud inventory: %+v %+v", i, nodes, edges)
		}
		for j, source := range sources {
			network, subnet := nodes[2*j], nodes[2*j+1]
			if network.Label != networkID(source.Provider, i) || network.Cloud == nil ||
				network.Cloud.CloudInventorySource != source || !network.Cloud.ObservedAt.Equal(at) ||
				edges[j].From != network.ID || edges[j].To != subnet.ID {
				t.Fatalf("tenant %d saw a different project, resource or clock: %+v %+v", i, network, edges[j])
			}
		}
		if _, nodes, _ := read(route + "?include_cloud=true&at=" + url.QueryEscape(at.Add(-time.Second).Format(time.RFC3339))); len(nodes) != 0 {
			t.Fatal("cloud inventory was projected before the source observation")
		}
		if _, nodes, _ := read(route + "?include_cloud=true&at=" + url.QueryEscape(at.Add(2*time.Hour).Format(time.RFC3339))); len(nodes) != 0 {
			t.Fatal("stale cloud resources were projected as current")
		}
	}
}
