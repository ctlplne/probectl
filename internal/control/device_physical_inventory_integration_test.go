// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func TestPhysicalInventoryReadKeepsObservationAndCurrentTenantAuthority(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	source := entity.SourceKey{AgentID: "role-snmp", Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"}
	const route = "/v1/device/physical-inventory"
	selection := url.Values{"context_id": {f.contextID}, "device_entity_id": {f.routerID},
		"agent_id": {source.AgentID}, "source_ref": {source.SourceRef}}
	serials := [2]string{"example-tenant-alpha", "example-tenant-beta"}
	originalIDs := seedPhysicalInventoryObservations(t, f, source, serials)
	for lane, tenant := range f.tenants {
		payload := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, route+"?"+selection.Encode(), nil, http.StatusOK)
		var page devicePhysicalInventoryPage
		if err := json.Unmarshal(payload, &page); err != nil || !page.Available || page.Methodology != entity.SNMPPhysicalInventorySource ||
			page.ObservationID != originalIDs[lane] ||
			len(page.Items) != physicalInventoryPageSize || page.Items[0].Serial != serials[lane] ||
			page.NextIndex != physicalInventoryPageSize || page.Items[0].Parent == nil || *page.Items[0].Parent != 0 ||
			page.Items[1].Parent != nil || page.Items[0].References.VulnerabilityCoverage != "unavailable" ||
			bytes.Contains(payload, []byte(serials[1-lane])) {
			t.Fatal("inventory response lost original presence, authority or source coverage", page.ObservationID, err)
		}
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		request := sdk.GetDevicePhysicalInventoryRequest{ContextId: &f.contextID, DeviceEntityId: &f.routerID,
			AgentId: &source.AgentID, SourceRef: &source.SourceRef}
		fromSDK, err := client.GetDevicePhysicalInventory(t.Context(), request)
		if err != nil || fromSDK == nil || fromSDK.ObservationId != page.ObservationID || len(fromSDK.Items) != len(page.Items) ||
			fromSDK.Items[0].Parent == nil || *fromSDK.Items[0].Parent != 0 || fromSDK.Items[1].Parent != nil {
			t.Fatal("generated SDK lost original parent presence or source identity", err)
		}
		selection.Set("observation_id", originalIDs[lane])
		selection.Set("after_index", strconv.FormatUint(uint64(page.NextIndex), 10))
		payload = callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, route+"?"+selection.Encode(), nil, http.StatusOK)
		page = devicePhysicalInventoryPage{}
		if err := json.Unmarshal(payload, &page); err != nil || len(page.Items) != 1 ||
			page.Items[0].Index != physicalInventoryPageSize+1 || page.Items[0].Serial != serials[lane] || page.NextIndex != 0 {
			t.Fatal("continuation lost the remaining original component", err)
		}
		selection.Set("observation_id", originalIDs[1-lane])
		callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, route+"?"+selection.Encode(), nil, http.StatusConflict)
		selection.Del("observation_id")
		selection.Del("after_index")
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var own, other int
			err := sc.Q.QueryRow(ctx, `SELECT count(*) FILTER (WHERE tenant_id=$1 AND data->>'facet'='sensitive_read'
 AND actor=(SELECT email FROM users WHERE tenant_id=$1 AND id=$2)), count(*) FILTER (WHERE tenant_id<>$1)
 FROM audit_events
 WHERE action='access.read.device.physical_inventory' AND target=$3`, tenant, f.users[tenant], route).Scan(&own, &other)
			if err == nil && (own != 4 || other != 0) {
				t.Fatalf("inventory access audit rows: got %d for the actor and %d for other tenants", own, other)
			}
			return err
		})
	}
	verifyPhysicalInventoryAlternateClients(t, f, socket, selection, serials, originalIDs)
	tenant := f.tenants[0]
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		role, err := (store.Roles{}).Create(ctx, sc, "inventory-metrics-only", "Metrics only", "No canonical device read")
		if err != nil {
			return err
		}
		if err := (store.Roles{}).AddPermission(ctx, sc, role.ID, "metrics.read"); err != nil {
			return err
		}
		if err := (store.RoleBindings{}).Bind(ctx, sc, "user", f.users[tenant], role.ID); err != nil {
			return err
		}
		return (store.RoleBindings{}).Unbind(ctx, sc, "user", f.users[tenant], f.roles[tenant])
	})
	payload := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, route+"?"+selection.Encode(), nil, http.StatusForbidden)
	if bytes.Contains(payload, []byte(serials[0])) {
		t.Fatal("forbidden response exposed original hardware evidence")
	}
}

func seedPhysicalInventoryObservations(t *testing.T, f *roleExplanationAPIFixture,
	source entity.SourceKey, serials [2]string) [2]string {
	t.Helper()
	var originalIDs [2]string
	originalParent := uint32(0)
	for lane, tenant := range f.tenants {
		claimID := gouuid.NewString()
		components := make([]entity.SNMPPhysicalComponent, 0, physicalInventoryPageSize+1)
		for index := uint32(1); index <= physicalInventoryPageSize+1; index++ {
			components = append(components, entity.SNMPPhysicalComponent{Index: index, Class: 3,
				Manufacturer: "Example Networks", Model: "same-chassis", Serial: serials[lane]})
		}
		components[0].Parent = &originalParent
		obs := entity.Observation{ID: claimID, Source: source, SourceRef: entity.SNMPPhysicalInventorySource,
			Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: source.SourceRef}, ObservedAt: f.observedAt(tenant),
			SNMPPhysicalInventory: &entity.SNMPPhysicalInventory{Version: 1, Available: true, Components: components}}
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		accepted, unresolved, err := writeEntityEvidenceBatchForTest(ctx, store.NewEntityRegistry(f.pool), source.AgentID,
			f.serials[tenant+source.AgentID], []entity.Observation{obs})
		if err != nil || accepted != 1 || unresolved != 0 {
			t.Fatal("authorized inventory write was refused", accepted, unresolved, err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT id::text FROM entity_evidence WHERE tenant_id=$1 AND observation_id=$2`,
				tenant, claimID).Scan(&originalIDs[lane])
		})
		if originalIDs[lane] == claimID {
			t.Fatal("inventory pagination must use a server-created identity")
		}
	}
	return originalIDs
}

func verifyPhysicalInventoryAlternateClients(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server,
	selection url.Values, serials, observationIDs [2]string) {
	t.Helper()
	ca := filepath.Join(t.TempDir(), "physical-inventory-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	seedInterfaceRoleMCPConsent(f)
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], "ai.query")
		})
		getenv := func(key string) string {
			return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
		}
		args := []string{"--json", "device", "physical-inventory"}
		for _, name := range []string{"context_id", "device_entity_id", "agent_id", "source_ref"} {
			args = append(args, "--query", name+"="+selection.Get(name))
		}
		var stdout, stderr bytes.Buffer
		if result := cli.RunWithStdin(args, getenv, bytes.NewReader(nil), &stdout, &stderr); result != 0 ||
			!bytes.Contains(stdout.Bytes(), []byte(serials[lane])) || bytes.Contains(stdout.Bytes(), []byte(serials[1-lane])) {
			t.Fatal("CLI failed to serve the exact tenant inventory", result, stderr.String())
		}
	}
	for _, revision := range []string{"2026-07-28", "2025-11-25"} {
		call := interfaceRoleNativeTLSCaller(t, f, revision)
		for lane, tenant := range f.tenants {
			args := map[string]any{"context_id": selection.Get("context_id"), "device_entity_id": selection.Get("device_entity_id"),
				"agent_id": selection.Get("agent_id"), "source_ref": selection.Get("source_ref")}
			var page devicePhysicalInventoryPage
			call(tenant, "device_physical_inventory", args, &page, true)
			if page.ObservationID != observationIDs[lane] || len(page.Items) != physicalInventoryPageSize ||
				page.Items[0].Serial != serials[lane] || page.NextIndex != physicalInventoryPageSize {
				t.Fatal("native inventory changed the original scope or observation", revision, page.ObservationID)
			}
			args["observation_id"], args["after_index"] = page.ObservationID, page.NextIndex
			page = devicePhysicalInventoryPage{}
			call(tenant, "device_physical_inventory", args, &page, true)
			if page.ObservationID != observationIDs[lane] || len(page.Items) != 1 || page.Items[0].Serial != serials[lane] {
				t.Fatal("native continuation lost the selected observation", revision, page.ObservationID)
			}
			args["tenant_id"] = f.tenants[1-lane]
			call(tenant, "device_physical_inventory", args, nil, false)
		}
	}
}
