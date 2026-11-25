// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package topology

import (
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/secrets"
)

func TestAzureCloudInventoryPinsContinuationAndResourceIdentity(t *testing.T) {
	const subscription = "11111111-2222-4333-8444-555555555555"
	const neighbor = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	const root = "/subscriptions/" + subscription
	const networkList = root + "/providers/Microsoft.Network/virtualNetworks"
	const natList = root + "/providers/Microsoft.Network/natGateways"
	const owner = root + "/resourceGroups/Inventory-RG/providers/Microsoft.Network/"
	const edge = owner + "virtualNetworks/Edge"
	const core = owner + "virtualNetworks/Core"
	const subnet = edge + "/subnets/GatewaySubnet"
	const nat = owner + "natGateways/Egress"
	const gateway = owner + "virtualNetworkGateways/Vpn"
	const foreignCore = "/subscriptions/" + neighbor + "/resourceGroups/Inventory-RG/providers/Microsoft.Network/virtualNetworks/Core"
	const cursor = "opaque/+=="
	const continued = "https://management.azure.com" + networkList + "?api-version=2025-05-01&%24skiptoken=opaque%2F%2B%3D%3D"

	resolver, err := secrets.NewResolver(time.Minute, secrets.NewEnvSource(func(name string) string {
		if name == "ARM_TOPOLOGY_READER" {
			return "fixture.azure.read-token"
		}
		return ""
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resolver.Close)
	config := AzureInventoryConfig{Subscription: subscription, CredentialRef: "env:ARM_TOPOLOGY_READER"}
	next := continued
	gatewayID, gatewayReads, requestCount := gateway, 0, 0
	client := &http.Client{Transport: cloudInventoryHTTPFixture(func(req *http.Request) (*http.Response, error) {
		requestCount++
		params := req.URL.Query()
		if req.Method != http.MethodGet || req.URL.Scheme != "https" || req.URL.Host != "management.azure.com" ||
			req.Header.Get("Authorization") != "Bearer fixture.azure.read-token" {
			return nil, fmt.Errorf("inventory request left the Azure Resource Manager read boundary")
		}
		version := "2025-05-01"
		if req.URL.Path == root+"/resources" {
			version = "2021-04-01"
		}
		if params.Get("api-version") != version {
			return nil, fmt.Errorf("unexpected Azure API version")
		}
		var body string
		switch req.URL.Path {
		case networkList:
			switch params.Get("$skiptoken") {
			case "":
				body = fmt.Sprintf(`{"value":[{"id":%q,"properties":{
				 "addressSpace":{"addressPrefixes":["10.0.0.0/16","2001:db8::/48"]},
				 "subnets":[{"id":%q,"properties":{"addressPrefix":"10.0.1.0/24","addressPrefixes":["2001:db8:1::/64"],"natGateway":{"id":%q}}}],
				 "virtualNetworkPeerings":[
				   {"id":%q,"properties":{"remoteVirtualNetwork":{"id":%q},"peeringState":"Connected"}},
				   {"id":%q,"properties":{"remoteVirtualNetwork":{"id":%q},"peeringState":"Initiated"}}]
				 }}],"nextLink":%q}`, edge, subnet, strings.ToUpper(nat),
					edge+"/virtualNetworkPeerings/Local", strings.ToUpper(core),
					edge+"/virtualNetworkPeerings/External", foreignCore, next)
			case cursor:
				body = fmt.Sprintf(`{"value":[{"id":%q,"properties":{"addressSpace":{"addressPrefixes":["10.0.0.0/16"]}}}]}`, core)
			}
		case natList:
			body = fmt.Sprintf(`{"value":[{"id":%q,"properties":{"subnets":[{"id":%q}],"provisioningState":"Succeeded"}}]}`, nat, subnet)
		case root + "/resources":
			if params.Get("$filter") != "resourceType eq 'Microsoft.Network/virtualNetworkGateways'" {
				return nil, fmt.Errorf("gateway discovery dropped the type filter")
			}
			body = fmt.Sprintf(`{"value":[{"id":%q,"type":"Microsoft.Network/virtualNetworkGateways"}]}`, gatewayID)
		case gateway:
			gatewayReads++
			body = fmt.Sprintf(`{"id":%q,"properties":{"gatewayType":"Vpn","provisioningState":"Succeeded",
			 "ipConfigurations":[{"properties":{"subnet":{"id":%q}}}]}}`, strings.ToLower(gateway), strings.ToUpper(subnet))
		}
		if body == "" {
			return nil, fmt.Errorf("an unexpected Azure endpoint was called")
		}
		return &http.Response{StatusCode: http.StatusOK, ContentLength: int64(len(body)), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	result, err := discoverAzureCloudInventory(t.Context(), client, config, resolver)
	if err != nil || result.Source != (CloudInventorySource{Provider: "azure", Account: subscription, Location: "global"}) ||
		len(result.Resources) != 7 || len(result.Links) != 6 || requestCount != 5 || gatewayReads != 1 {
		t.Fatalf("incomplete Azure inventory: %+v requests=%d gateway reads=%d error=%v", result, requestCount, gatewayReads, err)
	}
	external := strings.ToLower(edge + "/virtualNetworkPeerings/External")
	local := strings.ToLower(edge + "/virtualNetworkPeerings/Local")
	for _, resource := range result.Resources {
		switch resource.ID {
		case external:
			if !resource.External || resource.State != "Initiated" {
				t.Fatal("the foreign side of the Azure peering appeared local")
			}
		case strings.ToLower(subnet):
			if !slices.Equal(resource.CIDRs, []string{"10.0.1.0/24", "2001:db8:1::/64"}) {
				t.Fatal("Azure IPv4 or IPv6 subnet prefix was lost", resource.CIDRs)
			}
		}
	}
	if !slices.Contains(result.Links, CloudInventoryLink{From: strings.ToLower(core), To: local, Kind: "cloud_peering_accepter"}) ||
		slices.Contains(result.Links, CloudInventoryLink{From: strings.ToLower(core), To: external, Kind: "cloud_peering_accepter"}) ||
		!slices.Contains(result.Links, CloudInventoryLink{From: strings.ToLower(subnet), To: strings.ToLower(gateway), Kind: "cloud_attachment"}) {
		t.Fatal("Azure relationships were joined by name instead of full resource identity", result.Links)
	}
	for _, bad := range []string{
		strings.Replace(continued, "management.azure.com", "unexpected.example", 1),
		strings.Replace(continued, subscription, neighbor, 1),
		strings.Replace(continued, "/virtualNetworks?", "/natGateways?", 1),
		continued + "&api-version=2025-05-01",
	} {
		next, requestCount = bad, 0
		if inventory, err := discoverAzureCloudInventory(t.Context(), client, config, resolver); err == nil || len(inventory.Resources) != 0 || requestCount != 1 {
			t.Fatal("an invalid continuation caused another request or yielded a partial snapshot", err)
		}
	}
	next, gatewayID, gatewayReads = continued, strings.Replace(gateway, subscription, neighbor, 1), 0
	if inventory, err := discoverAzureCloudInventory(t.Context(), client, config, resolver); err == nil || len(inventory.Resources) != 0 || gatewayReads != 0 {
		t.Fatal("a foreign gateway was fetched or yielded a partial replacement", err)
	}
}
