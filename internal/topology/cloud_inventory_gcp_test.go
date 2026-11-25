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

func TestGCPCloudInventoryKeepsReadsAndPeeringsInTheSelectedProject(t *testing.T) {
	const project = "example-owner"
	const base = "/compute/v1/projects/" + project + "/"
	const first = "projects/" + project + "/global/networks/local-a"
	const second = "projects/" + project + "/global/networks/local-b"
	const subnet = "projects/" + project + "/regions/europe-west1/subnetworks/subnet-a"
	const cursor = "fixture/+=="
	const foreign = "projects/other-owner/global/networks/local-b"
	resolver, err := secrets.NewResolver(time.Minute, secrets.NewEnvSource(func(name string) string {
		if name == "CLOUD_INVENTORY_READER" {
			return "fixture-read-token"
		}
		return ""
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resolver.Close)
	config := GCPInventoryConfig{Project: project, CredentialRef: "env:CLOUD_INVENTORY_READER"}
	requests := 0
	partial, foreignNetwork, wrongListKind := false, false, false
	client := &http.Client{Transport: cloudInventoryHTTPFixture(func(req *http.Request) (*http.Response, error) {
		requests++
		method, scoped := strings.CutPrefix(req.URL.Path, base)
		params := req.URL.Query()
		if req.URL.Scheme != "https" || req.URL.Host != "compute.googleapis.com" || req.Method != http.MethodGet || !scoped ||
			req.Header.Get("Authorization") != "Bearer fixture-read-token" || params.Get("maxResults") != "100" ||
			(strings.HasPrefix(method, "aggregated/") && params.Get("returnPartialSuccess") != "false") {
			return nil, fmt.Errorf("unscoped Compute Engine request")
		}
		var response string
		switch method {
		case "global/networks":
			switch params.Get("pageToken") {
			case "":
				response = `{"kind":"compute#networkList","items":[{"selfLink":"https://www.googleapis.com/compute/v1/` + first + `","IPv4Range":"10.0.0.0/16","peerings":[` +
					`{"name":"local-peer","network":"global/networks/local-b","state":"ACTIVE"},` +
					`{"name":"foreign-peer","network":"` + foreign + `","state":"ACTIVE"}]}],"nextPageToken":"` + cursor + `"}`
			case cursor:
				id := second
				if foreignNetwork {
					id = foreign
				}
				response = `{"kind":"compute#networkList","items":[{"selfLink":"` + id + `","IPv4Range":"10.0.0.0/16"}]}`
			}
		case "aggregated/subnetworks":
			response = `{"kind":"compute#subnetworkAggregatedList","items":{` +
				`"regions/europe-west1":{"subnetworks":[{"selfLink":"` + subnet + `","network":"` + first +
				`","ipCidrRange":"10.0.1.0/24","internalIpv6Prefix":"2001:db8:1::/64","secondaryIpRanges":[{"ipCidrRange":"10.128.0.0/20"}]}]},` +
				`"regions/us-west1":{"warning":{"code":"NO_RESULTS_ON_PAGE"}}}}`
		case "aggregated/vpnGateways":
			response = `{"kind":"compute#vpnGatewayAggregatedList","items":{"regions/europe-west1":{"vpnGateways":[{"selfLink":"projects/` + project +
				`/regions/europe-west1/vpnGateways/gateway-a","network":"` + first + `"}]}}}`
		case "aggregated/targetVpnGateways":
			response = `{"kind":"compute#targetVpnGatewayAggregatedList","items":{"regions/europe-west1":{"targetVpnGateways":[{"selfLink":"projects/` + project +
				`/regions/europe-west1/targetVpnGateways/classic-b","network":"` + second + `"}]}}}`
		case "aggregated/routers":
			switch {
			case partial:
				response = `{"kind":"compute#routerAggregatedList","unreachables":["regions/europe-west1"]}`
			case wrongListKind:
				response = `{"kind":"compute#instanceAggregatedList","items":{}}`
			default:
				response = `{"kind":"compute#routerAggregatedList","items":{"regions/europe-west1":{"routers":[{"selfLink":"projects/` + project +
					`/regions/europe-west1/routers/router-a","network":"` + first + `","nats":[{"name":"nat-a"}]}]}}}`
			}
		case "global/routes":
			response = `{"kind":"compute#routeList","items":[{"selfLink":"projects/` + project + `/global/routes/internet-route-a","network":"` + first +
				`","nextHopGateway":"https://www.googleapis.com/compute/v1/projects/` + project + `/global/gateways/default-internet-gateway"}]}`
		}
		if response == "" {
			return nil, fmt.Errorf("unexpected Compute Engine method or page")
		}
		return &http.Response{StatusCode: http.StatusOK, ContentLength: int64(len(response)), Body: io.NopCloser(strings.NewReader(response))}, nil
	})}
	result, err := discoverGCPCloudInventory(t.Context(), client, config, resolver)
	if err != nil || result.Source != (CloudInventorySource{Provider: "gcp", Account: project, Location: "global"}) ||
		len(result.Resources) != 9 || len(result.Links) != 8 || requests != 7 {
		t.Fatalf("incomplete GCP inventory: %+v, requests=%d, error=%v", result, requests, err)
	}
	for _, resource := range result.Resources {
		switch resource.ID {
		case subnet:
			if !slices.Equal(resource.CIDRs, []string{"10.0.1.0/24", "10.128.0.0/20", "2001:db8:1::/64"}) {
				t.Fatal("primary, secondary or IPv6 subnet prefixes were lost", resource.CIDRs)
			}
		case first + "/peerings/foreign-peer":
			if !resource.External {
				t.Fatal("a same-name foreign VPC was linked as local")
			}
		}
	}
	if !slices.Contains(result.Links, CloudInventoryLink{From: second, To: first + "/peerings/local-peer", Kind: "cloud_peering_accepter"}) ||
		slices.Contains(result.Links, CloudInventoryLink{From: second, To: first + "/peerings/foreign-peer", Kind: "cloud_peering_accepter"}) {
		t.Fatal("peering endpoints were matched by name or address instead of project resource ID")
	}
	partial = true
	if inventory, err := discoverGCPCloudInventory(t.Context(), client, config, resolver); err == nil || len(inventory.Resources) != 0 {
		t.Fatal("unreachable regions yielded a partial replacement", err)
	}
	partial, wrongListKind = false, true
	if inventory, err := discoverGCPCloudInventory(t.Context(), client, config, resolver); err == nil || len(inventory.Resources) != 0 {
		t.Fatal("an empty list for a different resource kind yielded a partial replacement", err)
	}
	wrongListKind, foreignNetwork = false, true
	if inventory, err := discoverGCPCloudInventory(t.Context(), client, config, resolver); err == nil || len(inventory.Resources) != 0 {
		t.Fatal("inventory accepted a resource owned by a different project", err)
	}
}
