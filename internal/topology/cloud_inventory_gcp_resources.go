// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package topology

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"
)

type gcpNetworkObject struct {
	Self          string `json:"selfLink"`
	Network       string `json:"network"`
	LegacyIPv4    string `json:"IPv4Range"`
	NetworkIPv6   string `json:"internalIpv6Range"`
	IPv4          string `json:"ipCidrRange"`
	IPv6          string `json:"ipv6CidrRange"`
	InternalIPv6  string `json:"internalIpv6Prefix"`
	ExternalIPv6  string `json:"externalIpv6Prefix"`
	NextHop       string `json:"nextHopGateway"`
	SecondaryIPv4 []struct {
		IPv4 string `json:"ipCidrRange"`
	} `json:"secondaryIpRanges"`
	Peerings []struct {
		Name    string `json:"name"`
		Network string `json:"network"`
		State   string `json:"state"`
	} `json:"peerings"`
	NATs []struct {
		Name string `json:"name"`
	} `json:"nats"`
}

type gcpNetworkInventory struct {
	networks, subnets, vpn, classicVPN, routers, routes []gcpNetworkObject
}

var gcpResourceName = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// gcpResourcePath recognizes the canonical Compute URLs and relative API
// names. The result is used exclusively as a join key inside the inventory.
func gcpResourcePath(ref, project string) string {
	for _, prefix := range []string{"https://www.googleapis.com/compute/v1/", "https://compute.googleapis.com/compute/v1/"} {
		if path, ok := strings.CutPrefix(ref, prefix); ok {
			return path
		}
	}
	if strings.HasPrefix(ref, "global/") || strings.HasPrefix(ref, "regions/") {
		return "projects/" + project + "/" + ref
	}
	return ref
}

func gcpOwnedResource(ref, project, collection string, regional bool) string {
	path := gcpResourcePath(ref, project)
	parts := strings.Split(path, "/")
	if len(parts) < 5 || parts[0] != "projects" || parts[1] != project {
		return ""
	}
	if regional && len(parts) == 6 && parts[2] == "regions" && gcpResourceName.MatchString(parts[3]) &&
		parts[4] == collection && gcpResourceName.MatchString(parts[5]) {
		return path
	}
	if !regional && len(parts) == 5 && parts[2] == "global" && parts[3] == collection && gcpResourceName.MatchString(parts[4]) {
		return path
	}
	return ""
}

func (raw gcpNetworkInventory) normalize(project string, observed time.Time) (CloudInventory, error) {
	result := CloudInventory{Source: CloudInventorySource{Provider: "gcp", Account: project, Location: "global"}, ObservedAt: observed}
	networks := make(map[string]bool, len(raw.networks))
	for _, network := range raw.networks {
		id := gcpOwnedResource(network.Self, project, "networks", false)
		cidrs, err := cloudInventoryCIDRs(network.LegacyIPv4, network.NetworkIPv6)
		if id == "" || err != nil {
			return CloudInventory{}, errors.New("topology: invalid GCP network inventory")
		}
		networks[id] = true
		result.Resources = append(result.Resources, CloudInventoryResource{ID: id, Kind: CloudNetwork, Type: "vpc", CIDRs: cidrs})
	}
	if err := raw.addSubnetworks(&result, networks); err != nil {
		return CloudInventory{}, err
	}
	if err := raw.addGateways(&result, networks); err != nil {
		return CloudInventory{}, err
	}
	if err := raw.addPeerings(&result, networks); err != nil {
		return CloudInventory{}, err
	}
	// Aggregated responses use JSON maps. Sort the final snapshot to keep
	// projection and API ordering independent of map iteration order.
	slices.SortFunc(result.Resources, func(a, b CloudInventoryResource) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(result.Links, func(a, b CloudInventoryLink) int {
		return strings.Compare(a.From+"\x00"+a.To+"\x00"+a.Kind, b.From+"\x00"+b.To+"\x00"+b.Kind)
	})
	if err := result.Validate(); err != nil {
		return CloudInventory{}, err
	}
	return result, nil
}

func (raw gcpNetworkInventory) addSubnetworks(result *CloudInventory, networks map[string]bool) error {
	for _, subnet := range raw.subnets {
		id := gcpOwnedResource(subnet.Self, result.Source.Account, "subnetworks", true)
		addresses := []string{subnet.IPv4, subnet.IPv6, subnet.InternalIPv6, subnet.ExternalIPv6}
		for _, secondary := range subnet.SecondaryIPv4 {
			addresses = append(addresses, secondary.IPv4)
		}
		cidrs, err := cloudInventoryCIDRs(addresses...)
		if id == "" || err != nil {
			return errors.New("topology: invalid GCP subnetwork inventory")
		}
		result.Resources = append(result.Resources, CloudInventoryResource{ID: id, Kind: CloudSubnet, Type: "subnet", CIDRs: cidrs})
		parent := gcpResourcePath(subnet.Network, result.Source.Account)
		if networks[parent] {
			result.Links = append(result.Links, CloudInventoryLink{From: parent, To: id, Kind: "cloud_contains"})
		}
	}
	return nil
}

func (raw gcpNetworkInventory) addGateways(result *CloudInventory, networks map[string]bool) error {
	project := result.Source.Account
	appendGateway := func(id, kind, network string) {
		result.Resources = append(result.Resources, CloudInventoryResource{ID: id, Kind: CloudGateway, Type: kind})
		if networks[network] {
			result.Links = append(result.Links, CloudInventoryLink{From: network, To: id, Kind: "cloud_attachment"})
		}
	}
	for _, gateways := range []struct {
		kind, collection string
		items            []gcpNetworkObject
	}{
		{"ha_vpn_gateway", "vpnGateways", raw.vpn},
		{"classic_vpn_gateway", "targetVpnGateways", raw.classicVPN},
	} {
		for _, site := range gateways.items {
			id := gcpOwnedResource(site.Self, project, gateways.collection, true)
			if id == "" {
				return errors.New("topology: invalid GCP VPN gateway inventory")
			}
			appendGateway(id, gateways.kind, gcpResourcePath(site.Network, project))
		}
	}
	for _, router := range raw.routers {
		id := gcpOwnedResource(router.Self, project, "routers", true)
		if id == "" {
			return errors.New("topology: invalid GCP Cloud Router inventory")
		}
		for _, nat := range router.NATs {
			if !gcpResourceName.MatchString(nat.Name) || len(result.Resources) >= MaxCloudInventoryResources {
				return errors.New("topology: invalid GCP Cloud NAT inventory")
			}
			appendGateway(id+"/nats/"+nat.Name, "nat_gateway", gcpResourcePath(router.Network, project))
		}
	}
	defaultGateway := "projects/" + project + "/global/gateways/default-internet-gateway"
	attached := make(map[string]bool)
	for _, route := range raw.routes {
		if gcpOwnedResource(route.Self, project, "routes", false) == "" {
			return errors.New("topology: invalid GCP route inventory")
		}
		network := gcpResourcePath(route.Network, project)
		if networks[network] && !attached[network] && gcpResourcePath(route.NextHop, project) == defaultGateway {
			attached[network] = true
			appendGateway(network+"/gateways/default-internet-gateway", "internet_gateway", network)
		}
	}
	return nil
}

func (raw gcpNetworkInventory) addPeerings(result *CloudInventory, networks map[string]bool) error {
	project := result.Source.Account
	for _, network := range raw.networks {
		id := gcpResourcePath(network.Self, project)
		for _, peering := range network.Peerings {
			if !gcpResourceName.MatchString(peering.Name) || len(result.Resources) >= MaxCloudInventoryResources {
				return errors.New("topology: invalid GCP VPC peering inventory")
			}
			peer := gcpResourcePath(peering.Network, project)
			connection := id + "/peerings/" + peering.Name
			result.Resources = append(result.Resources, CloudInventoryResource{ID: connection, Kind: CloudPeering, Type: "vpc_peering", State: peering.State, External: !networks[peer]})
			result.Links = append(result.Links, CloudInventoryLink{From: id, To: connection, Kind: "cloud_peering_requester"})
			if networks[peer] && id != peer {
				result.Links = append(result.Links, CloudInventoryLink{From: peer, To: connection, Kind: "cloud_peering_accepter"})
			}
		}
	}
	return nil
}
