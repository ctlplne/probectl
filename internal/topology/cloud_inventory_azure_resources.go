// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package topology

import (
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
)

type azureNetworkRef struct {
	ID string `json:"id"`
}

type azureNetworkObject struct {
	ID         string                  `json:"id"`
	Type       string                  `json:"type"`
	Properties *azureNetworkProperties `json:"properties"`
}

type azureNetworkProperties struct {
	ProvisioningState string               `json:"provisioningState"`
	AddressPrefix     string               `json:"addressPrefix"`
	AddressPrefixes   []string             `json:"addressPrefixes"`
	Subnetworks       []azureNetworkObject `json:"subnets"`
	Peerings          []azureNetworkObject `json:"virtualNetworkPeerings"`
	PeeringState      string               `json:"peeringState"`
	RemoteNetwork     azureNetworkRef      `json:"remoteVirtualNetwork"`
	NATGateway        azureNetworkRef      `json:"natGateway"`
	SourceNetwork     azureNetworkRef      `json:"sourceVirtualNetwork"`
	GatewayType       string               `json:"gatewayType"`
	AddressSpace      struct {
		Prefixes []string `json:"addressPrefixes"`
	} `json:"addressSpace"`
	IPConfigurations []struct {
		Properties struct {
			Subnet azureNetworkRef `json:"subnet"`
		} `json:"properties"`
	} `json:"ipConfigurations"`
}

type azureNetworkInventory struct {
	vnets, nats, gateways []azureNetworkObject
}

// ARM resource IDs are case-insensitive. Compare the collection, subscription
// and every path segment before using an ID as a join key or a resource read.
func azureOwnedNetworkID(raw, subscription, collection, child string) string {
	if !cloudInventoryText(raw, 1024) {
		return ""
	}
	parts := strings.Split(raw, "/")
	wantParts := 9
	if child != "" {
		wantParts = 11
	}
	if len(parts) != wantParts || parts[0] != "" || !strings.EqualFold(parts[1], "subscriptions") ||
		!strings.EqualFold(parts[2], subscription) || !strings.EqualFold(parts[3], "resourceGroups") ||
		!azureResourceSegment(parts[4]) || !strings.EqualFold(parts[5], "providers") ||
		!strings.EqualFold(parts[6], "Microsoft.Network") || !strings.EqualFold(parts[7], collection) || !azureResourceSegment(parts[8]) {
		return ""
	}
	if child != "" && (!strings.EqualFold(parts[9], child) || !azureResourceSegment(parts[10])) {
		return ""
	}
	return strings.ToLower(raw)
}

func azureResourceSegment(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 256 {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r) && !strings.ContainsRune("._-()", r)
	}) < 0
}

func (raw azureNetworkInventory) normalize(subscription string, observed time.Time) (CloudInventory, error) {
	result := CloudInventory{Source: CloudInventorySource{Provider: "azure", Account: subscription, Location: "global"}, ObservedAt: observed}
	networks := make(map[string]bool, len(raw.vnets))
	subnets := make(map[string]string)
	for _, network := range raw.vnets {
		id := azureOwnedNetworkID(network.ID, subscription, "virtualNetworks", "")
		if id == "" || network.Properties == nil {
			return CloudInventory{}, errors.New("topology: invalid Azure virtual network inventory")
		}
		p := network.Properties
		cidrs, err := cloudInventoryCIDRs(p.AddressSpace.Prefixes...)
		if err != nil {
			return CloudInventory{}, err
		}
		networks[id] = true
		result.Resources = append(result.Resources, CloudInventoryResource{ID: id, Kind: CloudNetwork, Type: "vnet", CIDRs: cidrs, State: p.ProvisioningState})
		for _, subnet := range p.Subnetworks {
			subnetID := azureOwnedNetworkID(subnet.ID, subscription, "virtualNetworks", "subnets")
			if !strings.HasPrefix(subnetID, id+"/subnets/") || subnet.Properties == nil || len(result.Resources) >= MaxCloudInventoryResources {
				return CloudInventory{}, errors.New("topology: invalid Azure subnet inventory")
			}
			prefixes := append([]string{subnet.Properties.AddressPrefix}, subnet.Properties.AddressPrefixes...)
			cidrs, err := cloudInventoryCIDRs(prefixes...)
			if err != nil {
				return CloudInventory{}, err
			}
			result.Resources = append(result.Resources, CloudInventoryResource{ID: subnetID, Kind: CloudSubnet, Type: "subnet", CIDRs: cidrs, State: subnet.Properties.ProvisioningState})
			result.Links = append(result.Links, CloudInventoryLink{From: id, To: subnetID, Kind: "cloud_contains"})
			subnets[subnetID] = azureOwnedNetworkID(subnet.Properties.NATGateway.ID, subscription, "natGateways", "")
		}
	}
	if err := raw.addAzureGateways(&result, networks, subnets); err != nil {
		return CloudInventory{}, err
	}
	if err := raw.addAzurePeerings(&result, networks); err != nil {
		return CloudInventory{}, err
	}
	slices.SortFunc(result.Resources, func(a, b CloudInventoryResource) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(result.Links, func(a, b CloudInventoryLink) int {
		return strings.Compare(a.From+"\x00"+a.To+"\x00"+a.Kind, b.From+"\x00"+b.To+"\x00"+b.Kind)
	})
	if err := result.Validate(); err != nil {
		return CloudInventory{}, err
	}
	return result, nil
}

func (raw azureNetworkInventory) addAzureGateways(result *CloudInventory, networks map[string]bool, subnets map[string]string) error {
	subscription := result.Source.Account
	nats := make(map[string]bool, len(raw.nats))
	attachments := make(map[CloudInventoryLink]bool)
	attach := func(from, to string) {
		link := CloudInventoryLink{From: from, To: to, Kind: "cloud_attachment"}
		if !attachments[link] {
			attachments[link] = true
			result.Links = append(result.Links, link)
		}
	}
	for _, nat := range raw.nats {
		id := azureOwnedNetworkID(nat.ID, subscription, "natGateways", "")
		if id == "" || nat.Properties == nil {
			return errors.New("topology: invalid Azure NAT gateway inventory")
		}
		nats[id] = true
		p := nat.Properties
		result.Resources = append(result.Resources, CloudInventoryResource{ID: id, Kind: CloudGateway, Type: "nat_gateway", State: p.ProvisioningState})
		if network := azureOwnedNetworkID(p.SourceNetwork.ID, subscription, "virtualNetworks", ""); networks[network] {
			attach(network, id)
		}
		for _, subnet := range p.Subnetworks {
			subnetID := azureOwnedNetworkID(subnet.ID, subscription, "virtualNetworks", "subnets")
			if configured, exists := subnets[subnetID]; exists && (configured == "" || configured == id) {
				attach(subnetID, id)
			}
		}
	}
	for subnet, nat := range subnets {
		if nats[nat] {
			attach(subnet, nat)
		}
	}
	for _, gateway := range raw.gateways {
		id := azureOwnedNetworkID(gateway.ID, subscription, "virtualNetworkGateways", "")
		if id == "" || gateway.Properties == nil {
			return errors.New("topology: invalid Azure virtual network gateway inventory")
		}
		p := gateway.Properties
		kind := "virtual_network_gateway"
		switch strings.ToLower(p.GatewayType) {
		case "vpn":
			kind = "vpn_gateway"
		case "expressroute":
			kind = "expressroute_gateway"
		}
		result.Resources = append(result.Resources, CloudInventoryResource{ID: id, Kind: CloudGateway, Type: kind, State: p.ProvisioningState})
		for _, ip := range p.IPConfigurations {
			subnet := azureOwnedNetworkID(ip.Properties.Subnet.ID, subscription, "virtualNetworks", "subnets")
			if _, exists := subnets[subnet]; exists {
				attach(subnet, id)
			}
		}
	}
	return nil
}

func (raw azureNetworkInventory) addAzurePeerings(result *CloudInventory, networks map[string]bool) error {
	subscription := result.Source.Account
	for _, vnet := range raw.vnets {
		id := azureOwnedNetworkID(vnet.ID, subscription, "virtualNetworks", "")
		for _, peer := range vnet.Properties.Peerings {
			peerID := azureOwnedNetworkID(peer.ID, subscription, "virtualNetworks", "virtualNetworkPeerings")
			if !strings.HasPrefix(peerID, id+"/virtualnetworkpeerings/") || peer.Properties == nil || len(result.Resources) >= MaxCloudInventoryResources {
				return errors.New("topology: invalid Azure virtual network peering inventory")
			}
			remote := azureOwnedNetworkID(peer.Properties.RemoteNetwork.ID, subscription, "virtualNetworks", "")
			result.Resources = append(result.Resources, CloudInventoryResource{ID: peerID, Kind: CloudPeering, Type: "vnet_peering",
				State: peer.Properties.PeeringState, External: !networks[remote]})
			result.Links = append(result.Links, CloudInventoryLink{From: id, To: peerID, Kind: "cloud_peering_requester"})
			if networks[remote] && remote != id {
				result.Links = append(result.Links, CloudInventoryLink{From: remote, To: peerID, Kind: "cloud_peering_accepter"})
			}
		}
	}
	return nil
}
