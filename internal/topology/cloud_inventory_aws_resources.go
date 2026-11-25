// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package topology

import (
	"errors"
	"strings"
	"time"
)

type awsInventoryVPC struct {
	ID      string   `xml:"vpcId"`
	Owner   string   `xml:"ownerId"`
	State   string   `xml:"state"`
	Primary string   `xml:"cidrBlock"`
	IPv4    []string `xml:"cidrBlockAssociationSet>item>cidrBlock"`
	IPv6    []string `xml:"ipv6CidrBlockAssociationSet>item>ipv6CidrBlock"`
}

type awsInventorySubnet struct {
	ID      string   `xml:"subnetId"`
	VPCID   string   `xml:"vpcId"`
	Owner   string   `xml:"ownerId"`
	State   string   `xml:"state"`
	Primary string   `xml:"cidrBlock"`
	IPv6    []string `xml:"ipv6CidrBlockAssociationSet>item>ipv6CidrBlock"`
}

type awsAttachment struct {
	VPC   string `xml:"vpcId"`
	State string `xml:"state"`
}

type awsInventoryIGW struct {
	ID          string          `xml:"internetGatewayId"`
	Owner       string          `xml:"ownerId"`
	Attachments []awsAttachment `xml:"attachmentSet>item"`
}

type awsInventoryNAT struct {
	ID     string `xml:"natGatewayId"`
	VPC    string `xml:"vpcId"`
	Subnet string `xml:"subnetId"`
	State  string `xml:"state"`
}

type awsInventoryVPN struct {
	ID          string          `xml:"vpnGatewayId"`
	State       string          `xml:"state"`
	Attachments []awsAttachment `xml:"attachments>item"`
}

type awsInventoryPeerRef struct {
	ID     string `xml:"vpcId"`
	Owner  string `xml:"ownerId"`
	Region string `xml:"region"`
}

type awsInventoryPeer struct {
	ID        string              `xml:"vpcPeeringConnectionId"`
	State     string              `xml:"status>code"`
	Requester awsInventoryPeerRef `xml:"requesterVpcInfo"`
	Accepter  awsInventoryPeerRef `xml:"accepterVpcInfo"`
}

type awsNetworkInventory struct {
	vpcs     []awsInventoryVPC
	subnets  []awsInventorySubnet
	internet []awsInventoryIGW
	nat      []awsInventoryNAT
	vpn      []awsInventoryVPN
	peers    []awsInventoryPeer
}

func (raw awsNetworkInventory) normalize(source CloudInventorySource, clock time.Time) (CloudInventory, error) {
	result := CloudInventory{Source: source, ObservedAt: clock, Resources: []CloudInventoryResource{}, Links: []CloudInventoryLink{}}
	networks, subnets, err := raw.addNetworksAndSubnets(&result)
	if err != nil {
		return CloudInventory{}, err
	}
	raw.addGateways(&result, networks, subnets)
	raw.addPeerings(&result, networks)
	if err := result.Validate(); err != nil {
		return CloudInventory{}, err
	}
	return result, nil
}

func (raw awsNetworkInventory) addNetworksAndSubnets(result *CloudInventory) (map[string]bool, map[string]string, error) {
	networks := make(map[string]bool, len(raw.vpcs))
	for _, v := range raw.vpcs {
		if v.Owner != result.Source.Account {
			continue
		}
		cidrs, err := awsInventoryCIDRs(v.Primary, v.IPv4, v.IPv6)
		if err != nil || !strings.HasPrefix(v.ID, "vpc-") {
			return nil, nil, errors.New("topology: malformed AWS VPC inventory")
		}
		result.Resources = append(result.Resources, CloudInventoryResource{ID: v.ID, Kind: CloudNetwork, Type: "vpc", CIDRs: cidrs, State: v.State})
		networks[v.ID] = true
	}
	subnets := make(map[string]string, len(raw.subnets))
	for _, s := range raw.subnets {
		if s.Owner != result.Source.Account || !networks[s.VPCID] {
			continue
		}
		cidrs, err := awsInventoryCIDRs(s.Primary, s.IPv6)
		if err != nil || !strings.HasPrefix(s.ID, "subnet-") {
			return nil, nil, errors.New("topology: malformed AWS subnet inventory")
		}
		result.Resources = append(result.Resources, CloudInventoryResource{ID: s.ID, Kind: CloudSubnet, Type: "subnet", CIDRs: cidrs, State: s.State})
		result.Links = append(result.Links, CloudInventoryLink{From: s.VPCID, To: s.ID, Kind: "cloud_contains"})
		subnets[s.ID] = s.VPCID
	}
	return networks, subnets, nil
}

func awsInventoryCIDRs(primary string, extras ...[]string) ([]string, error) {
	inputs := []string{primary}
	for _, list := range extras {
		inputs = append(inputs, list...)
	}
	return cloudInventoryCIDRs(inputs...)
}

func (raw awsNetworkInventory) addGateways(result *CloudInventory, networks map[string]bool, subnets map[string]string) {
	for _, g := range raw.internet {
		if g.Owner != result.Source.Account || !strings.HasPrefix(g.ID, "igw-") {
			continue
		}
		result.Resources = append(result.Resources, CloudInventoryResource{ID: g.ID, Kind: CloudGateway, Type: "internet_gateway"})
		for _, a := range g.Attachments {
			if networks[a.VPC] && a.State == "available" {
				result.Links = append(result.Links, CloudInventoryLink{From: a.VPC, To: g.ID, Kind: "cloud_attachment"})
			}
		}
	}
	for _, g := range raw.nat {
		if !networks[g.VPC] || !strings.HasPrefix(g.ID, "nat-") {
			continue
		}
		attached := g.VPC
		if subnets[g.Subnet] == g.VPC {
			attached = g.Subnet
		}
		result.Resources = append(result.Resources, CloudInventoryResource{ID: g.ID, Kind: CloudGateway, Type: "nat_gateway", State: g.State})
		result.Links = append(result.Links, CloudInventoryLink{From: attached, To: g.ID, Kind: "cloud_attachment"})
	}
	for _, g := range raw.vpn {
		if !strings.HasPrefix(g.ID, "vgw-") {
			continue
		}
		result.Resources = append(result.Resources, CloudInventoryResource{ID: g.ID, Kind: CloudGateway, Type: "vpn_gateway", State: g.State})
		for _, a := range g.Attachments {
			if networks[a.VPC] && a.State == "attached" {
				result.Links = append(result.Links, CloudInventoryLink{From: a.VPC, To: g.ID, Kind: "cloud_attachment"})
			}
		}
	}
}

func (raw awsNetworkInventory) addPeerings(result *CloudInventory, networks map[string]bool) {
	inScope := func(ref awsInventoryPeerRef) bool {
		return ref.Owner == result.Source.Account && (ref.Region == "" || ref.Region == result.Source.Location) && networks[ref.ID]
	}
	for _, p := range raw.peers {
		requester, accepter := inScope(p.Requester), inScope(p.Accepter)
		if (!requester && !accepter) || !strings.HasPrefix(p.ID, "pcx-") {
			continue
		}
		result.Resources = append(result.Resources, CloudInventoryResource{ID: p.ID, Kind: CloudPeering, Type: "vpc_peering",
			State: p.State, External: !requester || !accepter})
		if requester {
			result.Links = append(result.Links, CloudInventoryLink{From: p.Requester.ID, To: p.ID, Kind: "cloud_peering_requester"})
		}
		if accepter {
			result.Links = append(result.Links, CloudInventoryLink{From: p.Accepter.ID, To: p.ID, Kind: "cloud_peering_accepter"})
		}
	}
}
