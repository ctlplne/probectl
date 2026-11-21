// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package remediation

import (
	"net/netip"
	"slices"
)

// RTBHUpstreamTemplate is a versioned policy reference for an operator
// proposal. A zero family minimum indicates that this template omits it.
type RTBHUpstreamTemplate struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	SessionASN  uint32 `json:"session_asn"`
	Community   string `json:"community"`
	IPv4Minimum int    `json:"ipv4_minimum,omitempty"`
	IPv6Minimum int    `json:"ipv6_minimum,omitempty"`
	Scope       string `json:"scope"`
	Requirement string `json:"requirement"`
	Source      string `json:"source"`
	VerifiedOn  string `json:"verified_on"`
}

var rtbhUpstreamTemplates = []RTBHUpstreamTemplate{
	{
		ID: "arelion-transit-global-v1", Provider: "Arelion IP Transit", SessionASN: 1299, Community: "1299:666",
		IPv4Minimum: 32, IPv6Minimum: 128, Scope: "Global Arelion backbone",
		Requirement: "Confirm the RTBH add-on is enabled on this session. This template selects host prefixes.",
		Source:      "https://www.arelion.com/our-network/bgp-routing/bgp-communities", VerifiedOn: "2026-11-20",
	},
	{
		ID: "gtt-transit-v1", Provider: "GTT IP Transit", SessionASN: 3257, Community: "3257:2666",
		IPv4Minimum: 32, Scope: "GTT AS3257",
		Requirement: "Confirm session-specific enablement and the destination prefix with GTT. This template selects IPv4 host prefixes.",
		Source:      "https://www.gtt.net/services/managed-networking/internet/ip-transit/bgp-communities/", VerifiedOn: "2026-11-20",
	},
	{
		ID: "hurricane-electric-transit-v1", Provider: "Hurricane Electric IP Transit", SessionASN: 6939, Community: "6939:666",
		IPv4Minimum: 24, Scope: "Hurricane Electric core",
		Requirement: "Use your owned IPv4 space and a session with customer blackholing and community delivery enabled.",
		Source:      "https://www.he.net/adm/blackhole.html", VerifiedOn: "2026-11-20",
	},
	{
		ID: "inter-link-transit-global-v1", Provider: "Inter.link IP Transit", SessionASN: 5405, Community: "65535:666",
		IPv4Minimum: 20, IPv6Minimum: 48, Scope: "Global Inter.link backbone with propagation to peers and upstreams",
		Requirement: "Confirm peer prefix-filter coverage. The provider describes peer-dependent handling for prefixes broader than a host.",
		Source:      "https://inter.link/knowledgebase/bgp-communities/", VerifiedOn: "2026-11-20",
	},
	{
		ID: "lumen-on-demand-v1", Provider: "Lumen Internet On-Demand", SessionASN: 3356, Community: "3356:9999",
		IPv4Minimum: 32, IPv6Minimum: 128, Scope: "Individual host on the Lumen service",
		Requirement: "Confirm the blackholing option is selected on the exact BGP service.",
		Source:      "https://docs.lumen.com/intelligent-internet/adding-intelligent-internet-with-bgp-routing/", VerifiedOn: "2026-11-20",
	},
	{
		ID: "ntt-gin-global-v1", Provider: "NTT DATA Global IP Network", SessionASN: 2914, Community: "2914:666",
		IPv4Minimum: 32, IPv6Minimum: 128, Scope: "Ingress to the NTT Global IP Network",
		Requirement: "Confirm NTT has enabled blackholing on this BGP session and its existing ingress filter covers the protected host.",
		Source:      "https://www.gin.ntt.net/support-center/policies-procedures/routing/", VerifiedOn: "2026-11-21",
	},
	{
		ID: "retn-transit-v1", Provider: "RETN IP Transit", SessionASN: 9002, Community: "9002:666",
		IPv4Minimum: 32, IPv6Minimum: 128, Scope: "Ingress to the RETN network",
		Requirement: "Confirm RTBH is available on this IP Transit session and verify that it accepts the owned host prefix.",
		Source:      "https://retn.net/products/ddos-protection", VerifiedOn: "2026-11-21",
	},
}

func RTBHUpstreamTemplates() []RTBHUpstreamTemplate {
	return slices.Clone(rtbhUpstreamTemplates)
}

func RTBHUpstreamTemplateByID(id string) (RTBHUpstreamTemplate, bool) {
	for _, candidate := range rtbhUpstreamTemplates {
		if candidate.ID == id {
			return candidate, true
		}
	}
	return RTBHUpstreamTemplate{}, false
}

func (t RTBHUpstreamTemplate) SupportsPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
		return false
	}
	minimum := t.IPv6Minimum
	if prefix.Addr().Is4() {
		minimum = t.IPv4Minimum
	}
	return minimum > 0 && prefix.Bits() >= minimum
}
