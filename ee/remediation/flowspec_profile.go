// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"context"
	"net/netip"
	"strconv"

	rem "github.com/ctlplne/probectl/internal/remediation"
)

type flowSpecRouterGuide struct {
	ipv4, ipv6, documentation string
	defaultTableOnly          bool
	singlePortOnly            bool
	ipv6MinimumEntries        uint32
}

var flowSpecRouterGuides = map[rem.FlowSpecRouterProfile]flowSpecRouterGuide{
	rem.FlowSpecJunosStandard: {
		ipv4: "inet flow", ipv6: "inet6 flow", ipv6MinimumEntries: 1,
		documentation: "https://www.juniper.net/documentation/us/en/software/junos/bgp/topics/topic-map/multiprotocol-bgp.html",
	},
	rem.FlowSpecIOSXR711: {
		ipv4: "ipv4 flowspec", ipv6: "ipv6 flowspec", ipv6MinimumEntries: 1,
		documentation: "https://www.cisco.com/c/en/us/td/docs/routers/asr9000/software/711x/routing/configuration/guide/b-routing-cg-asr9000-711x/implementing-bgp-flowspec.html",
	},
	rem.FlowSpecEOS436: {
		ipv4: "flow-spec ipv4", ipv6: "flow-spec ipv6", ipv6MinimumEntries: 2,
		documentation: "https://www.arista.com/en/um-eos/eos-border-gateway-protocol-bgp",
	},
	rem.FlowSpecFRR1071: {
		ipv4: "ipv4 flowspec", ipv6: "ipv6 flowspec", ipv6MinimumEntries: 1,
		documentation:    "https://docs.frrouting.org/en/stable-10.7/bgp.html#flowspec",
		defaultTableOnly: true, singlePortOnly: true,
	},
}

func (s *Service) QualifyFlowSpec(ctx context.Context, tenant, id string, input rem.FlowSpecQualificationInput,
	credential func(context.Context) error,
) (rem.FlowSpecQualification, error) {
	review, err := s.GetFlowSpecReview(ctx, tenant, id, credential)
	if err != nil {
		return rem.FlowSpecQualification{}, err
	}
	out, err := qualifyFlowSpec(review, input)
	if err != nil {
		return out, err
	}
	out.QualificationFingerprint, err = digestFlowSpecQualification(out)
	return out, err
}

func qualifyFlowSpec(review rem.FlowSpecReview, input rem.FlowSpecQualificationInput) (rem.FlowSpecQualification, error) {
	guide, known := flowSpecRouterGuides[input.Profile]
	if !known {
		return rem.FlowSpecQualification{}, rem.Error{Code: "validation", Message: "select a documented router profile"}
	}
	if input.RoutingTable != "default" && input.RoutingTable != "vrf" {
		return rem.FlowSpecQualification{}, rem.Error{Code: "validation", Message: "select the target routing table"}
	}
	candidate := review.Proposal.Candidate
	destination, err := netip.ParsePrefix(candidate.Destination)
	if err != nil || destination != destination.Masked() || destination.Bits() < 1 || destination.Addr().Is4In6() ||
		candidate.Action != "discard" || candidate.Transport.Validate() != nil || !validRTBHDigest(review.Fingerprint) {
		return rem.FlowSpecQualification{}, rem.ErrUnknownBlastRadius
	}
	family := "ipv6"
	afi := uint16(2)
	addressFamily, minimumEntries := guide.ipv6, guide.ipv6MinimumEntries
	if destination.Addr().Is4() {
		family, afi = "ipv4", 1
		addressFamily, minimumEntries = guide.ipv4, 1
	}
	if family != candidate.Family {
		return rem.FlowSpecQualification{}, rem.ErrUnknownBlastRadius
	}

	out := rem.FlowSpecQualification{
		ReviewFingerprint: review.Fingerprint, Profile: input.Profile, RoutingTable: input.RoutingTable,
		AddressFamily: addressFamily, Documentation: guide.documentation,
		Capacity: rem.FlowSpecProfileCapacity{MinimumEntries: minimumEntries},
		Findings: make([]string, 0, 3),
	}
	if guide.defaultTableOnly && input.RoutingTable != "default" {
		out.Findings = append(out.Findings, "This FRRouting profile requires the default routing table.")
	}
	if guide.singlePortOnly && candidate.Transport.SourcePort != nil && candidate.Transport.DestinationPort != nil {
		out.Findings = append(out.Findings, "This FRRouting profile cannot install a match with both source and destination ports.")
	}
	out.SyntaxCompatible = len(out.Findings) == 0
	if input.AvailableEntries != nil {
		reported := *input.AvailableEntries
		fits := minimumEntries <= reported
		out.Capacity.DeclaredEntries, out.Capacity.FitsDeclared = &reported, &fits
		if !fits {
			out.Findings = append(out.Findings, "The declared free entries are below the documented minimum.")
		}
	}
	if out.SyntaxCompatible {
		template := flowSpecRuleTemplate(candidate, afi)
		out.Template = &template
	}
	return out, nil
}

func flowSpecRuleTemplate(candidate rem.FlowSpecCandidate, afi uint16) rem.FlowSpecRuleTemplate {
	protocol := "6"
	if candidate.Transport.Protocol == "udp" {
		protocol = "17"
	}
	field := "ip_protocol"
	if afi == 2 {
		field = "upper_layer_protocol"
	}
	components := []rem.FlowSpecComponent{
		{Type: 1, Field: "destination_prefix", Value: candidate.Destination},
		{Type: 3, Field: field, Value: protocol},
	}
	if port := candidate.Transport.DestinationPort; port != nil {
		components = append(components, rem.FlowSpecComponent{Type: 5, Field: "destination_port", Value: strconv.FormatUint(uint64(*port), 10)})
	}
	if port := candidate.Transport.SourcePort; port != nil {
		components = append(components, rem.FlowSpecComponent{Type: 6, Field: "source_port", Value: strconv.FormatUint(uint64(*port), 10)})
	}
	return rem.FlowSpecRuleTemplate{AFI: afi, SAFI: 133, Components: components, Action: candidate.Action}
}
