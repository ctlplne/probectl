// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"slices"
	"strings"
	"testing"

	rem "github.com/ctlplne/probectl/internal/remediation"
)

func TestFlowSpecProfileChecksPreserveTypedReview(t *testing.T) {
	one, three := uint32(1), uint32(3)
	fits, insufficient := true, false
	port, destination := uint16(1053), uint16(1443)
	for _, tc := range []struct {
		name            string
		profile         rem.FlowSpecRouterProfile
		family          string
		prefix          string
		table           string
		available       *uint32
		source          *uint16
		requestedFamily string
		wantCompatible  bool
		wantMinimum     uint32
		wantFits        *bool
		wantCodes       []uint8
	}{
		{"junos ipv4", rem.FlowSpecJunosStandard, "ipv4", "192.0.2.0/24", "default", nil, &port, "inet flow", true, 1, nil, []uint8{1, 3, 5, 6}},
		{"ios xr ipv6 vrf", rem.FlowSpecIOSXR711, "ipv6", "2001:db8::/64", "vrf", nil, &port, "ipv6 flowspec", true, 1, nil, []uint8{1, 3, 5, 6}},
		{"eos ipv6 low capacity", rem.FlowSpecEOS436, "ipv6", "2001:db8::/64", "default", &one, &port, "flow-spec ipv6", true, 2, &insufficient, []uint8{1, 3, 5, 6}},
		{"eos ipv6 admitted lower bound", rem.FlowSpecEOS436, "ipv6", "2001:db8::/64", "default", &three, &port, "flow-spec ipv6", true, 2, &fits, []uint8{1, 3, 5, 6}},
		{"frr single port", rem.FlowSpecFRR1071, "ipv4", "192.0.2.0/24", "default", &one, nil, "ipv4 flowspec", true, 1, &fits, []uint8{1, 3, 5}},
		{"frr two ports", rem.FlowSpecFRR1071, "ipv4", "192.0.2.0/24", "default", nil, &port, "ipv4 flowspec", false, 1, nil, nil},
		{"frr vrf", rem.FlowSpecFRR1071, "ipv6", "2001:db8::/64", "vrf", nil, nil, "ipv6 flowspec", false, 1, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			review := rem.FlowSpecReview{
				Fingerprint: strings.Repeat("c", 64),
				Proposal: rem.FlowSpecPreview{Candidate: rem.FlowSpecCandidate{
					Family: tc.family, Destination: tc.prefix, Action: "discard",
					Transport: rem.FlowSpecTransport{Protocol: "udp", SourcePort: tc.source, DestinationPort: &destination},
				}},
			}
			check, err := qualifyFlowSpec(review, rem.FlowSpecQualificationInput{
				Profile: tc.profile, RoutingTable: tc.table, AvailableEntries: tc.available,
			})
			if err != nil || check.ReviewFingerprint != review.Fingerprint || check.AddressFamily != tc.requestedFamily ||
				check.SyntaxCompatible != tc.wantCompatible || check.Capacity.MinimumEntries != tc.wantMinimum ||
				!sameOptionalBool(check.Capacity.FitsDeclared, tc.wantFits) {
				t.Fatalf("profile check = %+v, error = %v", check, err)
			}
			if !tc.wantCompatible {
				if check.Template != nil || len(check.Findings) == 0 {
					t.Fatalf("unsupported rule has no reason or returned a template: %+v", check)
				}
				return
			}
			assertFlowSpecTemplate(t, check.Template, tc.prefix, tc.family, tc.wantCodes)
		})
	}
}

func sameOptionalBool(a, b *bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func assertFlowSpecTemplate(t *testing.T, template *rem.FlowSpecRuleTemplate, prefix, family string, wantCodes []uint8) {
	t.Helper()
	if template == nil || template.SAFI != 133 || template.Action != "discard" {
		t.Fatalf("wrong template: %+v", template)
	}
	afi, field := uint16(1), "ip_protocol"
	if family == "ipv6" {
		afi, field = 2, "upper_layer_protocol"
	}
	codes := make([]uint8, 0, len(template.Components))
	for _, component := range template.Components {
		codes = append(codes, component.Type)
	}
	if !slices.Equal(codes, wantCodes) || template.AFI != afi || template.Components[0].Value != prefix ||
		template.Components[1].Value != "17" || template.Components[1].Field != field {
		t.Fatalf("wrong family, component order or match: %+v", template)
	}
}
