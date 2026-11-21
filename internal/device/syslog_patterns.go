// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"encoding/hex"
	"net/netip"
	"regexp"
	"strings"

	"github.com/ctlplne/probectl/internal/crypto"
)

type SyslogPatternKind string

const (
	SyslogPatternOther       SyslogPatternKind = "other"
	SyslogPatternLinkDown    SyslogPatternKind = "link_down"
	SyslogPatternBGPDown     SyslogPatternKind = "bgp_neighbor_down"
	SyslogPatternSupplyFault SyslogPatternKind = "power_supply_fault"
)

// SyslogPattern is candidate evidence derived from one stored line. Subject
// preserves the reported identifier for a later scoped identity check.
type SyslogPattern struct {
	ID             string
	Version        int
	Kind           SyslogPatternKind
	Template       string
	Subject        string
	RoutingContext string
}

var (
	syslogCiscoLinkDown = regexp.MustCompile(`^Interface ([[:alnum:]_.:/-]{1,64}), changed state to down$`)
	syslogCiscoPeerDown = regexp.MustCompile(`^neighbor ([0-9A-Fa-f:.]{1,64}) Down(?: [^\r\n]+)?$`)
	syslogCiscoPSFailed = regexp.MustCompile(`^Power supply ([0-9]{1,4}) failed or shut down \(Serial number [^()\r\n]+\)$`)
	syslogFRRPeerDown   = regexp.MustCompile(`^(?:BGP: )?(?:\[[A-Z0-9]{5}-[A-Z0-9]{5}\] )?%ADJCHANGE: neighbor ([0-9A-Fa-f:.]{1,64})\([^()\r\n]{0,128}\) in vrf ([[:alnum:]_.:-]{1,64}) Down ([^\r\n]+)$`)
	syslogFRRHoldExpiry = regexp.MustCompile(`^(?:BGP: )?(?:\[[A-Z0-9]{5}-[A-Z0-9]{5}\] )?%NOTIFICATION: sent to neighbor ([0-9A-Fa-f:.]{1,64}) 4/0 \(Hold Timer Expired\) [0-9]+ bytes$`)
	syslogNumericToken  = regexp.MustCompile(`^[-+]?(?:[0-9]+(?:\.[0-9]+)?|0[xX][0-9a-fA-F]+)$`)
	syslogOpaqueToken   = regexp.MustCompile(`^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{24,})$`)
)

// DeriveSyslogPattern accepts the source family established by the receiver's
// current device binding. Unbound input is eligible for structural grouping.
func DeriveSyslogPattern(row SyslogEvent, trustedFamily string) (SyslogPattern, bool) {
	const maxObservedBytes = 65536
	if row.TenantID == "" || strings.TrimSpace(row.Message) == "" || len(row.Message) > maxObservedBytes {
		return SyslogPattern{}, false
	}
	pattern := SyslogPattern{Version: 1, Kind: SyslogPatternOther, Template: "Unclassified device message"}
	switch trustedFamily {
	case "cisco_ios", "cisco_nxos":
		pattern = ciscoSyslogPattern(row, pattern)
	case "frr":
		pattern = frrSyslogPattern(row, pattern)
	}
	key := string(pattern.Kind)
	if pattern.Kind == SyslogPatternOther {
		key = "structure\x00" + strings.ToLower(row.AppName) + "\x00" + classifySyslogTokens(row.Message)
	}
	pattern.ID = hex.EncodeToString(crypto.Hash([]byte("device-syslog-pattern-v1\x00" + row.TenantID + "\x00" + key)))
	return pattern, len(pattern.ID) == 64
}

func (row *SyslogEvent) stampSyslogPattern(trustedFamily string) {
	pattern, _ := DeriveSyslogPattern(*row, trustedFamily)
	row.PatternID, row.PatternVersion, row.PatternKind = pattern.ID, pattern.Version, pattern.Kind
}

func ciscoSyslogPattern(row SyslogEvent, pattern SyslogPattern) SyslogPattern {
	tag := strings.TrimPrefix(row.AppName, "%")
	message := row.Message
	if prefix, body, found := strings.Cut(row.Message, ": "); found && strings.HasPrefix(prefix, "%") {
		tag, message = strings.TrimPrefix(prefix, "%"), body
	}
	switch tag {
	case "LINK-3-UPDOWN":
		if matched := syslogCiscoLinkDown.FindStringSubmatch(message); matched != nil {
			pattern.Kind, pattern.Template, pattern.Subject = SyslogPatternLinkDown, "Interface {interface} changed state to down", matched[1]
		}
	case "BGP-5-ADJCHANGE":
		if matched := syslogCiscoPeerDown.FindStringSubmatch(message); matched != nil {
			if peer, err := netip.ParseAddr(matched[1]); err == nil {
				pattern.Kind, pattern.Template, pattern.Subject = SyslogPatternBGPDown, "BGP neighbor {peer} went down", peer.String()
			}
		}
	case "PLATFORM-2-PS_FAIL":
		if matched := syslogCiscoPSFailed.FindStringSubmatch(message); matched != nil {
			pattern.Kind, pattern.Template, pattern.Subject = SyslogPatternSupplyFault, "Power supply {bay} failed or shut down", matched[1]
		}
	}
	return pattern
}

func frrSyslogPattern(row SyslogEvent, pattern SyslogPattern) SyslogPattern {
	if row.AppName != "bgpd" {
		return pattern
	}
	message := strings.TrimSpace(row.Message)
	if matched := syslogFRRHoldExpiry.FindStringSubmatch(message); matched != nil {
		if peer, err := netip.ParseAddr(matched[1]); err == nil {
			pattern.Kind, pattern.Template, pattern.Subject = SyslogPatternBGPDown, "BGP neighbor {peer} went down", peer.String()
		}
		return pattern
	}
	matched := syslogFRRPeerDown.FindStringSubmatch(message)
	if matched == nil || matched[3] == "Admin. shutdown" || matched[3] == "Neighbor deleted" {
		return pattern
	}
	peer, err := netip.ParseAddr(matched[1])
	if err != nil {
		return pattern
	}
	pattern.Kind, pattern.Template = SyslogPatternBGPDown, "BGP neighbor {peer} went down"
	pattern.Subject, pattern.RoutingContext = peer.String(), matched[2]
	return pattern
}

func classifySyslogTokens(message string) string {
	var normalized []string
	for token := range strings.FieldsSeq(message) {
		value := strings.Trim(token, "\"'[](),;")
		if address, err := netip.ParseAddr(value); err == nil && address.IsValid() {
			normalized = append(normalized, "{address}")
			continue
		}
		switch {
		case syslogNumericToken.MatchString(value):
			normalized = append(normalized, "{number}")
		case syslogOpaqueToken.MatchString(value):
			normalized = append(normalized, "{identifier}")
		default:
			normalized = append(normalized, strings.ToLower(token))
		}
	}
	return strings.Join(normalized, " ")
}
