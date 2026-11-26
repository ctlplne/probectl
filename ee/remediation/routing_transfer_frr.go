// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/ctlplne/probectl/internal/crypto"
	rem "github.com/ctlplne/probectl/internal/remediation"
)

var frrRoutingPolicyName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)

type frrTransferDryRun struct {
	CandidatePeer          string
	CandidateASN           uint32
	ExactPrefix            string
	BeforeMap              string
	AfterMap               string
	DefaultLocalPreference uint32
	WeightVerification     bool
	Configure              []string
	Withdraw               []string
}

type frrInboundPolicy struct {
	asn     string
	mapName string
	peerASN uint32
}

type frrNeighborKey struct{ localASN, name string }

type frrNeighborDefinition struct {
	remoteAS, group         string
	groupDefined, ambiguous bool
}

// draftFRRTransfer generates a read-only handoff for a currently authorized
// archive and transfer. It cannot change the router or approve a proposal.
// The operator's old map still filters and transforms every candidate route.
func draftFRRTransfer(ctx context.Context, config string, peer netip.Addr, peerASN uint32, prefix netip.Prefix, preference uint32, maxBytes int64) (frrTransferDryRun, error) {
	none := frrTransferDryRun{}
	if !peer.IsValid() || peer.Zone() != "" || peer.Is4In6() || peer.IsUnspecified() || peer.IsMulticast() ||
		!prefix.IsValid() || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.Addr().Is4In6() || preference == 0 || peerASN == 0 {
		return none, rem.ErrUnknownBlastRadius
	}
	family, prefixList := "ipv6", "ipv6 prefix-list"
	if prefix.Addr().Is4() {
		family, prefixList = "ipv4", "ip prefix-list"
	}
	digest := hex.EncodeToString(crypto.Hash([]byte(peer.String() + "/" + prefix.String())))
	name := "PCTL-TE-" + digest[:16]
	current, err := readFRRInboundPolicy(ctx, config, peer, family, name, maxBytes)
	if err != nil {
		return none, err
	}
	if current.peerASN != peerASN {
		return none, rem.Error{Code: "validation", Message: "the router archive names a different ASN for the observed candidate peer"}
	}
	defaultPreference, checkWeight, err := frrBestPathControls(ctx, config, current.asn)
	if err != nil {
		return none, err
	}
	if preference <= defaultPreference {
		return none, rem.Error{Code: "validation", Message: "the proposed preference must exceed the router's default local preference"}
	}
	matchFamily := "ipv6"
	if family == "ipv4" {
		matchFamily = "ip"
	}
	match := "match " + matchFamily + " address prefix-list " + name
	addressFamily := "address-family " + family + " unicast"
	neighbor := "neighbor " + peer.String() + " route-map "
	routeMap := "route-map " + name
	return frrTransferDryRun{CandidatePeer: peer.String(), CandidateASN: current.peerASN,
		ExactPrefix: prefix.String(), BeforeMap: current.mapName, AfterMap: name,
		DefaultLocalPreference: defaultPreference, WeightVerification: checkWeight,
		Configure: []string{
			prefixList + " " + name + " seq 10 permit " + prefix.String(),
			routeMap + " permit 10", match, "call " + current.mapName, "on-match next", "exit",
			routeMap + " permit 20", match, "set local-preference " + strconv.FormatUint(uint64(preference), 10), "exit",
			routeMap + " permit 30", "call " + current.mapName, "exit",
			"router bgp " + current.asn, addressFamily, neighbor + name + " in", "exit-address-family", "exit",
		},
		Withdraw: []string{
			"router bgp " + current.asn, addressFamily, neighbor + current.mapName + " in", "exit-address-family", "exit",
			"no " + routeMap, "no " + prefixList + " " + name,
		},
	}, ctx.Err()
}

// Local weight precedes preference in FRR. The archive can indicate that
// weight is configured, while effective per-route weights require live
// best-path evidence. Keep that qualification explicit in the dry run.
func frrBestPathControls(ctx context.Context, config, routerASN string) (uint32, bool, error) {
	const defaultLocalPreference = 100 // FRR bgpd.h BGP_DEFAULT_LOCAL_PREF
	preference := uint32(defaultLocalPreference)
	var selectedInstance, configuredPreference, weightConfigured bool
	scanner := bufio.NewScanner(strings.NewReader(config))
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return 0, false, err
		}
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] == "!" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			selectedInstance = slices.Equal(fields, []string{"router", "bgp", routerASN})
			continue
		}
		if len(fields) == 3 && fields[0] == "set" && fields[1] == "weight" {
			weightConfigured = true
		}
		if !selectedInstance {
			continue
		}
		if len(fields) >= 4 && fields[0] == "neighbor" && fields[2] == "weight" {
			weightConfigured = true
		}
		if len(fields) == 4 && slices.Equal(fields[:3], []string{"bgp", "default", "local-preference"}) {
			value, err := strconv.ParseUint(fields[3], 10, 32)
			if err != nil || value > math.MaxUint32 || configuredPreference {
				return 0, false, rem.ErrUnknownBlastRadius
			}
			configuredPreference = true
			preference = uint32(value) // ParseUint admits only 32-bit values.
		}
	}
	return preference, weightConfigured, scanner.Err()
}

// Read the explicit unicast attachment from FRR's running-config syntax. A
// missing, inherited, ambiguous or non-global attachment is never guessed.
func readFRRInboundPolicy(ctx context.Context, config string, peer netip.Addr, family, newName string, maxBytes int64) (frrInboundPolicy, error) {
	none := frrInboundPolicy{}
	if config == "" || maxBytes <= 0 || int64(len(config)) > maxBytes {
		return none, rem.ErrUnknownBlastRadius
	}
	var out frrInboundPolicy
	var asn, afi string
	var confirmedFRR, inFamily bool
	defined := map[string]bool{}
	neighbors := map[frrNeighborKey]frrNeighborDefinition{}
	scanner := bufio.NewScanner(strings.NewReader(config))
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] == "!" {
			continue
		}
		if slices.Contains(fields, newName) {
			return none, rem.ErrUnknownBlastRadius
		}
		if line[0] != ' ' && line[0] != '\t' {
			asn, afi = "", ""
			inFamily = false
			if len(fields) == 3 && fields[0] == "frr" && fields[1] == "version" {
				confirmedFRR = true
			}
			if len(fields) == 3 && fields[0] == "router" && fields[1] == "bgp" {
				value, err := strconv.ParseUint(fields[2], 10, 32)
				if err == nil && value > 0 && strconv.FormatUint(value, 10) == fields[2] {
					asn = fields[2]
				}
			}
			if len(fields) == 4 && fields[0] == "route-map" && (fields[2] == "permit" || fields[2] == "deny") {
				defined[fields[1]] = true
			}

			continue
		}
		if asn == "" {
			continue
		}
		switch fields[0] {
		case "address-family":
			inFamily = true
			afi = ""
			if len(fields) == 3 && fields[2] == "unicast" {
				afi = fields[1]
			}
		case "exit-address-family":
			inFamily = false
			afi = ""
		case "neighbor":
			if !inFamily && recordFRRNeighborDefinition(neighbors, asn, fields) {
				continue
			}
			if afi != family || len(fields) != 5 || fields[2] != "route-map" || fields[4] != "in" {
				continue
			}
			address, err := netip.ParseAddr(fields[1])
			if err != nil || address != peer {
				continue
			}
			if out.asn != "" || !frrRoutingPolicyName.MatchString(fields[3]) {
				return none, rem.ErrUnknownBlastRadius
			}
			out = frrInboundPolicy{asn: asn, mapName: fields[3]}
		}
	}
	if err := scanner.Err(); err != nil {
		return none, fmt.Errorf("read complete routing policy archive: %w", err)
	}
	if !confirmedFRR || out.asn == "" || !defined[out.mapName] {
		return none, rem.ErrUnknownBlastRadius
	}
	peerASN, err := frrArchivedRemoteASN(neighbors, out.asn, peer)
	if err != nil {
		return none, err
	}
	out.peerASN = peerASN
	return out, ctx.Err()
}

func recordFRRNeighborDefinition(neighbors map[frrNeighborKey]frrNeighborDefinition, asn string, fields []string) bool {
	if len(fields) == 3 && fields[2] == "peer-group" {
		key := frrNeighborKey{asn, fields[1]}
		definition := neighbors[key]
		definition.ambiguous = definition.ambiguous || definition.groupDefined
		definition.groupDefined = true
		neighbors[key] = definition
		return true
	}
	if len(fields) != 4 || (fields[2] != "remote-as" && fields[2] != "peer-group") {
		return false
	}
	key := frrNeighborKey{asn, fields[1]}
	if address, err := netip.ParseAddr(key.name); err == nil {
		key.name = address.String()
	}
	definition := neighbors[key]
	if fields[2] == "remote-as" {
		definition.ambiguous = definition.ambiguous || definition.remoteAS != ""
		definition.remoteAS = fields[3]
	} else {
		definition.ambiguous = definition.ambiguous || definition.group != ""
		definition.group = fields[3]
	}
	neighbors[key] = definition
	return true
}

func frrArchivedRemoteASN(neighbors map[frrNeighborKey]frrNeighborDefinition, localASN string, peer netip.Addr) (uint32, error) {
	definition := neighbors[frrNeighborKey{localASN, peer.String()}]
	if definition.ambiguous || definition.groupDefined {
		return 0, rem.ErrUnknownBlastRadius
	}
	remote := definition.remoteAS
	if definition.group != "" {
		if !frrRoutingPolicyName.MatchString(definition.group) {
			return 0, rem.ErrUnknownBlastRadius
		}
		group := neighbors[frrNeighborKey{localASN, definition.group}]
		if !group.groupDefined || group.ambiguous || group.group != "" || group.remoteAS == "" || (remote != "" && remote != group.remoteAS) {
			return 0, rem.ErrUnknownBlastRadius
		}
		remote = group.remoteAS
	}
	value, err := strconv.ParseUint(remote, 10, 32)
	if err != nil || value == 0 || value > math.MaxUint32 || strconv.FormatUint(value, 10) != remote {
		return 0, rem.ErrUnknownBlastRadius
	}
	return uint32(value), nil
}
