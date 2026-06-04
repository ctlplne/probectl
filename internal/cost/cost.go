// Package cost is the S44 (F41) FinOps / egress-cost engine: it correlates
// flow records (S38) with operator-declared zone/ownership maps and PUBLIC
// cloud pricing into per-service/per-team cost attribution, cross-AZ/region
// "chatty service" detection, hourly cost trends, and budget alerts with
// Org/Team showback.
//
// Design constraints (the S44 watch-outs):
//
//   - Volume × public pricing FIRST. Cloud billing APIs vary and lag, so the
//     engine prices observed egress volume against list rates; full billing
//     reconciliation is explicitly out of scope.
//   - Degrade gracefully without pricing: no price table → volume-only
//     accounting (bytes attributed, dollars zero, priced=false surfaced
//     honestly) — never a refusal, never an invented rate.
//   - Pricing freshness/AUP: the table carries provenance (source, as-of
//     date, license note); defaults ship embedded from public pricing pages
//     and operators override them (their negotiated rates differ).
//   - Tenant isolation: all state is tenant-partitioned (guardrail 1);
//     budget breaches are SIGNALS into the incident pipeline (guardrail 9).
package cost

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// TrafficClass classifies a flow for pricing.
type TrafficClass string

// Traffic classes, cheapest to most expensive in typical public pricing.
const (
	ClassSameZone    TrafficClass = "same_zone"
	ClassInterAZ     TrafficClass = "inter_az"
	ClassInterRegion TrafficClass = "inter_region"
	ClassInternet    TrafficClass = "internet_egress"
	ClassUnknown     TrafficClass = "unknown" // zones unmapped — volume tracked, conservatively unpriced
)

// ZoneRule maps a CIDR onto a cloud zone/region (operator-declared: VPC
// subnet layouts are deployment-specific and never guessable).
type ZoneRule struct {
	Prefix netip.Prefix
	Zone   string // e.g. "us-east-1a"
	Region string // e.g. "us-east-1" (derived from Zone when empty)
}

// OwnerRule attributes a CIDR to a service and its owning team (showback).
type OwnerRule struct {
	Prefix  netip.Prefix
	Service string
	Team    string
}

// ParseZoneRules parses "cidr=zone[/region],..." (the config wire format).
func ParseZoneRules(raw string) ([]ZoneRule, error) {
	var out []ZoneRule
	for _, part := range splitList(raw) {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("cost: zone rule %q is not cidr=zone", part)
		}
		pfx, err := netip.ParsePrefix(strings.TrimSpace(kv[0]))
		if err != nil {
			return nil, fmt.Errorf("cost: zone rule %q: %w", part, err)
		}
		zone, region, _ := strings.Cut(strings.TrimSpace(kv[1]), "/")
		if region == "" {
			region = regionOfZone(zone)
		}
		out = append(out, ZoneRule{Prefix: pfx, Zone: zone, Region: region})
	}
	return out, nil
}

// ParseOwnerRules parses "cidr=service:team,..." (the config wire format).
func ParseOwnerRules(raw string) ([]OwnerRule, error) {
	var out []OwnerRule
	for _, part := range splitList(raw) {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("cost: owner rule %q is not cidr=service:team", part)
		}
		pfx, err := netip.ParsePrefix(strings.TrimSpace(kv[0]))
		if err != nil {
			return nil, fmt.Errorf("cost: owner rule %q: %w", part, err)
		}
		svc, team, _ := strings.Cut(strings.TrimSpace(kv[1]), ":")
		if svc == "" {
			return nil, fmt.Errorf("cost: owner rule %q has no service", part)
		}
		out = append(out, OwnerRule{Prefix: pfx, Service: svc, Team: team})
	}
	return out, nil
}

// regionOfZone derives "us-east-1" from "us-east-1a" (the common cloud
// convention: a single trailing zone letter). Zones that don't follow it
// should declare the region explicitly (zone/region).
func regionOfZone(zone string) string {
	if len(zone) > 1 {
		last := zone[len(zone)-1]
		if last >= 'a' && last <= 'z' {
			return zone[:len(zone)-1]
		}
	}
	return zone
}

// Mapper resolves addresses to zones and owners (longest-prefix match).
type Mapper struct {
	zones  []ZoneRule
	owners []OwnerRule
}

// NewMapper builds a mapper; both rule sets may be empty (degraded modes).
func NewMapper(zones []ZoneRule, owners []OwnerRule) *Mapper {
	z := append([]ZoneRule(nil), zones...)
	o := append([]OwnerRule(nil), owners...)
	// Longest prefix first so the first match wins.
	sort.Slice(z, func(i, j int) bool { return z[i].Prefix.Bits() > z[j].Prefix.Bits() })
	sort.Slice(o, func(i, j int) bool { return o[i].Prefix.Bits() > o[j].Prefix.Bits() })
	return &Mapper{zones: z, owners: o}
}

// ZonesConfigured reports whether any zone rules exist (honesty flag).
func (m *Mapper) ZonesConfigured() bool { return len(m.zones) > 0 }

// Zone resolves addr to (zone, region); ok=false when unmapped.
func (m *Mapper) Zone(addr string) (zone, region string, ok bool) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return "", "", false
	}
	for _, r := range m.zones {
		if r.Prefix.Contains(ip) {
			return r.Zone, r.Region, true
		}
	}
	return "", "", false
}

// Owner resolves addr to (service, team); service "" when unmapped.
func (m *Mapper) Owner(addr string) (service, team string) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return "", ""
	}
	for _, r := range m.owners {
		if r.Prefix.Contains(ip) {
			return r.Service, r.Team
		}
	}
	return "", ""
}

// Classify determines the traffic class for src→dst.
func (m *Mapper) Classify(src, dst string) TrafficClass {
	sZone, sRegion, sOK := m.Zone(src)
	dZone, dRegion, dOK := m.Zone(dst)
	switch {
	case sOK && dOK && sZone == dZone:
		return ClassSameZone
	case sOK && dOK && sRegion == dRegion:
		return ClassInterAZ
	case sOK && dOK:
		return ClassInterRegion
	case sOK && !dOK && !isPrivate(dst):
		return ClassInternet
	default:
		return ClassUnknown
	}
}

func isPrivate(addr string) bool {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func splitList(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
