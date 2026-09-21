// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package topology

import (
	"encoding/base64"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxIdentityClaimSets                    = 1024
	maxIdentityClaimsPerSet                 = 8
	maxIdentityTextRunes                    = 512
	maxIdentityInterfaceAddrsPerObservation = 64
)

// IdentityConflictKind names the identity field whose competing values cannot
// both be authoritative for the same subject.
type IdentityConflictKind string

const (
	IdentityManagementAddress IdentityConflictKind = "management_address"
	IdentityDeviceName        IdentityConflictKind = "device_name"
	IdentityInterfaceAddress  IdentityConflictKind = "interface_address"
	IdentityInterfaceName     IdentityConflictKind = "interface_name"
	IdentityInterfaceIndex    IdentityConflictKind = "interface_index"
)

// IdentityClaim is one bounded, normalized device-identity assertion. It
// deliberately excludes raw telemetry and credentials.
type IdentityClaim struct {
	Value     string    `json:"value"`
	Source    string    `json:"source"`
	AgentID   string    `json:"agent_id,omitempty"`
	Basis     string    `json:"basis"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// IdentityConflict is a stable read-only disagreement record derived from two
// or more distinct values asserted for the same tenant-local identity key.
type IdentityConflict struct {
	ID        string               `json:"id"`
	Kind      IdentityConflictKind `json:"kind"`
	Subject   string               `json:"subject"`
	Claims    []IdentityClaim      `json:"claims"`
	FirstSeen time.Time            `json:"first_seen"`
	LastSeen  time.Time            `json:"last_seen"`
}

// IdentityConflictSnapshot is the bounded store-owned conflict read model.
// Truncated means claim-set or per-set eviction occurred before this read.
type IdentityConflictSnapshot struct {
	Items     []IdentityConflict
	At        time.Time
	Truncated bool
}

type identityClaimSet struct {
	kind     IdentityConflictKind
	subject  string
	claims   map[string]*IdentityClaim
	lastSeen time.Time
}

func identityClaimKey(kind IdentityConflictKind, subject string) string {
	return string(kind) + "\x00" + strings.ToLower(strings.TrimSpace(subject))
}

func identityClaimOrigin(claim IdentityClaim) string {
	return strings.ToLower(claim.Source) + "\x00" + claim.AgentID + "\x00" + strings.ToLower(claim.Value)
}

func identityConflictID(kind IdentityConflictKind, subject string) string {
	token := base64.RawURLEncoding.EncodeToString([]byte(strings.ToLower(strings.TrimSpace(subject))))
	return "identity:" + string(kind) + ":" + token
}

// recordIdentityClaim records one normalized assertion. Caller does not hold
// g.mu; the identity store shares the graph's tenant-owned lock.
func (g *Graph) recordIdentityClaim(
	kind IdentityConflictKind,
	subject, value, source, agentID, basis string,
	at time.Time,
) {
	subject = boundedIdentityText(subject)
	value = boundedIdentityText(value)
	if subject == "" || value == "" {
		return
	}
	source = strings.ToLower(boundedIdentityText(source))
	if source == "" {
		source = "device"
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	claim := IdentityClaim{
		Value: value, Source: source, AgentID: boundedIdentityText(agentID),
		Basis: boundedIdentityText(basis), FirstSeen: at, LastSeen: at,
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	key := identityClaimKey(kind, subject)
	set, ok := g.identityClaims[key]
	if !ok {
		if len(g.identityClaims) >= maxIdentityClaimSets {
			g.evictOldestIdentityClaimSetLocked()
			g.identityClaimsTruncated = true
		}
		set = &identityClaimSet{
			kind: kind, subject: subject, claims: map[string]*IdentityClaim{}, lastSeen: at,
		}
		g.identityClaims[key] = set
	}
	origin := identityClaimOrigin(claim)
	if current, exists := set.claims[origin]; exists {
		if at.Before(current.FirstSeen) {
			current.FirstSeen = at
		}
		if at.After(current.LastSeen) {
			current.LastSeen = at
		}
	} else {
		if len(set.claims) >= maxIdentityClaimsPerSet {
			evictOldestIdentityClaimLocked(set)
			g.identityClaimsTruncated = true
		}
		set.claims[origin] = &claim
	}
	if at.After(set.lastSeen) {
		set.lastSeen = at
	}
}

func boundedIdentityText(value string) string {
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(runes) > maxIdentityTextRunes {
		runes = runes[:maxIdentityTextRunes]
	}
	return string(runes)
}

func (g *Graph) markIdentityClaimsTruncated() {
	g.mu.Lock()
	g.identityClaimsTruncated = true
	g.mu.Unlock()
}

func (g *Graph) evictOldestIdentityClaimSetLocked() {
	var oldestKey string
	var oldest time.Time
	for key, set := range g.identityClaims {
		if oldestKey == "" || set.lastSeen.Before(oldest) ||
			(set.lastSeen.Equal(oldest) && key < oldestKey) {
			oldestKey, oldest = key, set.lastSeen
		}
	}
	if oldestKey != "" {
		delete(g.identityClaims, oldestKey)
	}
}

func evictOldestIdentityClaimLocked(set *identityClaimSet) {
	var oldestKey string
	var oldest time.Time
	for key, claim := range set.claims {
		if oldestKey == "" || claim.LastSeen.Before(oldest) ||
			(claim.LastSeen.Equal(oldest) && key < oldestKey) {
			oldestKey, oldest = key, claim.LastSeen
		}
	}
	if oldestKey != "" {
		delete(set.claims, oldestKey)
	}
}

// IdentityConflicts returns only claim sets containing at least two distinct
// values. Source duplicates for the same value remain available as provenance
// but cannot manufacture a conflict.
func (g *Graph) IdentityConflicts() IdentityConflictSnapshot {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := IdentityConflictSnapshot{Truncated: g.identityClaimsTruncated}
	for _, set := range g.identityClaims {
		values := map[string]struct{}{}
		claims := make([]IdentityClaim, 0, len(set.claims))
		var first, last time.Time
		for _, claim := range set.claims {
			claims = append(claims, *claim)
			values[strings.ToLower(claim.Value)] = struct{}{}
			if first.IsZero() || claim.FirstSeen.Before(first) {
				first = claim.FirstSeen
			}
			if claim.LastSeen.After(last) {
				last = claim.LastSeen
			}
		}
		if len(values) < 2 {
			continue
		}
		sort.Slice(claims, func(i, j int) bool {
			if !claims[i].LastSeen.Equal(claims[j].LastSeen) {
				return claims[i].LastSeen.After(claims[j].LastSeen)
			}
			if claims[i].Value != claims[j].Value {
				return claims[i].Value < claims[j].Value
			}
			if claims[i].Source != claims[j].Source {
				return claims[i].Source < claims[j].Source
			}
			return claims[i].AgentID < claims[j].AgentID
		})
		out.Items = append(out.Items, IdentityConflict{
			ID: identityConflictID(set.kind, set.subject), Kind: set.kind,
			Subject: set.subject, Claims: claims, FirstSeen: first, LastSeen: last,
		})
		if last.After(out.At) {
			out.At = last
		}
	}
	sort.Slice(out.Items, func(i, j int) bool {
		if !out.Items[i].LastSeen.Equal(out.Items[j].LastSeen) {
			return out.Items[i].LastSeen.After(out.Items[j].LastSeen)
		}
		return out.Items[i].ID < out.Items[j].ID
	})
	return out
}

func (g *Graph) pruneIdentityClaimsBeforeLocked(cutoff time.Time) int {
	deleted := 0
	for key, set := range g.identityClaims {
		for origin, claim := range set.claims {
			if claim.LastSeen.Before(cutoff) {
				delete(set.claims, origin)
				deleted++
			}
		}
		if len(set.claims) == 0 {
			delete(g.identityClaims, key)
			continue
		}
		set.lastSeen = time.Time{}
		for _, claim := range set.claims {
			if claim.LastSeen.After(set.lastSeen) {
				set.lastSeen = claim.LastSeen
			}
		}
	}
	return deleted
}

func observeDeviceIdentity(g *Graph, in DeviceInput, at time.Time) {
	source := strings.TrimSpace(in.Source)
	if source == "" {
		source = "device"
	}
	if in.Address != "" && in.Name != "" {
		g.recordIdentityClaim(
			IdentityDeviceName, in.Address, in.Name, source, in.AgentID,
			"device.metric.device_name", at,
		)
		g.recordIdentityClaim(
			IdentityManagementAddress, in.Name, in.Address, source, in.AgentID,
			"device.metric.device_address", at,
		)
	}
	if in.Address != "" && in.IfIndex != 0 && in.IfName != "" {
		g.recordIdentityClaim(
			IdentityInterfaceName,
			in.Address+"@"+strconv.FormatUint(uint64(in.IfIndex), 10),
			in.IfName, source, in.AgentID, "device.metric.interface_name", at,
		)
		g.recordIdentityClaim(
			IdentityInterfaceIndex,
			in.Address+"@"+in.IfName,
			strconv.FormatUint(uint64(in.IfIndex), 10),
			source, in.AgentID, "device.metric.interface_index", at,
		)
	}
	interfaceIPs := in.InterfaceIPs
	if len(interfaceIPs) > maxIdentityInterfaceAddrsPerObservation {
		interfaceIPs = interfaceIPs[:maxIdentityInterfaceAddrsPerObservation]
		g.markIdentityClaimsTruncated()
	}
	for _, address := range interfaceIPs {
		if strings.TrimSpace(address) == "" || strings.TrimSpace(in.Address) == "" {
			continue
		}
		g.recordIdentityClaim(
			IdentityInterfaceAddress, address, in.Address, source, in.AgentID,
			"device.inventory.interface_address", at,
		)
	}
}
