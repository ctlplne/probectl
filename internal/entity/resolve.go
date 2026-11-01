// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package entity defines the tenant- and routing-context-bound identity
// vocabulary. Authoritative candidates come from the FORCE-RLS registry;
// untrusted observations never choose a canonical entity on their own.
package entity

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

var (
	ErrInvalidScope        = errors.New("entity: invalid tenant or routing context")
	ErrInvalidAlias        = errors.New("entity: invalid alias")
	ErrInvalidPage         = errors.New("entity: invalid page cursor or limit")
	ErrInvalidClaim        = errors.New("entity: invalid evidence claim")
	ErrScopeMismatch       = errors.New("entity: evidence outside resolution scope")
	ErrAliasMismatch       = errors.New("entity: evidence for another alias")
	ErrConflictingEvidence = errors.New("entity: observation ID reused for different evidence")
)

// Scope identifies one tenant and one server-configured site/VRF routing
// context. An absent context is not a wildcard for an address lookup.
type Scope struct {
	TenantID  string `json:"tenant_id"`
	ContextID string `json:"context_id"`
}

func (s Scope) Normalize() (Scope, error) {
	tenant, err := uuid.Parse(s.TenantID)
	if err != nil || tenant == uuid.Nil {
		return Scope{}, ErrInvalidScope
	}
	contextID, err := uuid.Parse(s.ContextID)
	if err != nil || contextID == uuid.Nil {
		return Scope{}, ErrInvalidScope
	}
	return Scope{TenantID: tenant.String(), ContextID: contextID.String()}, nil
}

// Kind is a canonical registry node type, not an untrusted device claim.
type Kind string

const (
	Device    Kind = "device"
	Interface Kind = "interface"
	Address   Kind = "address"
	Prefix    Kind = "prefix"
	Service   Kind = "service"
	Site      Kind = "site"
	Customer  Kind = "customer"
)

func (k Kind) valid() bool {
	switch k {
	case Device, Interface, Address, Prefix, Service, Site, Customer:
		return true
	default:
		return false
	}
}

// AliasKind keeps a source identity typed. Only AddressAlias and PrefixAlias
// compare values across planes; a source-local ID cannot collide with an ID
// from a different collector family.
type AliasKind string

const (
	AddressAlias          AliasKind = "address"
	PrefixAlias           AliasKind = "prefix"
	SNMPDeviceAlias       AliasKind = "snmp_device_id"
	SNMPInterfaceAlias    AliasKind = "snmp_interface_id"
	PhysicalNeighborAlias AliasKind = "physical_neighbor_id"
	FlowExporterAlias     AliasKind = "flow_exporter_id"
	BMPPeerAlias          AliasKind = "bmp_peer_id"
	PathHopAlias          AliasKind = "path_hop_id"
	AgentSiteAlias        AliasKind = "agent_site_id"
	SiteAlias             AliasKind = "site_key"
	CustomerAlias         AliasKind = "customer_key"
	ServiceAlias          AliasKind = "service_key"
)

type AliasKey struct {
	Kind  AliasKind `json:"kind"`
	Value string    `json:"value"`
}

func (a AliasKey) Normalize() (AliasKey, error) {
	value := strings.TrimSpace(a.Value)
	if value == "" || len(value) > 1024 {
		return AliasKey{}, ErrInvalidAlias
	}
	switch a.Kind {
	case AddressAlias:
		addr, err := netip.ParseAddr(value)
		if err != nil || addr.Zone() != "" {
			return AliasKey{}, ErrInvalidAlias
		}
		value = addr.Unmap().String()
	case PrefixAlias:
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Zone() != "" {
			return AliasKey{}, ErrInvalidAlias
		}
		value = prefix.Masked().String()
	case SNMPInterfaceAlias:
		index, err := strconv.ParseUint(value, 10, 32)
		if err != nil || index == 0 || strconv.FormatUint(index, 10) != value {
			return AliasKey{}, ErrInvalidAlias
		}
	case SNMPDeviceAlias, PhysicalNeighborAlias, FlowExporterAlias,
		BMPPeerAlias, PathHopAlias, AgentSiteAlias, SiteAlias,
		CustomerAlias, ServiceAlias:
		if strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return AliasKey{}, ErrInvalidAlias
		}
	default:
		return AliasKey{}, ErrInvalidAlias
	}
	return AliasKey{Kind: a.Kind, Value: value}, nil
}

// Claim points to one durable, tenant-owned evidence row. The caller must
// obtain it from the scoped registry transaction, not from a packet payload.
type Claim struct {
	Scope             Scope     `json:"scope"`
	Alias             AliasKey  `json:"alias"`
	EntityID          string    `json:"entity_id"`
	EntityKind        Kind      `json:"entity_kind"`
	EvidenceID        string    `json:"evidence_id"`
	SupportEvidenceID string    `json:"support_evidence_id,omitempty"`
	Source            string    `json:"source"`
	SourceRef         string    `json:"source_ref"`
	SourceKey         SourceKey `json:"source_key"`
	ObservedAt        time.Time `json:"observed_at"`
}

// Record is the durable canonical node. Its label is tenant data and must be
// authorized for the caller before a REST, CLI, UI or MCP surface exposes it.
type Record struct {
	Scope     Scope     `json:"scope"`
	ID        string    `json:"id"`
	Kind      Kind      `json:"kind"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Page is a bounded, context-scoped walk over durable canonical records.
// NextCursor is the last returned UUID, not a tenant or routing-context hint.
type Page struct {
	Scope      Scope    `json:"scope"`
	Items      []Record `json:"items"`
	NextCursor string   `json:"next_cursor,omitempty"`
}

type Status string

const (
	Unresolved Status = "unresolved"
	Resolved   Status = "resolved"
	Conflict   Status = "conflict"
)

// Resolution never exposes a selected entity when evidence is ambiguous.
type Resolution struct {
	Scope          Scope    `json:"scope"`
	Alias          AliasKey `json:"alias"`
	Status         Status   `json:"status"`
	EntityID       string   `json:"entity_id,omitempty"`
	Candidates     []Claim  `json:"candidates,omitempty"`
	MoreCandidates bool     `json:"more_candidates"`
}

// Resolve classifies already-scoped durable claims. It refuses even one
// foreign-scope or mismatched-alias row rather than hiding it in a result.
// Storage must additionally enforce tenant_id and context_id with FORCE RLS
// and composite keys (docs/guardrails.md G7-1).
func Resolve(scope Scope, alias AliasKey, claims []Claim) (Resolution, error) {
	wantScope, err := scope.Normalize()
	if err != nil {
		return Resolution{}, err
	}
	wantAlias, err := alias.Normalize()
	if err != nil {
		return Resolution{}, err
	}
	result := Resolution{Scope: wantScope, Alias: wantAlias, Status: Unresolved}
	entities := make(map[string]struct{})
	evidenceOwners := make(map[string]string)
	for _, claim := range claims {
		gotScope, err := claim.Scope.Normalize()
		if err != nil {
			return Resolution{}, ErrInvalidClaim
		}
		if gotScope != wantScope {
			return Resolution{}, ErrScopeMismatch
		}
		gotAlias, err := claim.Alias.Normalize()
		if err != nil {
			return Resolution{}, ErrInvalidClaim
		}
		if gotAlias != wantAlias {
			return Resolution{}, ErrAliasMismatch
		}
		entityID, err := uuid.Parse(claim.EntityID)
		if err != nil || entityID == uuid.Nil || !claim.EntityKind.valid() {
			return Resolution{}, ErrInvalidClaim
		}
		evidenceID, err := uuid.Parse(claim.EvidenceID)
		if err != nil || evidenceID == uuid.Nil || claim.ObservedAt.IsZero() {
			return Resolution{}, ErrInvalidClaim
		}
		if claim.SupportEvidenceID != "" {
			supportID, err := uuid.Parse(claim.SupportEvidenceID)
			if err != nil || supportID == uuid.Nil ||
				(claim.SourceKey.Kind != FlowExporter && claim.SourceKey.Kind != BMPPeer) {
				return Resolution{}, ErrInvalidClaim
			}
			claim.SupportEvidenceID = supportID.String()
		}
		source := strings.TrimSpace(claim.Source)
		if source == "" || len(source) > 128 || strings.IndexFunc(source, unicode.IsControl) >= 0 {
			return Resolution{}, ErrInvalidClaim
		}
		sourceRef := strings.TrimSpace(claim.SourceRef)
		if sourceRef == "" || len(sourceRef) > 1024 || strings.IndexFunc(sourceRef, unicode.IsControl) >= 0 {
			return Resolution{}, ErrInvalidClaim
		}
		sourceKey, err := claim.SourceKey.Normalize()
		if err != nil {
			return Resolution{}, ErrInvalidClaim
		}
		if owner, exists := evidenceOwners[evidenceID.String()]; exists && owner != entityID.String() {
			return Resolution{}, ErrConflictingEvidence
		}
		evidenceOwners[evidenceID.String()] = entityID.String()
		claim.Scope, claim.Alias = gotScope, gotAlias
		claim.EntityID, claim.EvidenceID = entityID.String(), evidenceID.String()
		claim.Source = source
		claim.SourceRef = sourceRef
		claim.SourceKey = sourceKey
		claim.ObservedAt = claim.ObservedAt.UTC()
		result.Candidates = append(result.Candidates, claim)
		entities[entityID.String()] = struct{}{}
	}
	sort.Slice(result.Candidates, func(i, j int) bool {
		a, b := result.Candidates[i], result.Candidates[j]
		if a.EntityID != b.EntityID {
			return a.EntityID < b.EntityID
		}
		return a.EvidenceID < b.EvidenceID
	})
	switch len(entities) {
	case 0:
		return result, nil
	case 1:
		for id := range entities {
			result.EntityID = id
		}
		result.Status = Resolved
	default:
		result.Status = Conflict
	}
	return result, nil
}

// ValidateKind is used at the storage/API seams before a row is written.
func ValidateKind(kind Kind) error {
	if !kind.valid() {
		return fmt.Errorf("%w: unknown entity kind", ErrInvalidClaim)
	}
	return nil
}
