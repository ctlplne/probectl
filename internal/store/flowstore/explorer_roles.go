// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrInterfaceRoleQueryScope = errors.New("flow interface role lookup is not bound to current tenant inputs")

// InterfaceRoleProjection is server-selected current metadata. The caller
// first proves a unique tenant-wide exporter owner, current source identity,
// same-router canonical interface and current context/source read authority.
// This value is never accepted from query grammar or retained as a grant.
type InterfaceRoleProjection struct {
	entity.Scope
	RouterID    string               `json:"router_id"`
	InterfaceID string               `json:"interface_id"`
	Exporter    string               `json:"exporter"`
	Protocol    string               `json:"protocol"`
	Domain      uint32               `json:"obs_domain"`
	IfIndex     uint32               `json:"if_index"`
	Role        entity.InterfaceRole `json:"role"`
	Reason      string               `json:"reason"`
	Sources     []string             `json:"sources"`
	ValidUntil  time.Time            `json:"valid_until"`
}

type interfaceRoleQueryKey struct {
	exporter, protocol string
	domain, index      uint32
}

// InterfaceRoleQueryData is an immutable request-local projection. Raw AgentID
// is deliberately absent from the key: it cannot select a routing context.
// Missing/ambiguous metadata is Other, preserving every matching flow row.
type InterfaceRoleQueryData struct {
	tenantID string
	asOf     time.Time
	rows     []InterfaceRoleProjection
	byKey    map[interfaceRoleQueryKey]int
	digest   string
}

func NewInterfaceRoleQueryData(ctx context.Context, tenant string, asOf time.Time, rows []InterfaceRoleProjection, maxBytes int64) (*InterfaceRoleQueryData, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id, present := tenancy.FromContext(ctx)
	if !present || id.String() != tenant || !validTagProjectionID(tenant) || asOf.IsZero() {
		return nil, ErrInterfaceRoleQueryScope
	}
	if maxBytes < 4096 || int64(len(rows)) > (maxBytes-4096)/1024 {
		return nil, ErrExplorerBudget
	}
	out := &InterfaceRoleQueryData{tenantID: tenant, asOf: asOf.UTC(), byKey: make(map[interfaceRoleQueryKey]int, len(rows))}
	used := int64(4096)
	// All protocols/domains of an exporter must agree on context/router.
	// A later caller cannot prune competing assignments into unique ownership.
	owners := map[string]struct{ context, router string }{}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		scope, err := row.Scope.Normalize()
		address, addressErr := netip.ParseAddr(row.Exporter)
		if err != nil || scope != row.Scope || scope.TenantID != tenant || !validTagProjectionID(row.RouterID) || !validTagProjectionID(row.InterfaceID) ||
			addressErr != nil || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || address.String() != row.Exporter ||
			row.IfIndex == 0 || !row.ValidUntil.After(asOf) || row.Reason == "" || strings.TrimSpace(row.Reason) != row.Reason || !validInterfaceRoleProjection(row.Role) {
			return nil, ErrInterfaceRoleQueryScope
		}
		switch row.Protocol {
		case "netflow5", "netflow9", "ipfix", "sflow5":
		default:
			return nil, ErrInterfaceRoleQueryScope
		}
		owner := struct{ context, router string }{scope.ContextID, row.RouterID}
		if previous, exists := owners[row.Exporter]; exists && previous != owner {
			return nil, ErrInterfaceRoleQueryScope
		}
		owners[row.Exporter] = owner
		// JSON escaping can expand each input byte. Reserve both encoded and
		// decoded copies before allocating the complete publication payload.
		used += 2048 + 12*int64(len(row.Exporter)+len(row.Protocol)+len(row.Reason))
		if used > maxBytes {
			return nil, ErrExplorerBudget
		}
		for _, source := range row.Sources {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			used += 256 + 12*int64(len(source))
			if used > maxBytes {
				return nil, ErrExplorerBudget
			}
			if source == "" || strings.TrimSpace(source) != source || strings.ContainsAny(source, "\x00\r\n") {
				return nil, ErrInterfaceRoleQueryScope
			}
		}
		if len(row.Sources) == 0 {
			return nil, ErrInterfaceRoleQueryScope
		}
		row.Sources = slices.Clone(row.Sources)
		slices.Sort(row.Sources)
		row.Sources = slices.Compact(row.Sources)
		out.rows = append(out.rows, row)
	}
	slices.SortFunc(out.rows, compareInterfaceRoleProjection)
	for i, row := range out.rows {
		key := interfaceRoleQueryKey{row.Exporter, row.Protocol, row.Domain, row.IfIndex}
		if _, exists := out.byKey[key]; exists {
			return nil, ErrInterfaceRoleQueryScope
		}
		out.byKey[key] = i
	}
	// The source/configuration identity is stable across collection order and
	// wall-clock advances. Current authorization is revalidated separately.
	body, err := json.Marshal(struct {
		Tenant string                    `json:"tenant_id"`
		Rows   []InterfaceRoleProjection `json:"rows"`
	}{tenant, out.rows})
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > used {
		return nil, ErrExplorerBudget
	}
	out.digest = hex.EncodeToString(crypto.Hash(body))
	return out, nil
}

func validInterfaceRoleProjection(role entity.InterfaceRole) bool {
	switch role {
	case entity.InterfaceRoleTransit, entity.InterfaceRoleIX, entity.InterfaceRolePrivate, entity.InterfaceRoleCustomer, entity.InterfaceRoleBackbone, entity.InterfaceRoleOther:
		return true
	default:
		return false
	}
}

func compareInterfaceRoleProjection(a, b InterfaceRoleProjection) int {
	if n := strings.Compare(a.Exporter, b.Exporter); n != 0 {
		return n
	}
	if n := strings.Compare(a.Protocol, b.Protocol); n != 0 {
		return n
	}
	if a.Domain < b.Domain {
		return -1
	}
	if a.Domain > b.Domain {
		return 1
	}
	if a.IfIndex < b.IfIndex {
		return -1
	}
	if a.IfIndex > b.IfIndex {
		return 1
	}
	return 0
}

func (d *InterfaceRoleQueryData) validate(ctx context.Context, tenant string, now time.Time) error {
	id, present := tenancy.FromContext(ctx)
	if d == nil || !present || tenant != id.String() || tenant != d.tenantID || now.Before(d.asOf) {
		return ErrInterfaceRoleQueryScope
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, row := range d.rows {
		if !row.ValidUntil.After(now) {
			return ErrInterfaceRoleQueryScope
		}
	}
	return nil
}

func (d *InterfaceRoleQueryData) Digest(ctx context.Context, tenant string, now time.Time) (string, error) {
	if err := d.validate(ctx, tenant, now); err != nil {
		return "", err
	}
	return d.digest, nil
}

func (d *InterfaceRoleQueryData) valueForRow(row Row, output bool) string {
	if d == nil || row.TenantID != d.tenantID {
		return string(entity.InterfaceRoleOther)
	}
	address, err := netip.ParseAddr(row.Exporter)
	if err != nil || address.Zone() != "" {
		return string(entity.InterfaceRoleOther)
	}
	index := row.InIf
	if output {
		index = row.OutIf
	}
	if found, exists := d.byKey[interfaceRoleQueryKey{address.Unmap().String(), row.Protocol, row.ObsDomain, index}]; exists {
		return string(d.rows[found].Role)
	}
	return string(entity.InterfaceRoleOther)
}
