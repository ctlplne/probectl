// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cmdb

import (
	"context"
	"net/netip"
	"net/url"
	"strconv"

	"github.com/ctlplne/probectl/internal/tags"
)

type netBoxTagAttribute struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

func (n *NetBox) tagIPByID(ctx context.Context, source, id string) (CI, error) {
	q := url.Values{"tenant_id": {source}, "id": {id}, "limit": {"2"}}
	var page struct {
		Count   int    `json:"count"`
		Next    string `json:"next"`
		Results []struct {
			ID             int64         `json:"id"`
			Tenant         *netBoxTenant `json:"tenant"`
			Address        string        `json:"address"`
			DNSName        string        `json:"dns_name"`
			AssignedObject struct {
				Device struct {
					ID     int64         `json:"id"`
					Tenant *netBoxTenant `json:"tenant"`
				} `json:"device"`
				VM struct {
					ID     int64         `json:"id"`
					Tenant *netBoxTenant `json:"tenant"`
				} `json:"virtual_machine"`
			} `json:"assigned_object"`
		} `json:"results"`
	}
	if err := n.get(ctx, "/api/ipam/ip-addresses/?"+q.Encode(), &page); err != nil {
		return CI{}, err
	}
	if page.Next != "" || page.Count != 1 || len(page.Results) != 1 {
		return CI{}, ErrNoTagCandidate
	}
	row := page.Results[0]
	if row.ID <= 0 || strconv.FormatInt(row.ID, 10) != id || !row.Tenant.matches(source) {
		return CI{}, ErrTenantBinding
	}
	address, err := netip.ParsePrefix(row.Address)
	if err != nil || address.Addr().Zone() != "" {
		return CI{}, ErrTenantBinding
	}
	device, vm := row.AssignedObject.Device, row.AssignedObject.VM
	if device.ID < 0 || vm.ID < 0 || (device.ID > 0 && vm.ID > 0) ||
		(device.Tenant != nil && !device.Tenant.matches(source)) || (vm.Tenant != nil && !vm.Tenant.matches(source)) {
		return CI{}, ErrTenantBinding
	}
	kind, related := "", int64(0)
	if device.ID > 0 {
		kind, related = "device", device.ID
	} else if vm.ID > 0 {
		kind, related = "vm", vm.ID
	}
	return CI{SysID: "netbox:ipam.ip_address:" + id, Class: "netbox.ip_address", IPAddress: address.Addr().Unmap().String(),
		FQDN: CanonicalKey(row.DNSName), relatedKind: kind, relatedID: related}, nil
}

// Prefixes have their own tenant and IPAM role. A site value comes only from
// an ID-consistent dcim.site scope; no first-host or legacy-site inference.
func (n *NetBox) prefixTagSelection(ctx context.Context, source string, prefix netip.Prefix, field, id string) (NetBoxTagSelection, error) {
	if prefix != prefix.Masked() || prefix.Addr().Is4In6() {
		return NetBoxTagSelection{}, ErrNoTagCandidate
	}
	q := url.Values{"tenant_id": {source}, "prefix": {prefix.String()}, "limit": {"2"}}
	if id != "" {
		q.Set("id", id)
	}
	var page struct {
		Count   int               `json:"count"`
		Next    string            `json:"next"`
		Results []netBoxTagPrefix `json:"results"`
	}
	if err := n.get(ctx, "/api/ipam/prefixes/?"+q.Encode(), &page); err != nil {
		return NetBoxTagSelection{}, err
	}
	if page.Next != "" || page.Count != 1 || len(page.Results) != 1 {
		return NetBoxTagSelection{}, ErrNoTagCandidate
	}
	row := page.Results[0]
	actual, err := netip.ParsePrefix(row.Prefix)
	if err != nil || actual != prefix || row.ID <= 0 || !row.Tenant.matches(source) || (id != "" && strconv.FormatInt(row.ID, 10) != id) {
		return NetBoxTagSelection{}, ErrTenantBinding
	}
	value, binding, err := row.tagAttribute(field)
	if err != nil {
		return NetBoxTagSelection{}, err
	}
	id = strconv.FormatInt(row.ID, 10)
	ciID := "netbox:ipam.prefix:" + id
	return NetBoxTagSelection{prefix: prefix, candidate: NetBoxTagCandidate{NetBoxTenantID: source,
		LookupCIID: ciID, CIID: ciID, Name: prefix.String(), Field: field, Value: value,
		SourceRef: "netbox:t" + source + ":p" + id + ":" + binding + ":" + field}}, nil
}

type netBoxTagPrefix struct {
	ID     int64         `json:"id"`
	Tenant *netBoxTenant `json:"tenant"`
	Prefix string        `json:"prefix"`
	VRF    *struct {
		ID int64 `json:"id"`
	} `json:"vrf"`
	Role      *netBoxTagAttribute `json:"role"`
	ScopeType string              `json:"scope_type"`
	ScopeID   *int64              `json:"scope_id"`
	Scope     *netBoxTagAttribute `json:"scope"`
}

func (p netBoxTagPrefix) tagAttribute(field string) (string, string, error) {
	vrf, role, scope := int64(0), int64(0), int64(0)
	if p.VRF != nil {
		if p.VRF.ID <= 0 {
			return "", "", ErrTenantBinding
		}
		vrf = p.VRF.ID
	}
	if p.Role != nil {
		if p.Role.ID <= 0 {
			return "", "", ErrTenantBinding
		}
		role = p.Role.ID
	}
	if p.ScopeType == "" {
		if p.ScopeID != nil || p.Scope != nil {
			return "", "", ErrTenantBinding
		}
	} else {
		switch p.ScopeType {
		case "dcim.site", "dcim.sitegroup", "dcim.region", "dcim.location":
		default:
			return "", "", ErrNoTagCandidate
		}
		if p.ScopeID == nil || *p.ScopeID <= 0 || p.Scope == nil || p.Scope.ID != *p.ScopeID {
			return "", "", ErrTenantBinding
		}
		scope = *p.ScopeID
	}
	value := ""
	if field == "role" && p.Role != nil {
		value = p.Role.Name
	}
	if field == "site" && p.ScopeType == "dcim.site" {
		value = p.Scope.Name
	}
	if tags.ValidateValue(value) != nil {
		return "", "", ErrNoTagCandidate
	}
	scopeCode := map[string]string{"": "n", "dcim.site": "s", "dcim.sitegroup": "g", "dcim.region": "r", "dcim.location": "l"}[p.ScopeType]
	binding := "v" + strconv.FormatInt(vrf, 10) + ":" + scopeCode + strconv.FormatInt(scope, 10) + ":r" + strconv.FormatInt(role, 10)
	return value, binding, nil
}
