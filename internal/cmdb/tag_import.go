// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cmdb

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

var ErrNoTagCandidate = errors.New("cmdb: no unambiguous importable tag value")

// NetBoxTagCandidate is source metadata, never entity or sender identity.
// Its exact fields must be freshly rechecked after operator confirmation.
type NetBoxTagCandidate struct {
	NetBoxTenantID string `json:"netbox_tenant_id"`
	LookupCIID     string `json:"lookup_ci_id"`
	CIID           string `json:"ci_id"`
	Name           string `json:"name"`
	Field          string `json:"field"`
	Value          string `json:"value"`
	SourceRef      string `json:"source_ref"`
}

func compactNetBoxCIRef(ci CI) (string, error) {
	for prefix, code := range map[string]string{
		"netbox:ipam.ip_address:": "ip", "netbox:dcim.device:": "d",
		"netbox:virtualization.virtual_machine:": "vm",
		"netbox:ipam.prefix:":                    "p",
	} {
		if raw, ok := strings.CutPrefix(ci.SysID, prefix); ok {
			id, err := strconv.ParseInt(raw, 10, 64)
			if err == nil && id > 0 && strconv.FormatInt(id, 10) == raw {
				return code + raw, nil
			}
		}
	}
	return "", ErrTenantBinding
}

// A brief IP relation cannot authorize role/site metadata. Read its exact CI
// ID through a tenant-filtered list endpoint and attest that full CI again.
func (n *NetBox) relatedTagCI(ctx context.Context, source, kind string, id int64) (CI, error) {
	path, prefix, class := "", "", ""
	switch kind {
	case "device":
		path, prefix, class = "/api/dcim/devices/", "netbox:dcim.device:", "netbox.device"
	case "vm":
		path, prefix, class = "/api/virtualization/virtual-machines/", "netbox:virtualization.virtual_machine:", "netbox.virtual_machine"
	default:
		return CI{}, ErrNoTagCandidate
	}
	if id <= 0 {
		return CI{}, ErrNoTagCandidate
	}
	q := url.Values{"tenant_id": {source}, "id": {strconv.FormatInt(id, 10)}, "limit": {"2"}}
	var page struct {
		Count   int    `json:"count"`
		Next    string `json:"next"`
		Results []struct {
			ID     int64              `json:"id"`
			Tenant *netBoxTenant      `json:"tenant"`
			Name   string             `json:"name"`
			Role   netBoxTagAttribute `json:"role"`
			Site   netBoxTagAttribute `json:"site"`
		} `json:"results"`
	}
	if err := n.get(ctx, path+"?"+q.Encode(), &page); err != nil {
		return CI{}, err
	}
	if page.Next != "" || page.Count != 1 || len(page.Results) != 1 {
		return CI{}, ErrNoTagCandidate
	}
	row := page.Results[0]
	if row.ID != id || !row.Tenant.matches(source) {
		return CI{}, ErrTenantBinding
	}
	return CI{SysID: prefix + strconv.FormatInt(id, 10), Name: row.Name, FQDN: CanonicalKey(row.Name),
		Class: class, Extra: compactExtra(map[string]string{"role": row.Role.Name, "site": row.Site.Name,
			"role_id": strconv.FormatInt(row.Role.ID, 10), "site_id": strconv.FormatInt(row.Site.ID, 10)})}, nil
}
