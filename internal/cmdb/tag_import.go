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
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/tags"
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

// PreviewNetBoxTag bypasses enrichment caches. The caller must resolve key
// from an owned canonical target before invoking this read-only source path.
func (r *Resolver) PreviewNetBoxTag(ctx context.Context, key, field string) (candidate NetBoxTagCandidate, err error) {
	if r == nil || (field != "role" && field != "site") {
		return NetBoxTagCandidate{}, ErrNoTagCandidate
	}
	provider, ok := r.provider.(*NetBox)
	if !ok {
		return NetBoxTagCandidate{}, ErrUnavailable
	}
	_, source, err := provider.sourceTenant(ctx)
	if err != nil {
		return NetBoxTagCandidate{}, err
	}
	scope, err := provider.cacheScope(ctx)
	if err != nil {
		return NetBoxTagCandidate{}, err
	}
	cacheKey := scope + "\x00" + CanonicalKey(key)
	r.mu.Lock()
	epoch := r.epochs[cacheKey]
	r.mu.Unlock()
	ownershipUnavailable := false
	defer func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if errors.Is(err, ErrTenantBinding) || ownershipUnavailable {
			r.epochs[cacheKey]++
			delete(r.cache, cacheKey)
		} else if epoch != r.epochs[cacheKey] {
			candidate, err = NetBoxTagCandidate{}, ErrTenantBinding
		}
	}()
	cis, err := provider.Lookup(ctx, key)
	if err != nil {
		return NetBoxTagCandidate{}, err
	}
	if len(cis) != 1 {
		// A completed tenant-filtered read no longer identifies the old
		// cached CI. Do not let a later outage revive that enrichment.
		ownershipUnavailable = true
		return NetBoxTagCandidate{}, ErrNoTagCandidate
	}
	lookup := cis[0]
	ci := lookup
	if ci.Class == "netbox.ip_address" {
		ci, err = provider.relatedTagCI(ctx, source, ci.relatedKind, ci.relatedID)
		if err != nil {
			ownershipUnavailable = errors.Is(err, ErrNoTagCandidate)
			return NetBoxTagCandidate{}, err
		}
	}
	value := ci.Extra[field]
	if tags.ValidateValue(value) != nil {
		return NetBoxTagCandidate{}, ErrNoTagCandidate
	}
	lookupRef, err := compactNetBoxCIRef(lookup)
	if err != nil {
		return NetBoxTagCandidate{}, err
	}
	ciRef, err := compactNetBoxCIRef(ci)
	if err != nil {
		return NetBoxTagCandidate{}, err
	}
	name := ci.Name
	if len(name) > 256 || !utf8.ValidString(name) {
		name = ci.SysID
	}
	return NetBoxTagCandidate{NetBoxTenantID: source, LookupCIID: lookup.SysID,
		CIID: ci.SysID, Name: name, Field: field, Value: value,
		SourceRef: "netbox:t" + source + ":" + lookupRef + ":" + ciRef + ":" + field}, nil
}

func compactNetBoxCIRef(ci CI) (string, error) {
	for prefix, code := range map[string]string{
		"netbox:ipam.ip_address:": "ip", "netbox:dcim.device:": "d",
		"netbox:virtualization.virtual_machine:": "vm",
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
			ID     int64         `json:"id"`
			Tenant *netBoxTenant `json:"tenant"`
			Name   string        `json:"name"`
			Role   named         `json:"role"`
			Site   named         `json:"site"`
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
	return CI{SysID: prefix + strconv.FormatInt(id, 10), Name: row.Name,
		Class: class, Extra: compactExtra(map[string]string{"role": row.Role.Name, "site": row.Site.Name})}, nil
}
