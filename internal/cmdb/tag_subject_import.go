// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cmdb

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/tags"
)

// NetBoxTagFacts is private, current authority resolved from an owned subject.
// It is deliberately not a transport projection or a caller-supplied lookup.
type NetBoxTagFacts struct {
	Addresses []netip.Addr `json:"-"`
	Prefix    netip.Prefix `json:"-"`
	Hostname  string       `json:"-"`
}

// NetBoxTagSelection retains the private correspondence only during a request.
// It can be checked against a later tenant snapshot without exposing addresses
// or an address hash, storing a plan, or performing source I/O in a transaction.
type NetBoxTagSelection struct {
	candidate    NetBoxTagCandidate
	address      netip.Addr
	prefix       netip.Prefix
	hostname     string
	ownerBinding string
}

func (s NetBoxTagSelection) Candidate() NetBoxTagCandidate { return s.candidate }

// Matches requires the selected source relationship to remain current; an
// unrelated extra address or observation refresh does not invalidate review.
func (s NetBoxTagSelection) Matches(facts NetBoxTagFacts) bool {
	if s.prefix.IsValid() {
		return facts.Prefix == s.prefix
	}
	if s.address.IsValid() {
		return slices.Contains(facts.Addresses, s.address)
	}
	return s.hostname != "" && CanonicalKey(facts.Hostname) == s.hostname
}

// PreviewNetBoxSubjectTag uses only current owned facts and the mapped source
// tenant. An optional decimal source ID selects an IP CI (or an IPAM prefix).
// Source ambiguity is never resolved using a display name or first address.
func (r *Resolver) PreviewNetBoxSubjectTag(ctx context.Context, facts NetBoxTagFacts, field, sourceID string) (NetBoxTagSelection, error) {
	provider, source, err := r.tagSubjectProvider(ctx, field)
	if err != nil {
		return NetBoxTagSelection{}, err
	}
	if sourceID != "" && !canonicalNetBoxID(sourceID) {
		return NetBoxTagSelection{}, ErrNoTagCandidate
	}
	if facts.Prefix.IsValid() {
		return provider.prefixTagSelection(ctx, source, facts.Prefix, field, sourceID)
	}
	return r.readSubjectTag(ctx, provider, source, facts, field, sourceID, "")
}

// RecheckNetBoxSubjectTag re-attests the exact reviewed CI rather than choosing
// a different object when source inventory changes during operator review.
func (r *Resolver) RecheckNetBoxSubjectTag(ctx context.Context, facts NetBoxTagFacts, expected NetBoxTagCandidate) (NetBoxTagSelection, error) {
	provider, source, err := r.tagSubjectProvider(ctx, expected.Field)
	if err != nil {
		return NetBoxTagSelection{}, err
	}
	if expected.NetBoxTenantID != source {
		return NetBoxTagSelection{}, ErrTenantBinding
	}
	kind, id, err := netBoxTagCIID(expected.LookupCIID)
	if err != nil {
		return NetBoxTagSelection{}, err
	}
	if facts.Prefix.IsValid() {
		if kind != "prefix" {
			return NetBoxTagSelection{}, ErrNoTagCandidate
		}
		return provider.prefixTagSelection(ctx, source, facts.Prefix, expected.Field, id)
	}
	return r.readSubjectTag(ctx, provider, source, facts, expected.Field, id, kind)
}

func (r *Resolver) tagSubjectProvider(ctx context.Context, field string) (*NetBox, string, error) {
	if r == nil || (field != "role" && field != "site") {
		return nil, "", ErrNoTagCandidate
	}
	n, ok := r.provider.(*NetBox)
	if !ok || n == nil {
		return nil, "", ErrUnavailable
	}
	_, source, err := n.sourceTenant(ctx)
	return n, source, err
}

func canonicalNetBoxID(raw string) bool {
	id, err := strconv.ParseInt(raw, 10, 64)
	return err == nil && id > 0 && strconv.FormatInt(id, 10) == raw
}

func netBoxTagCIID(raw string) (string, string, error) {
	for prefix, kind := range map[string]string{
		"netbox:ipam.ip_address:": "ip", "netbox:ipam.prefix:": "prefix",
		"netbox:dcim.device:": "device", "netbox:virtualization.virtual_machine:": "vm",
	} {
		if id, ok := strings.CutPrefix(raw, prefix); ok && canonicalNetBoxID(id) {
			return kind, id, nil
		}
	}
	return "", "", ErrNoTagCandidate
}

func (r *Resolver) readSubjectTag(ctx context.Context, n *NetBox, source string, facts NetBoxTagFacts, field, id, kind string) (selected NetBoxTagSelection, err error) {
	keys, err := netBoxTagFactKeys(facts)
	if err != nil || len(keys) == 0 {
		return NetBoxTagSelection{}, ErrNoTagCandidate
	}
	scope, err := n.cacheScope(ctx)
	if err != nil {
		return NetBoxTagSelection{}, err
	}
	// Preserve ordinary enrichment's ownership-invalidating cache fence. A
	// failed new import cannot leave old metadata available through an outage.
	epochs := make(map[string]uint64, len(keys))
	r.mu.Lock()
	for _, key := range keys {
		cacheKey := scope + "\x00" + key
		epochs[cacheKey] = r.epochs[cacheKey]
	}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		for key, epoch := range epochs {
			if errors.Is(err, ErrTenantBinding) || errors.Is(err, ErrNoTagCandidate) {
				r.epochs[key]++
				delete(r.cache, key)
			} else if epoch != r.epochs[key] {
				selected, err = NetBoxTagSelection{}, ErrTenantBinding
			}
		}
	}()
	if id != "" {
		return n.selectedTagCI(ctx, source, facts, field, id, kind)
	}
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return NetBoxTagSelection{}, err
		}
		cis, err := n.Lookup(ctx, key)
		if err != nil {
			return NetBoxTagSelection{}, err
		}
		if len(cis) == 0 {
			continue
		}
		if len(cis) != 1 {
			return NetBoxTagSelection{}, ErrNoTagCandidate
		}
		current, err := n.tagSelectionForCI(ctx, source, cis[0], field)
		if err != nil {
			return NetBoxTagSelection{}, err
		}
		if !current.Matches(facts) {
			return NetBoxTagSelection{}, ErrTenantBinding
		}
		if selected.candidate.CIID != "" && !sameNetBoxTagOwner(selected, current) {
			return NetBoxTagSelection{}, ErrNoTagCandidate
		}
		if selected.candidate.CIID == "" {
			selected = current
		}
	}
	if selected.candidate.CIID == "" {
		return NetBoxTagSelection{}, ErrNoTagCandidate
	}
	return selected, nil
}

func netBoxTagFactKeys(facts NetBoxTagFacts) ([]string, error) {
	keys := make([]string, 0, len(facts.Addresses)+1)
	for _, address := range facts.Addresses {
		if !address.IsValid() || address.Zone() != "" || address.Unmap() != address {
			return nil, ErrNoTagCandidate
		}
		keys = append(keys, address.String())
	}
	if facts.Hostname != "" {
		key := CanonicalKey(facts.Hostname)
		if len(key) > 253 || strings.ContainsAny(key, "/% \t\r\n") {
			return nil, ErrNoTagCandidate
		}
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return slices.Compact(keys), nil
}

func sameNetBoxTagOwner(left, right NetBoxTagSelection) bool {
	a, b := left.candidate, right.candidate
	return a.NetBoxTenantID == b.NetBoxTenantID && a.CIID == b.CIID &&
		a.Name == b.Name && a.Field == b.Field && a.Value == b.Value && left.ownerBinding == right.ownerBinding
}

func (n *NetBox) selectedTagCI(ctx context.Context, source string, facts NetBoxTagFacts, field, id, kind string) (NetBoxTagSelection, error) {
	var lookup CI
	var err error
	if kind == "device" || kind == "vm" {
		if facts.Hostname == "" {
			return NetBoxTagSelection{}, ErrNoTagCandidate
		}
		number, _ := strconv.ParseInt(id, 10, 64)
		lookup, err = n.relatedTagCI(ctx, source, kind, number)
	} else if kind == "" || kind == "ip" {
		lookup, err = n.tagIPByID(ctx, source, id)
	} else {
		return NetBoxTagSelection{}, ErrNoTagCandidate
	}
	if err != nil {
		return NetBoxTagSelection{}, err
	}
	selected, err := n.tagSelectionForCI(ctx, source, lookup, field)
	if err != nil {
		return NetBoxTagSelection{}, err
	}
	if !selected.Matches(facts) && lookup.Class == "netbox.ip_address" &&
		facts.Hostname != "" && CanonicalKey(lookup.FQDN) == CanonicalKey(facts.Hostname) {
		selected.address, selected.hostname = netip.Addr{}, CanonicalKey(facts.Hostname)
	}
	if !selected.Matches(facts) {
		return NetBoxTagSelection{}, ErrNoTagCandidate
	}
	return selected, nil
}

func (n *NetBox) tagSelectionForCI(ctx context.Context, source string, lookup CI, field string) (NetBoxTagSelection, error) {
	ci := lookup
	var err error
	if lookup.Class == "netbox.ip_address" {
		ci, err = n.relatedTagCI(ctx, source, lookup.relatedKind, lookup.relatedID)
		if err != nil {
			return NetBoxTagSelection{}, err
		}
	} else if ci.Extra[field+"_id"] == "" {
		kind, id, err := netBoxTagCIID(lookup.SysID)
		if err != nil || (kind != "device" && kind != "vm") {
			return NetBoxTagSelection{}, ErrNoTagCandidate
		}
		number, _ := strconv.ParseInt(id, 10, 64)
		ci, err = n.relatedTagCI(ctx, source, kind, number)
		if err != nil {
			return NetBoxTagSelection{}, err
		}
		if ci.FQDN != lookup.FQDN {
			return NetBoxTagSelection{}, ErrTenantBinding
		}
	}
	value, attributeID := ci.Extra[field], ci.Extra[field+"_id"]
	if tags.ValidateValue(value) != nil || !canonicalNetBoxID(attributeID) {
		return NetBoxTagSelection{}, ErrNoTagCandidate
	}
	lookupRef, err := compactNetBoxCIRef(lookup)
	if err != nil {
		return NetBoxTagSelection{}, err
	}
	ownerRef, err := compactNetBoxCIRef(ci)
	if err != nil {
		return NetBoxTagSelection{}, err
	}
	selected := NetBoxTagSelection{ownerBinding: field + ":" + attributeID, candidate: NetBoxTagCandidate{NetBoxTenantID: source,
		LookupCIID: lookup.SysID, CIID: ci.SysID, Name: boundedNetBoxTagName(ci), Field: field, Value: value,
		SourceRef: "netbox:t" + source + ":" + lookupRef + ":" + ownerRef + ":" + field + ":a" + attributeID}}
	if lookup.Class == "netbox.ip_address" {
		selected.address, err = netip.ParseAddr(lookup.IPAddress)
		if err != nil || selected.address.Zone() != "" {
			return NetBoxTagSelection{}, ErrTenantBinding
		}
		selected.address = selected.address.Unmap()
	} else {
		selected.hostname = CanonicalKey(ci.FQDN)
	}
	return selected, nil
}

func boundedNetBoxTagName(ci CI) string {
	if len(ci.Name) > 256 || !utf8.ValidString(ci.Name) {
		return ci.SysID
	}
	return ci.Name
}
