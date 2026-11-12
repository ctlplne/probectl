// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"slices"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tags"
)

func (s *Server) loadIncidentImpactTags(ctx context.Context, actor *auth.Principal, snapshot incidentImpactSnapshot, key string) (*flowstore.TagQueryData, error) {
	if key == "" {
		return nil, nil
	}
	if tags.ValidateKey(key) != nil || snapshot.authority == nil {
		return nil, apierror.Validation("an owned customer tag key is required")
	}
	ctx, principal, err := snapshot.authority.requestContext(ctx, actor)
	if err != nil {
		return nil, err
	}
	data, err := s.loadAuthorizedFlowTagQuerySnapshot(ctx, principal, []string{"prefix"}, true)
	if err != nil {
		return nil, err
	}
	vocabulary, err := data.Vocabulary(actor.TenantID)
	if err != nil {
		return nil, err
	}
	if _, found := vocabulary.Lookup("tag.src_prefix." + key); !found {
		return nil, apierror.Validation("customer tag key is not defined in this tenant")
	}
	return data, nil
}

type incidentCustomerCounter struct {
	item               incident.ImpactCustomer
	totals             [2]incidentTrafficCounters
	seen               [2]map[string]bool
	prefixes, captures map[string]bool
}

func summarizeIncidentCustomers(ctx context.Context, tenant, key string, rows [2][]flowstore.Row, owners map[string]store.CapturedFlowOwner, data *flowstore.TagQueryData, maxBytes int64) ([]incident.ImpactCustomer, int, error) {
	type customerKey struct{ contextID, value string }
	byCustomer := map[customerKey]*incidentCustomerCounter{}
	unclassified := 0
	remaining := maxBytes
	for period, values := range rows {
		seen := map[string]bool{}
		for _, row := range values {
			if err := ctx.Err(); err != nil {
				return nil, 0, err
			}
			if row.TenantID != tenant {
				return nil, 0, flowstore.ErrNoTenant
			}
			owner, found := owners[row.RoutingCaptureKey]
			if !found || !incidentTrafficOwnerMatches(row, owner) || seen[row.RoutingCaptureKey] {
				continue
			}
			if remaining < 256 {
				return nil, 0, flowstore.ErrExplorerBudget
			}
			remaining -= 256
			seen[row.RoutingCaptureKey] = true
			memberships, err := data.IncidentCustomerPrefixes(row, owner.Owner.ContextID, key)
			if err != nil {
				return nil, 0, err
			}
			if len(memberships) == 0 {
				unclassified++
			}
			for _, membership := range memberships {
				identity := customerKey{membership.ContextID, membership.Value}
				customer := byCustomer[identity]
				if customer == nil {
					cost := int64(2048 + len(membership.Value) + len(membership.ContextID) + len(key))
					if cost > remaining {
						return nil, 0, flowstore.ErrExplorerBudget
					}
					remaining -= cost
					customer = &incidentCustomerCounter{item: incident.ImpactCustomer{TagKey: key, Value: membership.Value, ContextID: membership.ContextID,
						PrefixIDs: []string{}, TestIDs: []string{}, SLOIDs: []string{}, CaptureKeys: []string{}},
						seen: [2]map[string]bool{{}, {}}, prefixes: map[string]bool{}, captures: map[string]bool{}}
					byCustomer[identity] = customer
				}
				if !customer.prefixes[membership.PrefixID] {
					if remaining < 256 {
						return nil, 0, flowstore.ErrExplorerBudget
					}
					remaining -= 256
					customer.prefixes[membership.PrefixID] = true
					customer.item.PrefixIDs = append(customer.item.PrefixIDs, membership.PrefixID)
				}
				if !customer.seen[period][row.RoutingCaptureKey] {
					if remaining < 512 || row.Sampling == 0 {
						return nil, 0, flowstore.ErrExplorerBudget
					}
					remaining -= 512
					customer.seen[period][row.RoutingCaptureKey] = true
					customer.totals[period].add(row)
				}
				if !customer.captures[row.RoutingCaptureKey] {
					customer.captures[row.RoutingCaptureKey] = true
					customer.item.CaptureKeys = append(customer.item.CaptureKeys, row.RoutingCaptureKey)
				}
			}
		}
	}
	out := make([]incident.ImpactCustomer, 0, len(byCustomer))
	for _, customer := range byCustomer {
		slices.Sort(customer.item.PrefixIDs)
		slices.Sort(customer.item.CaptureKeys)
		if len(customer.seen[0]) > 0 {
			customer.item.Current = customer.totals[0].response()
		}
		if len(customer.seen[1]) > 0 {
			customer.item.Previous = customer.totals[1].response()
		}
		out = append(out, customer.item)
	}
	slices.SortFunc(out, func(a, b incident.ImpactCustomer) int {
		return slices.Compare([]string{a.ContextID, a.Value}, []string{b.ContextID, b.Value})
	})
	return out, unclassified, nil
}
