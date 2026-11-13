// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"math/big"
	"slices"
	"strconv"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type incidentTestCustomerTags struct {
	tenant   string
	revision int64
	items    map[string]tags.SubjectResolution
}

func incidentTestHitEvidence(test incident.ImpactTest) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, period := range []incident.ImpactTestPeriod{test.Current, test.Previous} {
		for _, observation := range period.Observations {
			hit := observation.Status == "failed"
			if observation.Status == "successful" && observation.Packets != nil {
				var lost big.Int
				_, valid := lost.SetString(observation.Packets.Lost, 10)
				hit = valid && lost.Sign() > 0
			}
			if hit && !seen[observation.EvidenceID] {
				seen[observation.EvidenceID] = true
				out = append(out, observation.EvidenceID)
			}
		}
	}
	return out
}

func (s *Server) loadIncidentTestCustomerTags(ctx context.Context, actor *auth.Principal, snapshot incidentImpactSnapshot, key string, tests []incident.ImpactTest) (*incidentTestCustomerTags, error) {
	if snapshot.authority == nil || key == "" {
		return nil, apierror.Unavailable("current test customer context is unavailable")
	}
	ctx, principal, err := snapshot.authority.requestContext(ctx, actor)
	if err != nil {
		return nil, err
	}
	expected := map[string]incident.ImpactTest{}
	byContext := map[string][]incident.ImpactTest{}
	ids := []string{}
	for _, test := range tests {
		if len(incidentTestHitEvidence(test)) == 0 {
			continue
		}
		byContext[test.ContextID] = append(byContext[test.ContextID], test)
		if prior, exists := expected[test.TestID]; exists {
			if prior.ContextID != test.ContextID {
				return nil, entity.ErrScopeMismatch
			}
			continue
		}
		expected[test.TestID] = test
		ids = append(ids, test.TestID)
	}
	authorize := func(ctx context.Context, current *auth.Principal, permission string, resource map[string]string) (bool, error) {
		if resource[auth.ResourceTenantKey] != actor.TenantID || current.TenantID != actor.TenantID {
			return false, entity.ErrScopeMismatch
		}
		copyResource := make(map[string]string, len(resource)+4)
		for name, value := range resource {
			copyResource[name] = value
		}
		copyResource["tag_key"] = key
		allowed, err := s.authorizeTestTagResource(ctx, current, permission, copyResource)
		if err != nil || !allowed {
			return allowed, err
		}
		if contextID := resource["context_id"]; contextID != "" {
			members, found := byContext[contextID]
			if !found {
				return false, entity.ErrScopeMismatch
			}
			for _, test := range members {
				copyResource["test_id"], copyResource["entity_id"], copyResource["agent_id"] = test.TestID, test.EntityID, test.AgentID
				allowed, err = s.authorizeTestTagResource(ctx, current, permission, copyResource)
				if err != nil || !allowed {
					return allowed, err
				}
			}
		}
		return true, nil
	}
	resolved, err := resolveTestTagContext(ctx, principal, s.pool, s.flowStore, tags.TestContextInput{TestIDs: ids}, authorize)
	if err != nil {
		return nil, err
	}
	revision, err := strconv.ParseInt(resolved.TagRevision, 10, 64)
	if err != nil || revision <= 0 {
		return nil, apierror.Unavailable("current test tag revision is unavailable")
	}
	out := &incidentTestCustomerTags{tenant: actor.TenantID, revision: revision, items: map[string]tags.SubjectResolution{}}
	for _, item := range resolved.Items {
		test, found := expected[item.TargetID]
		if !found || item.TargetKind != "test" || item.ContextID != test.ContextID || item.TagRevision != resolved.TagRevision {
			return nil, entity.ErrScopeMismatch
		}
		out.items[item.TargetID] = item
	}
	if len(out.items) != len(expected) {
		return nil, apierror.Forbidden("current tags and test disclosure are required for every affected test")
	}
	return out, nil
}

func mergeIncidentTestCustomers(ctx context.Context, tenant, key string, metadata *incidentTestCustomerTags, tests []incident.ImpactTest, slos []incident.ImpactSLO, customers []incident.ImpactCustomer, maxBytes int64) ([]incident.ImpactCustomer, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenant || metadata == nil || metadata.tenant != tenant {
		return nil, entity.ErrScopeMismatch
	}
	if maxBytes < 4096 || int64(len(tests))+int64(len(customers)) > maxBytes/1024 {
		return nil, flowstore.ErrExplorerBudget
	}
	type identity struct{ context, value string }
	items := map[identity]*incident.ImpactCustomer{}
	remaining := maxBytes
	for _, customer := range customers {
		remaining -= int64(2048 + 4*(len(customer.Value)+len(customer.TagKey)))
		if remaining < 0 {
			return nil, flowstore.ErrExplorerBudget
		}
		cloned := customer
		cloned.PrefixIDs, cloned.TestIDs, cloned.SLOIDs = slices.Clone(cloned.PrefixIDs), slices.Clone(cloned.TestIDs), slices.Clone(cloned.SLOIDs)
		cloned.CaptureKeys, cloned.EvidenceIDs, cloned.TagIDs = slices.Clone(cloned.CaptureKeys), slices.Clone(cloned.EvidenceIDs), slices.Clone(cloned.TagIDs)
		items[identity{customer.ContextID, customer.Value}] = &cloned
	}
	for _, test := range tests {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		evidence := incidentTestHitEvidence(test)
		if len(evidence) == 0 {
			continue
		}
		tagged, exists := metadata.items[test.TestID]
		if !exists || tagged.ContextID != test.ContextID || tagged.TargetKind != "test" {
			return nil, entity.ErrScopeMismatch
		}
		for _, tag := range tagged.Items {
			if tag.Key != key {
				continue
			}
			remaining -= int64(2048+4*(len(tag.Value)+len(tag.TagID)+len(test.TestID))) + 128*int64(len(evidence))
			if remaining < 0 {
				return nil, flowstore.ErrExplorerBudget
			}
			id := identity{test.ContextID, tag.Value}
			customer := items[id]
			if customer == nil {
				customer = &incident.ImpactCustomer{TagKey: key, Value: tag.Value, ContextID: test.ContextID, PrefixIDs: []string{}, TestIDs: []string{}, SLOIDs: []string{}, CaptureKeys: []string{}}
				items[id] = customer
			}
			customer.TestIDs = append(customer.TestIDs, test.TestID)
			customer.TagIDs = append(customer.TagIDs, tag.TagID)
			customer.EvidenceIDs = append(customer.EvidenceIDs, evidence...)
			for _, objective := range slos {
				for _, period := range []incident.ImpactSLOPeriod{objective.Current, objective.Previous} {
					for _, source := range period.Sources {
						if source.ContextID == test.ContextID && source.EntityID == test.EntityID && source.TestID == test.TestID && source.AgentID == test.AgentID && len(source.EvidenceIDs) > 0 {
							customer.SLOIDs = append(customer.SLOIDs, objective.Name)
						}
					}
				}
			}
		}
	}
	out := make([]incident.ImpactCustomer, 0, len(items))
	for _, customer := range items {
		for _, ids := range []*[]string{&customer.TestIDs, &customer.SLOIDs, &customer.EvidenceIDs, &customer.TagIDs} {
			slices.Sort(*ids)
			*ids = slices.Compact(*ids)
		}
		out = append(out, *customer)
	}
	slices.SortFunc(out, func(a, b incident.ImpactCustomer) int {
		return slices.Compare([]string{a.ContextID, a.Value}, []string{b.ContextID, b.Value})
	})
	return out, ctx.Err()
}
