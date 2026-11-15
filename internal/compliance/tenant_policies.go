// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package compliance

import (
	"errors"
	"maps"
	"slices"
	"sort"
	"strings"
)

// NewTenantEngine builds explicitly bound, already validated policy sets.
// Callers select policies through the authenticated tenant, never through an
// observation's address (docs/guardrails.md G7-1). Each set uses the same
// compiled Policy values returned by ParsePolicy/LoadDir.
func NewTenantEngine(policies map[string][]Policy) (*Engine, error) {
	engine := NewEngine(nil)
	engine.tenantPolicies = make(map[string][]Policy, len(policies))
	for tenant, selected := range policies {
		if tenant == "" || strings.TrimSpace(tenant) != tenant {
			return nil, errors.New("compliance: explicit tenant policy binding is required")
		}
		engine.tenantPolicies[tenant] = clonePolicies(selected)
	}
	return engine, nil
}

func clonePolicies(policies []Policy) []Policy {
	result := slices.Clone(policies)
	for i := range result {
		result[i].Zones = slices.Clone(result[i].Zones)
		for j := range result[i].Zones {
			zone := &result[i].Zones[j]
			zone.CIDRs = slices.Clone(zone.CIDRs)
			zone.prefixes = slices.Clone(zone.prefixes)
		}
		result[i].Rules = slices.Clone(result[i].Rules)
		for j := range result[i].Rules {
			rule := &result[i].Rules[j]
			rule.Ports = slices.Clone(rule.Ports)
			rule.Frameworks = maps.Clone(rule.Frameworks)
		}
	}
	return result
}

func (e *Engine) policiesFor(tenant string) []Policy {
	if e.tenantPolicies != nil {
		return e.tenantPolicies[tenant]
	}
	return e.policies
}

// PoliciesFor returns only the selected tenant's declared policy names. Bound
// engines have no global/default fallback, including for an unknown tenant.
func (e *Engine) PoliciesFor(tenant string) []string {
	selected := e.policiesFor(tenant)
	names := make([]string, 0, len(selected))
	for _, policy := range selected {
		names = append(names, policy.Name)
	}
	sort.Strings(names)
	return names
}
