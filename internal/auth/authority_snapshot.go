// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package auth

import (
	"encoding/json"
	"maps"
	"slices"
)

// ClonePrincipal copies verified identity and separates mutable authority.
func ClonePrincipal(p *Principal) *Principal {
	if p == nil {
		return nil
	}
	snapshot := *p
	snapshot.Permissions = maps.Clone(p.Permissions)
	snapshot.Attributes = maps.Clone(p.Attributes)
	snapshot.PermissionGrants = slices.Clone(p.PermissionGrants)
	return &snapshot
}

// SamePrincipalAuthority compares semantic authority, never display identity,
// map iteration order or credential-reference pointers. Revalidate the exact
// originating credential independently before using either snapshot.
func SamePrincipalAuthority(a, b *Principal) bool {
	if a == nil || b == nil || a.TenantID != b.TenantID || a.UserID != b.UserID || a.MFASatisfied != b.MFASatisfied || a.ViaBearerToken != b.ViaBearerToken || !maps.Equal(a.Permissions, b.Permissions) || !maps.Equal(a.Attributes, b.Attributes) {
		return false
	}
	left, right := map[PermissionGrant]bool{}, map[PermissionGrant]bool{}
	for _, g := range a.PermissionGrants {
		left[g] = true
	}
	for _, g := range b.PermissionGrants {
		right[g] = true
	}
	return maps.Equal(left, right)
}

// EnabledPolicyAuthoritySet excludes display identity and disabled policies,
// retaining exact enabled evaluation inputs. A failure cannot mean no policies.
func EnabledPolicyAuthoritySet(policies []Policy) (map[string]bool, error) {
	set := map[string]bool{}
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		policy.ID, policy.Name = "", ""
		encoded, err := json.Marshal(policy)
		if err != nil {
			return nil, err
		}
		set[string(encoded)] = true
	}
	return set, nil
}
