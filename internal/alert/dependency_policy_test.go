// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"math"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
)

func TestTopologyDependencyPolicyRetainsOnlyAReadCeilingAndFiniteFreshness(t *testing.T) {
	input, err := NormalizeDependencyPolicyInput(DependencyPolicyInput{ContextID: dependencyContext})
	if err != nil || input.FreshnessSeconds != 300 {
		t.Fatal("dependency policy did not normalize its finite source freshness", input, err)
	}
	input.FreshnessSeconds = math.MaxInt64 / int64(time.Second)
	if _, err := NormalizeDependencyPolicyInput(input); err != nil {
		t.Fatal("a valid operator freshness was limited below its duration representation", err)
	}
	for _, tenant := range []string{dependencyTenantA, dependencyTenantB} {
		policy := DependencyPolicy{Version: 1, OwnerUserID: dependencyRoot, ContextID: input.ContextID, FreshnessSeconds: input.FreshnessSeconds,
			ReadGrants: []QueryReadGrant{{Permission: "topology.read", ScopeType: auth.ScopeProject, ScopeID: dependencyRoom}}}
		ceiling, err := policy.CredentialCeiling(tenant)
		if err != nil || ceiling.TenantID != tenant || ceiling.UserID != policy.OwnerUserID || !ceiling.ViaBearerToken || ceiling.MFASatisfied || len(ceiling.Attributes) != 0 || len(ceiling.PermissionGrants) != 1 || ceiling.PermissionGrants[0].Permission != "topology.read" || ceiling.PermissionGrants[0].ScopeType != auth.ScopeProject || ceiling.PermissionGrants[0].ScopeID != dependencyRoom {
			t.Fatal("dependency source widened a credential or crossed its tenant", ceiling, err)
		}
		for _, mutate := range []func(*DependencyPolicy){
			func(p *DependencyPolicy) { p.ReadGrants[0].Permission = "alert.write" },
			func(p *DependencyPolicy) { p.ReadGrants[0].Permission = "remediation.approve" },
			func(p *DependencyPolicy) { p.ReadGrants[0].ScopeType = auth.ScopeTenant },
			func(p *DependencyPolicy) { p.ReadGrants[0].ScopeID = "foreign hierarchy name" },
			func(p *DependencyPolicy) { p.OwnerUserID = "not-an-owner-uuid" },
			func(p *DependencyPolicy) { p.ContextID = "10.0.0.1" },
			func(p *DependencyPolicy) { p.FreshnessSeconds++ },
		} {
			changed := policy
			changed.ReadGrants = append([]QueryReadGrant(nil), policy.ReadGrants...)
			mutate(&changed)
			if ceiling, err := changed.CredentialCeiling(tenant); err == nil || ceiling != nil {
				t.Fatal("invalid dependency source became read or mutation authority", ceiling, err)
			}
		}
	}
}
