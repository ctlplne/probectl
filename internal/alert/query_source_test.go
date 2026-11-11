// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
)

func TestSavedQueryAlertCredentialCeilingRetainsOnlyExplicitReadScopes(t *testing.T) {
	binding, _, _ := queryGroupsForTest()
	source := QuerySource{Version: 1, OwnerUserID: binding.RuleID, ViewID: binding.ViewID, ViewVersion: binding.ViewVersion, EverySeconds: 60, Condition: binding.Condition,
		ReadGrants: []QueryReadGrant{{Permission: "flow.read", ScopeType: auth.ScopeProject, ScopeID: binding.ViewID}, {Permission: "entities.read", ScopeType: auth.ScopeTenant}}}
	principal, err := source.CredentialCeiling(binding.TenantID)
	if err != nil || principal.TenantID != binding.TenantID || principal.UserID != source.OwnerUserID || !principal.ViaBearerToken || principal.MFASatisfied || principal.Attributes != nil || principal.Has("flow.read") || !principal.HasAny("flow.read") || !principal.Has("entities.read") || principal.HasAny("flow.write") {
		t.Fatal("captured read ceiling widened scope or invented a credential/MFA", principal, err)
	}
	for _, mutate := range []func(*QuerySource){
		func(s *QuerySource) {
			s.ReadGrants = []QueryReadGrant{{Permission: "flow.write", ScopeType: auth.ScopeTenant}}
		},
		func(s *QuerySource) { s.ReadGrants = nil },
		func(s *QuerySource) {
			s.ReadGrants = []QueryReadGrant{{Permission: "flow.read", ScopeType: auth.ScopeTenant, ScopeID: binding.ViewID}}
		},
		func(s *QuerySource) { s.OwnerUserID = "unknown" },
		func(s *QuerySource) { s.EverySeconds = -1 },
		func(s *QuerySource) { s.ViewVersion = "01" },
	} {
		changed := source
		mutate(&changed)
		if principal, err := changed.CredentialCeiling(binding.TenantID); err == nil || principal != nil {
			t.Fatal("invalid read delegation produced a credential ceiling", principal, err)
		}
	}
}
