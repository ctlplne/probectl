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

func TestPathHealthSourceKeepsCanonicalInputsAndTenantReadCeilings(t *testing.T) {
	const testID = "41111111-1111-4111-8111-111111111111"
	input, err := NormalizePathHealthSource(PathHealthSourceInput{TestID: testID, InterfaceID: testID, LookbackSeconds: 100 * 24 * 3600})
	if err != nil || input.LookbackSeconds != 100*24*3600 || input.PollGapSeconds != 300 || input.Metric != "probectl.device.if.in.errors" {
		t.Fatal("owned source default narrowed the requested history", input, err)
	}
	source := PathHealthSource{PathHealthSourceInput: input, Version: 1, OwnerUserID: testID,
		ReadGrants: []QueryReadGrant{{Permission: "metrics.read", ScopeType: auth.ScopeProject, ScopeID: testID}, {Permission: "test.read", ScopeType: auth.ScopeTenant}}}
	for _, tenant := range []string{"51111111-1111-4111-8111-111111111111", "61111111-1111-4111-8111-111111111111"} {
		ceiling, err := source.CredentialCeiling(tenant)
		if err != nil || ceiling.TenantID != tenant || ceiling.UserID != testID || ceiling.Has("metrics.read") || !ceiling.HasAny("metrics.read") || !ceiling.Has("test.read") || ceiling.HasAny("metrics.write") || ceiling.MFASatisfied || ceiling.Attributes != nil {
			t.Fatal("path source invented or widened authority", ceiling, err)
		}
	}
	for _, mutate := range []func(*PathHealthSource){
		func(s *PathHealthSource) { s.TestID = "same-router-name" },
		func(s *PathHealthSource) { s.InterfaceID = "same-port-name" },
		func(s *PathHealthSource) { s.Metric = "probectl.device.if.in.octets" },
		func(s *PathHealthSource) { s.LookbackSeconds = -1 },
		func(s *PathHealthSource) { s.PollGapSeconds = 0 },
		func(s *PathHealthSource) { s.OwnerUserID = "unverified-owner" },
		func(s *PathHealthSource) { s.ReadGrants = nil },
		func(s *PathHealthSource) {
			s.ReadGrants = []QueryReadGrant{{Permission: "metrics.write", ScopeType: auth.ScopeTenant}}
		},
		func(s *PathHealthSource) {
			s.ReadGrants = []QueryReadGrant{{Permission: "metrics.read", ScopeType: auth.ScopeTenant, ScopeID: testID}}
		},
	} {
		changed := source
		mutate(&changed)
		if principal, err := changed.CredentialCeiling("51111111-1111-4111-8111-111111111111"); err == nil || principal != nil {
			t.Fatal("invalid path source produced delegated authority", principal, err)
		}
	}
}
