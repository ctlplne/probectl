// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package scim

import (
	"errors"
	"testing"
)

// TestApplyUserPatchEnterpriseDepartmentAUTHZ32 pins the headline AUTHZ-32 bug:
// an enterprise-extension department PATCH used to FALL THROUGH silently, so the
// IdP got a 200 for a change that never applied. Every supported IdP shape must
// now land on User.Enterprise.Department (which the control plane persists into
// users.attributes, where ABAC reads the subject's department). Uses only
// pre-existing symbols, so it is assertion-RED on the baseline, not a build error.
func TestApplyUserPatchEnterpriseDepartmentAUTHZ32(t *testing.T) {
	const deptPath = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"
	const extPath = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	cases := []struct {
		name string
		ops  string
	}{
		{"entra path form", `[{"op":"Replace","path":"` + deptPath + `","value":"contractor"}]`},
		{"extension object path", `[{"op":"replace","path":"` + extPath + `","value":{"department":"contractor"}}]`},
		{"valueless object form", `[{"op":"replace","value":{"` + extPath + `":{"department":"contractor"}}}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := User{UserName: "ada@x.com", Active: true, Enterprise: &Enterprise{Department: "netops"}}
			if err := ApplyUserPatch(&u, ops(tc.ops)); err != nil {
				t.Fatalf("department PATCH errored: %v", err)
			}
			if u.Enterprise == nil || u.Enterprise.Department != "contractor" {
				t.Fatalf("department not applied (AUTHZ-32 fail-open): %+v", u.Enterprise)
			}
		})
	}
}

// TestApplyUserPatchEmailsValueAUTHZ32 pins the emails[...] fall-through: an
// `emails[type eq "work"].value` replace must change the user's address.
func TestApplyUserPatchEmailsValueAUTHZ32(t *testing.T) {
	u := User{UserName: "ada@x.com", Active: true, Emails: []Email{{Value: "ada@x.com", Primary: true}}}
	patch := `[{"op":"replace","path":"emails[type eq \"work\"].value","value":"ada-work@x.com"}]`
	if err := ApplyUserPatch(&u, ops(patch)); err != nil {
		t.Fatalf("emails PATCH errored: %v", err)
	}
	if got := u.PrimaryEmail(); got != "ada-work@x.com" {
		t.Fatalf("emails value not applied (AUTHZ-32 fail-open): %q", got)
	}
}

// TestApplyUserPatchUnsupportedPathFailsClosedAUTHZ32 pins the fail-closed
// contract: a path the server does not implement must be REJECTED, not applied
// as a silent 200. Asserts only err != nil (an existing-symbol assertion), so it
// is assertion-RED on the baseline.
func TestApplyUserPatchUnsupportedPathFailsClosedAUTHZ32(t *testing.T) {
	u := User{UserName: "ada@x.com", Active: true}
	for _, patch := range []string{
		`[{"op":"replace","path":"title","value":"boss"}]`,
		`[{"op":"add","path":"roles[primary eq true].value","value":"admin"}]`,
		`[{"op":"delete","path":"active"}]`,
	} {
		if err := ApplyUserPatch(&u, ops(patch)); err == nil {
			t.Fatalf("unsupported PATCH %q accepted (AUTHZ-32 fail-open)", patch)
		}
	}
}

// TestApplyUserPatchPreservesSupportedPaths guards against the fail-closed
// rewrite over-rejecting the paths IdPs already rely on.
func TestApplyUserPatchPreservesSupportedPaths(t *testing.T) {
	u := User{UserName: "old", DisplayName: "Old", Active: true, Name: &Name{Formatted: "Old"}}
	patch := `[{"op":"replace","path":"active","value":"False"},` +
		`{"op":"replace","path":"userName","value":"new@x.com"},` +
		`{"op":"replace","path":"displayName","value":"New Name"},` +
		`{"op":"replace","path":"name.formatted","value":"New Name"}]`
	if err := ApplyUserPatch(&u, ops(patch)); err != nil {
		t.Fatalf("supported paths rejected: %v", err)
	}
	if u.Active || u.UserName != "new@x.com" || u.DisplayName != "New Name" || u.Name.Formatted != "New Name" {
		t.Fatalf("supported paths not applied: %+v", u)
	}
	// A genuinely malformed value on a supported path stays invalidValue, not
	// invalidPath.
	if err := ApplyUserPatch(&u, ops(`[{"op":"replace","path":"active","value":"maybe"}]`)); err == nil ||
		errors.Is(err, ErrUnsupportedPatchPath) {
		t.Fatalf("bad boolean should be a value error, got %v", err)
	}
}

// TestParseGroupPatchRemoveAllAUTHZ32 pins RFC 7644 remove-all and multi-value
// remove. It references the new GroupPatch.RemoveAll field, so on the baseline
// (which lacks the field) the package fails to BUILD rather than asserting;
// the baseline RED for the observable behavior is proven by the integration
// test (members stay bound after a valueless remove).
func TestParseGroupPatchRemoveAllAUTHZ32(t *testing.T) {
	// no value, no filter → remove ALL (was a silent no-op)
	gp := ParseGroupPatch(ops(`[{"op":"remove","path":"members"}]`))
	if !gp.RemoveAll || len(gp.Remove) != 0 {
		t.Fatalf("valueless members remove = %+v, want RemoveAll", gp)
	}
	// explicit empty array is NOT remove-all (nothing named → nothing removed)
	gp = ParseGroupPatch(ops(`[{"op":"remove","path":"members","value":[]}]`))
	if gp.RemoveAll || len(gp.Remove) != 0 {
		t.Fatalf("empty-array remove = %+v, want no-op", gp)
	}
	// multi-value `or` filter removes EVERY named member, not just the first
	gp = ParseGroupPatch(ops(`[{"op":"remove","path":"members[value eq \"u1\" or value eq \"u2\"]"}]`))
	if gp.RemoveAll || len(gp.Remove) != 2 || gp.Remove[0] != "u1" || gp.Remove[1] != "u2" {
		t.Fatalf("multi-value remove = %+v, want [u1 u2]", gp.Remove)
	}
}
