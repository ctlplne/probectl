// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package scim

import (
	"encoding/json"
	"testing"
)

func TestUserMarshalRoundTrip(t *testing.T) {
	u := User{
		Schemas: []string{SchemaUser}, ID: "u1", ExternalID: "ext-1", UserName: "ada@x.com",
		DisplayName: "Ada", Emails: []Email{{Value: "ada@x.com", Primary: true}}, Active: true,
		Enterprise: &Enterprise{Department: "netops"}, Meta: &Meta{ResourceType: "User"},
	}
	b, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	// the enterprise extension marshals under its URN key
	if !json.Valid(b) || !contains(string(b), schemaEnterprise) {
		t.Fatalf("enterprise extension key missing: %s", b)
	}
	var back User
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.UserName != u.UserName || !back.Active || back.Enterprise == nil || back.Enterprise.Department != "netops" {
		t.Errorf("round-trip = %+v", back)
	}
	if back.PrimaryEmail() != "ada@x.com" {
		t.Errorf("PrimaryEmail = %q", back.PrimaryEmail())
	}
}

func TestErrorAndList(t *testing.T) {
	e := NewError(409, "uniqueness", "userName already exists")
	if e.Status != "409" || e.ScimType != "uniqueness" || e.Schemas[0] != SchemaError {
		t.Errorf("error = %+v", e)
	}
	l := NewList([]any{User{UserName: "a"}}, 1, 1, 1)
	if l.Schemas[0] != SchemaList || l.TotalResults != 1 || l.Resources == nil {
		t.Errorf("list = %+v", l)
	}
	// nil resources marshals as [] not null
	empty := NewList(nil, 0, 1, 0)
	b, _ := json.Marshal(empty)
	if !contains(string(b), `"Resources":[]`) {
		t.Errorf("empty list Resources should be []: %s", b)
	}
}

func TestApplyUserPatchDeactivation(t *testing.T) {
	// Okta form: valueless replace with an object
	u := User{Active: true}
	if err := ApplyUserPatch(&u, ops(`[{"op":"replace","value":{"active":false}}]`)); err != nil || u.Active {
		t.Errorf("okta deactivate: active=%v err=%v", u.Active, err)
	}
	// Entra form: path "active" with the string "False"
	u = User{Active: true}
	if err := ApplyUserPatch(&u, ops(`[{"op":"Replace","path":"active","value":"False"}]`)); err != nil || u.Active {
		t.Errorf("entra deactivate: active=%v err=%v", u.Active, err)
	}
	// bool form + a field replace
	u = User{Active: false, DisplayName: "old"}
	if err := ApplyUserPatch(&u, ops(`[{"op":"replace","path":"active","value":true},{"op":"replace","path":"displayName","value":"New"}]`)); err != nil {
		t.Fatal(err)
	}
	if !u.Active || u.DisplayName != "New" {
		t.Errorf("reactivate+rename = %+v", u)
	}
	// invalid boolean → error
	if err := ApplyUserPatch(&u, ops(`[{"op":"replace","path":"active","value":"maybe"}]`)); err == nil {
		t.Error("want error on invalid boolean")
	}
	// Invalid Okta object form must fail too; it used to be silently ignored.
	u = User{Active: true}
	if err := ApplyUserPatch(&u, ops(`[{"op":"replace","value":{"active":"maybe"}}]`)); err == nil {
		t.Error("want error on invalid object-form boolean")
	}
	if !u.Active {
		t.Error("invalid object-form boolean mutated active")
	}
}

func TestParseGroupPatch(t *testing.T) {
	// add members (array)
	gp := ParseGroupPatch(opsP(`[{"op":"add","path":"members","value":[{"value":"u1"},{"value":"u2"}]}]`))
	if len(gp.Add) != 2 || gp.Add[0] != "u1" {
		t.Errorf("add = %+v", gp.Add)
	}
	// remove by filter path
	gp = ParseGroupPatch(opsP(`[{"op":"remove","path":"members[value eq \"u3\"]"}]`))
	if len(gp.Remove) != 1 || gp.Remove[0] != "u3" {
		t.Errorf("remove-by-filter = %+v", gp.Remove)
	}
	// remove by value list
	gp = ParseGroupPatch(opsP(`[{"op":"remove","path":"members","value":[{"value":"u4"}]}]`))
	if len(gp.Remove) != 1 || gp.Remove[0] != "u4" {
		t.Errorf("remove-by-value = %+v", gp.Remove)
	}
	// replace whole member set + displayName
	gp = ParseGroupPatch(opsP(`[{"op":"replace","path":"members","value":[{"value":"u5"}]},{"op":"replace","path":"displayName","value":"Eng"}]`))
	if gp.ReplaceAll == nil || len(*gp.ReplaceAll) != 1 || gp.DisplayName == nil || *gp.DisplayName != "Eng" {
		t.Errorf("replace = %+v dn=%v", gp.ReplaceAll, gp.DisplayName)
	}
}

func ops(s string) []PatchOperation {
	var o []PatchOperation
	if err := json.Unmarshal([]byte(s), &o); err != nil {
		panic(err)
	}
	return o
}
func opsP(s string) []PatchOperation { return ops(s) }

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
