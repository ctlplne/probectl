// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package scim

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// PatchOp is a SCIM PATCH request (RFC 7644 §3.5.2). IdPs vary in how they encode
// the same change (Okta sends a valueless replace with an object; Entra sends a
// path + a string "False"), so the appliers below are deliberately lenient.
type PatchOp struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}

// PatchOperation is one op in a PATCH.
type PatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// ApplyUserPatch mutates a User per the PATCH operations. It handles the common
// IdP forms: deactivation (replace active, with or without a path; bool or the
// string "False"/"True"), and replacing userName/displayName/name.formatted.
func ApplyUserPatch(u *User, ops []PatchOperation) error {
	for _, op := range ops {
		action := strings.ToLower(strings.TrimSpace(op.Op))
		if action != "replace" && action != "add" {
			continue // a "remove" of a scalar user attr is uncommon — ignore leniently
		}
		switch strings.ToLower(strings.TrimSpace(op.Path)) {
		case "active":
			b, err := parseSCIMBool(op.Value)
			if err != nil {
				return err
			}
			u.Active = b
		case "username":
			u.UserName = jsonString(op.Value)
		case "displayname":
			u.DisplayName = jsonString(op.Value)
		case "name.formatted":
			if u.Name == nil {
				u.Name = &Name{}
			}
			u.Name.Formatted = jsonString(op.Value)
		case "":
			// A valueless-path op carries an object of attributes to replace.
			var m map[string]json.RawMessage
			if err := json.Unmarshal(op.Value, &m); err != nil {
				return fmt.Errorf("scim: patch value is not an object: %w", err)
			}
			if v, ok := m["active"]; ok {
				b, err := parseSCIMBool(v)
				if err != nil {
					return err
				}
				u.Active = b
			}
			if v, ok := m["userName"]; ok {
				u.UserName = trimJSONString(v)
			}
			if v, ok := m["displayName"]; ok {
				u.DisplayName = trimJSONString(v)
			}
		}
	}
	return nil
}

// GroupPatch is the resolved set of member changes from a Group PATCH.
type GroupPatch struct {
	Add         []string  // member user ids to bind
	Remove      []string  // member user ids to unbind
	ReplaceAll  *[]string // non-nil when the whole member set is replaced
	DisplayName *string   // non-nil when the group's displayName is replaced
}

var memberFilterRe = regexp.MustCompile(`(?i)value\s+eq\s+"([^"]+)"`)

// ParseGroupPatch resolves a Group PATCH into member add/remove/replace + an
// optional displayName change. It accepts both `members[value eq "id"]`
// remove-by-filter and value-list forms.
func ParseGroupPatch(ops []PatchOperation) GroupPatch {
	var gp GroupPatch
	for _, op := range ops {
		action := strings.ToLower(strings.TrimSpace(op.Op))
		path := strings.TrimSpace(op.Path)
		lpath := strings.ToLower(path)
		switch {
		case action == "remove" && strings.HasPrefix(lpath, "members"):
			if m := memberFilterRe.FindStringSubmatch(path); len(m) == 2 {
				gp.Remove = append(gp.Remove, m[1])
			} else {
				gp.Remove = append(gp.Remove, parseMembers(op.Value)...)
			}
		case action == "add" && lpath == "members":
			gp.Add = append(gp.Add, parseMembers(op.Value)...)
		case action == "replace" && lpath == "members":
			ms := parseMembers(op.Value)
			gp.ReplaceAll = &ms
		case (action == "replace" || action == "add") && lpath == "displayname":
			v := jsonString(op.Value)
			gp.DisplayName = &v
		case action == "replace" && lpath == "":
			var m map[string]json.RawMessage
			if err := json.Unmarshal(op.Value, &m); err == nil {
				if v, ok := m["displayName"]; ok {
					s := trimJSONString(v)
					gp.DisplayName = &s
				}
				if v, ok := m["members"]; ok {
					ms := parseMembers(v)
					gp.ReplaceAll = &ms
				}
			}
		}
	}
	return gp
}

// parseMembers extracts member ids from a value that is an array of {value:...}
// or a single {value:...}.
func parseMembers(raw json.RawMessage) []string {
	var arr []Member
	if err := json.Unmarshal(raw, &arr); err == nil {
		out := make([]string, 0, len(arr))
		for _, m := range arr {
			if m.Value != "" {
				out = append(out, m.Value)
			}
		}
		return out
	}
	var one Member
	if err := json.Unmarshal(raw, &one); err == nil && one.Value != "" {
		return []string{one.Value}
	}
	return nil
}

// parseSCIMBool accepts a JSON bool or a quoted "true"/"false" (Entra sends
// "False"/"True" strings).
func parseSCIMBool(raw json.RawMessage) (bool, error) {
	s := strings.ToLower(strings.Trim(strings.TrimSpace(string(raw)), `"`))
	switch s {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("scim: invalid boolean value %q", string(raw))
}

// jsonString unmarshals a JSON string value, tolerating a bare/quoted token.
func jsonString(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return trimJSONString(raw)
}

func trimJSONString(raw json.RawMessage) string {
	return strings.Trim(strings.TrimSpace(string(raw)), `"`)
}
