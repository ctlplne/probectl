// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Sentinel PATCH errors. They are FIXED strings and never embed the untrusted
// PATCH value: the control plane maps them to a generic SCIM error envelope and
// must be able to do so without echoing or logging attacker-controlled input
// (SEC-008). A path the server does not implement is fail-closed (AUTHZ-32:
// before this, unhandled paths — the enterprise department and emails paths —
// fell through silently and the IdP got a 200 for a change that never applied).
// docs/guardrails.md G7-5.
var (
	// ErrUnsupportedPatchPath is returned for a PATCH op whose path (or op) the
	// server does not implement. The caller maps it to 400 invalidPath.
	ErrUnsupportedPatchPath = errors.New("scim: unsupported PATCH path")
	// ErrInvalidPatchValue is returned when a recognized path carries a value
	// the server cannot apply. The caller maps it to 400 invalidValue.
	ErrInvalidPatchValue = errors.New("scim: invalid PATCH value")
)

// The enterprise-user extension paths we recognize, pre-lowercased to match the
// case-folded op path. SCIM lets an IdP address the department either directly
// (`…:User:department`) or as an object on the extension container (`…:User`).
var (
	enterprisePathLower     = strings.ToLower(schemaEnterprise)
	enterpriseDeptPathLower = strings.ToLower(schemaEnterprise + ":department")
)

// emailFilterTypeRe extracts the `type` from an `emails[type eq "work"]` path so
// an email-value PATCH round-trips the matched address.
var emailFilterTypeRe = regexp.MustCompile(`(?i)type\s+eq\s+"([^"]+)"`)

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
// string "False"/"True"), replacing userName/displayName/name.formatted, the
// enterprise-extension department (Entra sends the department as a path op;
// Okta nests it on the extension container), and emails[...] value changes.
//
// AUTHZ-32: a PATCH whose path the server does not implement is REJECTED
// (ErrUnsupportedPatchPath) rather than silently ignored — a fail-open 200 for a
// change that never applied is a directory-integrity hole (e.g. an unapplied
// department change leaves an ABAC deny policy on department=contractor
// unenforced). Only the valueless-path object form stays lenient toward unknown
// KEYS, because an IdP bundles a full attribute set there and we still apply
// every attribute we model. docs/guardrails.md G7-5.
func ApplyUserPatch(u *User, ops []PatchOperation) error {
	for _, op := range ops {
		action := strings.ToLower(strings.TrimSpace(op.Op))
		path := strings.TrimSpace(op.Path)
		lpath := strings.ToLower(path)
		switch action {
		case "replace", "add":
			if err := applyUserSet(u, lpath, op.Value); err != nil {
				return err
			}
		case "remove":
			if err := applyUserRemove(u, lpath); err != nil {
				return err
			}
		default:
			return ErrUnsupportedPatchPath
		}
	}
	return nil
}

// applyUserSet applies a replace/add op to a single recognized path.
func applyUserSet(u *User, lpath string, raw json.RawMessage) error {
	switch {
	case lpath == "active":
		b, err := parseSCIMBool(raw)
		if err != nil {
			return err
		}
		u.Active = b
	case lpath == "username":
		u.UserName = jsonString(raw)
	case lpath == "displayname":
		u.DisplayName = jsonString(raw)
	case lpath == "name.formatted":
		if u.Name == nil {
			u.Name = &Name{}
		}
		u.Name.Formatted = jsonString(raw)
	case lpath == enterpriseDeptPathLower:
		setDepartment(u, jsonString(raw))
	case lpath == enterprisePathLower:
		return applyEnterpriseObject(u, raw)
	case strings.HasPrefix(lpath, "emails"):
		return applyEmailValue(u, lpath, raw)
	case lpath == "":
		return applyUserObject(u, raw)
	default:
		return ErrUnsupportedPatchPath
	}
	return nil
}

// applyUserRemove applies a remove op. Only the enterprise department is
// clearable today; every other path fails closed.
func applyUserRemove(u *User, lpath string) error {
	switch lpath {
	case enterpriseDeptPathLower, enterprisePathLower:
		if u.Enterprise != nil {
			u.Enterprise.Department = ""
		}
		return nil
	default:
		return ErrUnsupportedPatchPath
	}
}

// applyUserObject applies a valueless-path op whose value is an object of
// attributes to replace. Unknown keys are tolerated (an IdP full-object sync
// carries attributes we do not model), but every attribute we DO model —
// including the enterprise department and emails — is applied.
func applyUserObject(u *User, raw json.RawMessage) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
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
	if v, ok := m[schemaEnterprise]; ok {
		if err := applyEnterpriseObject(u, v); err != nil {
			return err
		}
	}
	if v, ok := m["emails"]; ok {
		if val := firstEmailValue(v); val != "" {
			setPrimaryEmail(u, "", val)
		}
	}
	return nil
}

// applyEnterpriseObject applies the enterprise-extension object (we model only
// department). An extension object that carries nothing we apply is rejected so
// the change does not masquerade as applied.
func applyEnterpriseObject(u *User, raw json.RawMessage) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return ErrInvalidPatchValue
	}
	if v, ok := m["department"]; ok {
		setDepartment(u, trimJSONString(v))
		return nil
	}
	return ErrInvalidPatchValue
}

// applyEmailValue applies an emails[...] change. The store models a single
// (primary) address, so an `emails[type eq "work"].value` or `emails.value`
// change sets that address; a bare `emails`/`emails[...]` object or array is
// collapsed to its primary/first value.
func applyEmailValue(u *User, lpath string, raw json.RawMessage) error {
	var emailType string
	if m := emailFilterTypeRe.FindStringSubmatch(lpath); len(m) == 2 {
		emailType = m[1]
	}
	if strings.HasSuffix(lpath, ".value") {
		v := jsonString(raw)
		if v == "" {
			return ErrInvalidPatchValue
		}
		setPrimaryEmail(u, emailType, v)
		return nil
	}
	if v := firstEmailValue(raw); v != "" {
		setPrimaryEmail(u, emailType, v)
		return nil
	}
	return ErrInvalidPatchValue
}

func setDepartment(u *User, dept string) {
	if u.Enterprise == nil {
		u.Enterprise = &Enterprise{}
	}
	u.Enterprise.Department = dept
}

// setPrimaryEmail sets the user's primary email value (the one that round-trips
// to the single-address store), creating one if none exists.
func setPrimaryEmail(u *User, emailType, value string) {
	for i := range u.Emails {
		if u.Emails[i].Primary {
			u.Emails[i].Value = value
			if emailType != "" && u.Emails[i].Type == "" {
				u.Emails[i].Type = emailType
			}
			return
		}
	}
	if len(u.Emails) > 0 {
		u.Emails[0].Value = value
		u.Emails[0].Primary = true
		if emailType != "" && u.Emails[0].Type == "" {
			u.Emails[0].Type = emailType
		}
		return
	}
	u.Emails = append(u.Emails, Email{Value: value, Primary: true, Type: emailType})
}

// firstEmailValue extracts the primary (else first) value from an emails object
// or array.
func firstEmailValue(raw json.RawMessage) string {
	var arr []Email
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		for _, e := range arr {
			if e.Primary && e.Value != "" {
				return e.Value
			}
		}
		return arr[0].Value
	}
	var one Email
	if err := json.Unmarshal(raw, &one); err == nil && one.Value != "" {
		return one.Value
	}
	return ""
}

// GroupPatch is the resolved set of member changes from a Group PATCH.
type GroupPatch struct {
	Add         []string  // member user ids to bind
	Remove      []string  // member user ids to unbind
	RemoveAll   bool      // RFC 7644: `remove` on members with no value/filter → unbind ALL
	ReplaceAll  *[]string // non-nil when the whole member set is replaced
	DisplayName *string   // non-nil when the group's displayName is replaced
}

var memberFilterRe = regexp.MustCompile(`(?i)value\s+eq\s+"([^"]+)"`)

// ParseGroupPatch resolves a Group PATCH into member add/remove/replace + an
// optional displayName change. It accepts both `members[value eq "id"]`
// remove-by-filter and value-list forms. AUTHZ-32: a filter is parsed for EVERY
// `value eq "…"` term (an `or` expression removes each named member, not just
// the first), and a `remove` on members with neither a value nor a filter means
// "remove all members" per RFC 7644 §3.5.2 — not the old silent no-op.
func ParseGroupPatch(ops []PatchOperation) GroupPatch {
	var gp GroupPatch
	for _, op := range ops {
		action := strings.ToLower(strings.TrimSpace(op.Op))
		path := strings.TrimSpace(op.Path)
		lpath := strings.ToLower(path)
		switch {
		case action == "remove" && strings.HasPrefix(lpath, "members"):
			if matches := memberFilterRe.FindAllStringSubmatch(path, -1); len(matches) > 0 {
				for _, m := range matches {
					gp.Remove = append(gp.Remove, m[1])
				}
			} else if len(op.Value) == 0 {
				gp.RemoveAll = true
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
