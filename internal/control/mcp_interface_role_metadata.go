// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	guuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
)

// These types are used ONLY for server-created role metadata loaded after
// tenant/current-user authorization. Their JSON values are unchanged. Escaped
// separators/digits prevent a random identifier or revision's numeric prefix
// being mistaken for PII by text redaction. No arbitrary text, sender IDs or
// operator rule patterns receive this encoding; their full redaction remains.
type roleMCPUUID string

type roleMCPRevision string

func (id roleMCPUUID) MarshalJSON() ([]byte, error) {
	if id == "" {
		return []byte(`""`), nil
	}
	parsed, err := guuid.Parse(string(id))
	if err != nil || parsed == guuid.Nil || parsed.String() != string(id) {
		return nil, errors.New("invalid server role metadata UUID")
	}
	raw, err := json.Marshal(string(id))
	if err != nil {
		return nil, err
	}
	return []byte(strings.ReplaceAll(string(raw), "-", `\u002d`)), nil
}

func (revision roleMCPRevision) MarshalJSON() ([]byte, error) {
	value, err := strconv.ParseInt(string(revision), 10, 64)
	if err != nil || value < 0 || strconv.FormatInt(value, 10) != string(revision) {
		return nil, errors.New("invalid server role metadata revision")
	}
	var out strings.Builder
	out.WriteByte('"')
	for _, digit := range string(revision) {
		out.WriteString(`\u003`)
		out.WriteRune(digit)
	}
	out.WriteByte('"')
	return []byte(out.String()), nil
}

type roleMCPScope struct {
	TenantID  roleMCPUUID `json:"tenant_id"`
	ContextID roleMCPUUID `json:"context_id"`
}

func roleMetadataScope(scope entity.Scope) (roleMCPScope, error) {
	normalized, err := scope.Normalize()
	if err != nil || normalized != scope {
		return roleMCPScope{}, entity.ErrScopeMismatch
	}
	return roleMCPScope{TenantID: roleMCPUUID(scope.TenantID), ContextID: roleMCPUUID(scope.ContextID)}, nil
}

type roleMCPRule struct {
	ID      roleMCPUUID          `json:"id"`
	Pattern string               `json:"pattern"`
	Role    entity.InterfaceRole `json:"role"`
}
type roleMCPDefinition struct {
	ProviderASNs     []uint32      `json:"provider_asns"`
	CustomerASNs     []uint32      `json:"customer_asns"`
	DescriptionRules []roleMCPRule `json:"description_rules"`
}
type roleMCPPolicy struct {
	roleMCPScope
	ID         roleMCPUUID       `json:"id"`
	Revision   roleMCPRevision   `json:"revision"`
	Definition roleMCPDefinition `json:"definition"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

func marshalRoleMCPPolicy(raw json.RawMessage) (json.RawMessage, error) {
	var record entity.InterfaceRolePolicyRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, err
	}
	scope, err := roleMetadataScope(record.Scope)
	if err != nil {
		return nil, err
	}
	if _, err := interfaceRoleConfigurationVersion(record.ID, record.Revision); err != nil {
		return nil, err
	}
	definition := roleMCPDefinition{ProviderASNs: record.Definition.ProviderASNs, CustomerASNs: record.Definition.CustomerASNs, DescriptionRules: make([]roleMCPRule, 0, len(record.Definition.DescriptionRules))}
	for _, rule := range record.Definition.DescriptionRules {
		definition.DescriptionRules = append(definition.DescriptionRules, roleMCPRule{ID: roleMCPUUID(rule.ID), Pattern: rule.Pattern, Role: rule.Role})
	}
	return json.Marshal(roleMCPPolicy{roleMCPScope: scope, ID: roleMCPUUID(record.ID), Revision: roleMCPRevision(record.Revision), Definition: definition, UpdatedAt: record.UpdatedAt})
}

type roleMCPOverride struct {
	roleMCPScope
	InterfaceID roleMCPUUID          `json:"interface_id"`
	ID          roleMCPUUID          `json:"id"`
	Revision    roleMCPRevision      `json:"revision"`
	Role        entity.InterfaceRole `json:"role"`
}

func marshalRoleMCPOverride(raw json.RawMessage) (json.RawMessage, error) {
	var record entity.InterfaceRoleOverrideRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, err
	}
	scope, err := roleMetadataScope(record.Scope)
	if err != nil {
		return nil, err
	}
	if _, err := interfaceRoleConfigurationVersion(record.ID, record.Revision); err != nil {
		return nil, err
	}
	return json.Marshal(roleMCPOverride{roleMCPScope: scope, InterfaceID: roleMCPUUID(record.InterfaceID), ID: roleMCPUUID(record.ID), Revision: roleMCPRevision(record.Revision), Role: record.Role})
}

// Only configuration references contain exclusively server-created IDs and a
// database revision. Evidence/sender/open-data strings remain untrusted text.
type roleMCPSource string

func (source roleMCPSource) MarshalJSON() ([]byte, error) {
	parts := strings.Split(string(source), "/")
	if (len(parts) == 3 && (parts[0] == "policy" || parts[0] == "override")) || (len(parts) == 5 && parts[0] == "policy" && parts[3] == "rule") {
		if version, err := interfaceRoleConfigurationVersion(parts[1], parts[2]); err == nil && version != "" {
			id, err := roleMCPUUID(parts[1]).MarshalJSON()
			if err != nil {
				return nil, err
			}
			revision, err := roleMCPRevision(parts[2]).MarshalJSON()
			if err != nil {
				return nil, err
			}
			encoded := `"` + parts[0] + "/" + string(id[1:len(id)-1]) + "/" + string(revision[1:len(revision)-1])
			if len(parts) == 5 {
				rule, err := roleMCPUUID(parts[4]).MarshalJSON()
				if err != nil {
					return nil, err
				}
				encoded += "/rule/" + string(rule[1:len(rule)-1])
			}
			return []byte(encoded + `"`), nil
		}
	}
	return json.Marshal(string(source))
}

type roleMCPExplanation struct {
	roleMCPScope
	InterfaceID   roleMCPUUID          `json:"interface_id"`
	Role          entity.InterfaceRole `json:"role"`
	Reason        string               `json:"reason"`
	Sources       []roleMCPSource      `json:"sources"`
	AsOf          time.Time            `json:"as_of"`
	SNMPCurrent   bool                 `json:"snmp_current"`
	PrefixCurrent bool                 `json:"prefix_current"`
}

func marshalRoleMCPExplanation(raw json.RawMessage) (json.RawMessage, error) {
	var result interfaceRoleExplanation
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	scope, err := roleMetadataScope(result.Scope)
	if err != nil {
		return nil, err
	}
	sources := make([]roleMCPSource, 0, len(result.Sources))
	for _, source := range result.Sources {
		sources = append(sources, roleMCPSource(source))
	}
	return json.Marshal(roleMCPExplanation{roleMCPScope: scope, InterfaceID: roleMCPUUID(result.InterfaceID), Role: result.Role, Reason: result.Reason, Sources: sources, AsOf: result.AsOf, SNMPCurrent: result.SNMPCurrent, PrefixCurrent: result.PrefixCurrent})
}
