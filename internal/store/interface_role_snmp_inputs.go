// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func loadInterfaceRoleSNMPInputs(ctx context.Context, sc tenancy.Scope, input InterfaceRoleInputs,
	agent, configured string, budget *roleInputAdmission) (*InterfaceRoleSNMPInputs, error) {
	// Historical latest polls are NEGATIVE fences. Expiry, unavailable data,
	// revocation or a later rebind must never revive an older non-null table.
	var latest *time.Time
	if err := sc.Q.QueryRow(ctx, `SELECT max(e.observed_at) FROM entity_evidence e
 WHERE e.tenant_id=$1 AND e.context_id=$2 AND e.agent_id=$3 AND e.configured_ref=$4
 AND e.source_kind='device_target' AND e.alias_kind='address' AND e.source_ref='snmp:configured-target'
 AND e.observed_at<=transaction_timestamp()`, input.Scope.TenantID, input.Scope.ContextID, agent, configured).Scan(&latest); err != nil {
		return nil, err
	}
	if latest == nil {
		return nil, nil
	}
	root, err := loadInterfaceRolePollRoot(ctx, sc, input, agent, configured, *latest, budget)
	if err != nil || root == nil {
		return nil, err
	}
	fault, err := interfaceRolePollFaultAfter(ctx, sc, input.Scope, agent, configured, *latest)
	if err != nil || fault {
		return nil, err
	}
	return loadInterfaceRolePollFacts(ctx, sc, input, agent, configured, root, budget)
}

// A stored signal fingerprint is computed through internal/crypto at ingest.
// Joining the authenticated receipt to that exact fingerprint excludes bus
// lookalikes and still follows a signal moved by an operator's ungroup action.
// Use occurred_at, never receipt created_at, as the observation clock.
func interfaceRolePollFaultAfter(ctx context.Context, sc tenancy.Scope, scope entity.Scope,
	agent, configured string, observed time.Time) (bool, error) {
	var found bool
	err := sc.Q.QueryRow(ctx, `SELECT EXISTS(
 SELECT 1 FROM entity_fault_receipts receipt JOIN incident_signals signal
 ON (signal.tenant_id,signal.fingerprint)=(receipt.tenant_id,receipt.payload_fingerprint)
 JOIN entity_source_contexts current_source ON
 (current_source.tenant_id,current_source.agent_id,current_source.source_kind,current_source.source_ref)=
 (receipt.tenant_id,receipt.agent_id,receipt.source_kind,receipt.source_ref)
 JOIN entity_agent_contexts current_assignment ON
 (current_assignment.tenant_id,current_assignment.agent_id,current_assignment.context_id)=
 (current_source.tenant_id,current_source.agent_id,current_source.context_id)
 WHERE receipt.tenant_id=$1 AND receipt.agent_id=$2 AND receipt.source_kind='device_target' AND receipt.source_ref=$3
 AND current_source.context_id=$5 AND receipt.created_at>=current_source.assigned_at
 AND receipt.created_at>=current_assignment.assigned_at
 AND signal.kind='device.poll_failed' AND signal.occurred_at>=$4 AND signal.occurred_at<=transaction_timestamp())`,
		scope.TenantID, agent, configured, observed, scope.ContextID).Scan(&found)
	return found, err
}

func loadInterfaceRolePollRoot(ctx context.Context, sc tenancy.Scope, input InterfaceRoleInputs,
	agent, configured string, latest time.Time, budget *roleInputAdmission) (*InterfaceRoleSNMPInputs, error) {
	limit, bodyLimit := budget.memory/2048+1, budget.memory/16
	rows, err := sc.Q.Query(ctx, `SELECT e.id::text,e.alias_value,e.observed_at,`+interfaceRoleEvidenceExpirySQL()+`,
 CASE WHEN octet_length(e.snmp_interface_prefixes::text)<=$7 THEN e.snmp_interface_prefixes ELSE NULL END,
 COALESCE(octet_length(e.snmp_interface_prefixes::text)>$7,false)
 FROM entity_evidence e `+interfaceRoleAuthorityJoinsSQL()+`
 WHERE e.tenant_id=$1 AND e.context_id=$2 AND e.agent_id=$3 AND e.configured_ref=$4
 AND e.entity_id=$5 AND e.observed_at=$6 AND e.source_kind='device_target'
 AND e.alias_kind='address' AND e.source_ref='snmp:configured-target'
 AND `+currentEntityEvidenceSnapshotSQL()+` ORDER BY e.id LIMIT $8`,
		input.Scope.TenantID, input.Scope.ContextID, agent, configured, input.RouterID, latest, bodyLimit, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var root *InterfaceRoleSNMPInputs
	var address string
	ambiguous := false
	for rows.Next() {
		var id, currentAddress string
		var clock InterfaceRoleEvidenceClock
		var body []byte
		var oversized bool
		if err := rows.Scan(&id, &currentAddress, &clock.ObservedAt, &clock.ValidUntil, &body, &oversized); err != nil {
			return nil, err
		}
		if oversized {
			return nil, entity.ErrInterfaceRoleBudget
		}
		if err := budget.charge(ctx, 2048+16*int64(len(body)), 1+int64(len(body))); err != nil {
			return nil, err
		}
		prefixes, err := decodeInterfaceRolePrefixes(ctx, body, budget)
		if err != nil {
			return nil, err
		}
		if root == nil {
			root = &InterfaceRoleSNMPInputs{PrefixSourceID: "evidence/" + id, PrefixClock: clock, Prefixes: prefixes}
			address = currentAddress
		} else {
			ambiguous = ambiguous || address != currentAddress || !reflect.DeepEqual(root.Prefixes, prefixes)
			root.PrefixClock = intersectInterfaceRoleClock(root.PrefixClock, clock)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if ambiguous {
		return nil, nil
	}
	return root, nil
}

func decodeInterfaceRolePrefixes(ctx context.Context, body []byte, budget *roleInputAdmission) ([]entity.SNMPInterfacePrefix, error) {
	if body == nil {
		return nil, nil
	}
	var prefixes []entity.SNMPInterfacePrefix
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&prefixes); err != nil {
		return nil, err
	}
	if err := budget.charge(ctx, 0, 4*int64(len(prefixes))); err != nil {
		return nil, err
	}
	return entity.NormalizeSNMPInterfacePrefixes(prefixes)
}

type interfaceRolePollFact struct {
	id, interfaceID, kind, value, description string
	index                                     uint32
	clock                                     InterfaceRoleEvidenceClock
}

func loadInterfaceRolePollFacts(ctx context.Context, sc tenancy.Scope, input InterfaceRoleInputs, agent, configured string,
	root *InterfaceRoleSNMPInputs, budget *roleInputAdmission) (*InterfaceRoleSNMPInputs, error) {
	rows, err := sc.Q.Query(ctx, `SELECT e.id::text,node.id::text,node.interface_index,e.alias_kind,e.alias_value,
 COALESCE(e.interface_description,''),e.observed_at,`+interfaceRoleEvidenceExpirySQL()+`
 FROM entity_evidence e JOIN entities node ON
 (node.tenant_id,node.context_id,node.id)=(e.tenant_id,e.context_id,e.entity_id) `+interfaceRoleAuthorityJoinsSQL()+`
 WHERE e.tenant_id=$1 AND e.context_id=$2 AND e.agent_id=$3 AND e.configured_ref=$4
 AND e.source_kind='device_target' AND e.observed_at=$5 AND node.kind='interface' AND node.parent_entity_id=$6
 AND node.source_agent_id=e.agent_id AND node.configured_ref=e.configured_ref AND node.interface_index>0
 AND e.source_ref='snmp:ifIndex:'||node.interface_index::text AND e.alias_kind IN ('snmp_interface_id','address')
 AND `+currentEntityEvidenceSnapshotSQL()+` ORDER BY node.id,e.id LIMIT $7`,
		input.Scope.TenantID, input.Scope.ContextID, agent, configured, root.PrefixClock.ObservedAt, input.RouterID, budget.memory/2048+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bindings := map[string]InterfaceRoleBindingInput{}
	addresses := map[netip.Addr]bool{}
	selected, ambiguous := false, false
	selectedClock := root.PrefixClock
	for rows.Next() {
		var fact interfaceRolePollFact
		if err := rows.Scan(&fact.id, &fact.interfaceID, &fact.index, &fact.kind, &fact.value, &fact.description, &fact.clock.ObservedAt, &fact.clock.ValidUntil); err != nil {
			return nil, err
		}
		if err := budget.charge(ctx, 2048+int64(len(fact.value)+len(fact.description)), 1); err != nil {
			return nil, err
		}
		if fact.interfaceID == input.InterfaceID {
			selectedClock = intersectInterfaceRoleClock(selectedClock, fact.clock)
		}
		if fact.kind == "snmp_interface_id" {
			if fact.value != strconv.FormatUint(uint64(fact.index), 10) {
				return nil, entity.ErrInvalidClaim
			}
			binding, exists := bindings[fact.interfaceID]
			if !exists {
				bindings[fact.interfaceID] = InterfaceRoleBindingInput{InterfaceID: fact.interfaceID, IfIndex: fact.index, SourceID: "evidence/" + fact.id, InterfaceRoleEvidenceClock: intersectInterfaceRoleClock(fact.clock, root.PrefixClock)}
			} else {
				binding.InterfaceRoleEvidenceClock = intersectInterfaceRoleClock(binding.InterfaceRoleEvidenceClock, fact.clock)
				bindings[fact.interfaceID] = binding
			}
			if fact.interfaceID == input.InterfaceID {
				ambiguous = ambiguous || (selected && root.Description != fact.description)
				if !selected {
					root.SourceID, root.Description, root.InterfaceRoleEvidenceClock = "evidence/"+fact.id, fact.description, intersectInterfaceRoleClock(fact.clock, root.PrefixClock)
				} else {
					root.InterfaceRoleEvidenceClock = intersectInterfaceRoleClock(root.InterfaceRoleEvidenceClock, fact.clock)
				}
				selected = true
			}
		} else if fact.interfaceID == input.InterfaceID {
			address, err := netip.ParseAddr(fact.value)
			if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
				return nil, entity.ErrInvalidClaim
			}
			addresses[address.Unmap()] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !selected || ambiguous {
		return nil, nil
	}
	root.InterfaceRoleEvidenceClock = intersectInterfaceRoleClock(root.InterfaceRoleEvidenceClock, selectedClock)
	for _, binding := range bindings {
		root.Bindings = append(root.Bindings, binding)
	}
	for address := range addresses {
		root.Addresses = append(root.Addresses, address)
	}
	sort.Slice(root.Bindings, func(i, j int) bool { return root.Bindings[i].InterfaceID < root.Bindings[j].InterfaceID })
	sort.Slice(root.Addresses, func(i, j int) bool { return root.Addresses[i].Less(root.Addresses[j]) })
	return root, ctx.Err()
}

func intersectInterfaceRoleClock(a, b InterfaceRoleEvidenceClock) InterfaceRoleEvidenceClock {
	if b.ObservedAt.After(a.ObservedAt) {
		a.ObservedAt = b.ObservedAt
	}
	if b.ValidUntil.Before(a.ValidUntil) {
		a.ValidUntil = b.ValidUntil
	}
	return a
}
