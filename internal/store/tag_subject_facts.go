// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type tagScalarLineage struct{ field, agent, configured, sourceRef, entity string }
type tagScalarFact struct {
	at        time.Time
	value     string
	ambiguous bool
}
type tagScalarFacts map[tagScalarLineage]tagScalarFact

func (facts tagScalarFacts) add(lineage tagScalarLineage, at time.Time, value string) error {
	if err := tags.ValidateSNMPFact(lineage.field, value); err != nil {
		return err
	}
	old, exists := facts[lineage]
	if !exists || at.After(old.at) {
		facts[lineage] = tagScalarFact{at: at, value: value}
		return nil
	}
	if at.Equal(old.at) && value != old.value {
		old.ambiguous = true
		facts[lineage] = old
	}
	return nil
}

func (facts tagScalarFacts) values() (map[string]string, error) {
	out := map[string]string{}
	for lineage, fact := range facts {
		if fact.ambiguous {
			return nil, ErrTagSubjectFactsAmbiguous
		}
		if fact.value == "" {
			continue
		}
		if value, exists := out[lineage.field]; exists && value != fact.value {
			return nil, ErrTagSubjectFactsAmbiguous
		}
		out[lineage.field] = fact.value
	}
	return out, nil
}

type tagSourceCollection struct{ agent, configured string }
type tagEntityFactRow struct {
	entityID, aliasKind, aliasValue, sourceRef, agent, configured string
	ifName, ifDescr, sysDescr                                     string
	sysName                                                       *string
	observed                                                      time.Time
}

// Facts stay private to the store transaction. The complete current predicate
// authorizes each observation. A configured-target claim marks the collector's
// latest complete SNMP poll; every claim in that poll shares ObservedAt.
func loadCurrentTagEntityFacts(ctx context.Context, sc tenancy.Scope, subject *tags.Subject, parent string, maxBytes int64, charge func(...string) error) error {
	limit := maxBytes/2048 + 1
	rows, err := sc.Q.Query(ctx, `SELECT e.entity_id::text,e.alias_kind,e.alias_value,e.source_ref,e.agent_id,e.configured_ref,
        COALESCE(e.interface_name,''),COALESCE(e.interface_description,''),COALESCE(e.snmp_system_description,''),e.snmp_system_name,e.observed_at
        FROM entity_evidence e WHERE e.tenant_id=$1 AND e.context_id=$2 AND e.source_kind='device_target'
        AND (e.entity_id=$3 OR ($4='device' AND EXISTS(SELECT 1 FROM entities child
         WHERE child.tenant_id=$1 AND child.context_id=$2 AND child.id=e.entity_id AND child.kind='interface' AND child.parent_entity_id=$3))
         OR ($4='interface' AND e.entity_id=NULLIF($5,'')::uuid
         AND (e.alias_kind='snmp_device_id' OR (e.alias_kind='address' AND e.source_ref='snmp:configured-target'))))
        AND `+currentEntityEvidenceSnapshotSQL()+` ORDER BY e.observed_at DESC,e.id LIMIT $6`, subject.TenantID, subject.ContextID, subject.ID, subject.Kind, parent, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	collections := map[tagSourceCollection]bool{}
	var agents, configured []string
	observations := []tagEntityFactRow{}
	var seen int64
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		seen++
		if seen >= limit {
			return ErrTagSnapshotBudget
		}
		var row tagEntityFactRow
		if err := rows.Scan(&row.entityID, &row.aliasKind, &row.aliasValue, &row.sourceRef, &row.agent, &row.configured, &row.ifName, &row.ifDescr, &row.sysDescr, &row.sysName, &row.observed); err != nil {
			return err
		}
		if err := charge(row.entityID, row.aliasKind, row.aliasValue, row.sourceRef, row.agent, row.configured, row.ifName, row.ifDescr, row.sysDescr); err != nil {
			return err
		}
		if row.sysName != nil {
			if err := charge(*row.sysName); err != nil {
				return err
			}
		}
		observations = append(observations, row)
		key := tagSourceCollection{agent: row.agent, configured: row.configured}
		if !collections[key] {
			if err := charge(row.agent, row.configured); err != nil {
				return err
			}
			collections[key] = true
			agents, configured = append(agents, row.agent), append(configured, row.configured)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	latest, err := loadTagCollectionFences(ctx, sc, subject, agents, configured, charge)
	if err != nil {
		return err
	}
	return applyCurrentTagEntityFacts(ctx, subject, parent, observations, latest)
}

// Historical collection timestamps only remove older facts; they never add
// names, addresses or SNMP values. Keeping an expired latest poll as a fence
// prevents expiry or sender rotation from reviving an older still-live poll.
func loadTagCollectionFences(ctx context.Context, sc tenancy.Scope, subject *tags.Subject, agents, configured []string, charge func(...string) error) (map[tagSourceCollection]time.Time, error) {
	latest := map[tagSourceCollection]time.Time{}
	if len(agents) == 0 {
		return latest, nil
	}
	rows, err := sc.Q.Query(ctx, `SELECT e.agent_id,e.configured_ref,max(e.observed_at)
        FROM entity_evidence e WHERE e.tenant_id=$1 AND e.context_id=$2
        AND e.source_kind='device_target' AND e.alias_kind='address' AND e.source_ref='snmp:configured-target'
        AND e.observed_at<=transaction_timestamp()
        AND (e.agent_id,e.configured_ref) IN (SELECT * FROM unnest($3::text[],$4::text[]))
        GROUP BY e.agent_id,e.configured_ref`, subject.TenantID, subject.ContextID, agents, configured)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var key tagSourceCollection
		var at time.Time
		if err := rows.Scan(&key.agent, &key.configured, &at); err != nil {
			return nil, err
		}
		if err := charge(key.agent, key.configured); err != nil {
			return nil, err
		}
		latest[key] = at
	}
	return latest, rows.Err()
}

func applyCurrentTagEntityFacts(ctx context.Context, subject *tags.Subject, parent string, observations []tagEntityFactRow, latest map[tagSourceCollection]time.Time) error {
	rawNames, err := currentTagSystemNames(ctx, observations, latest)
	if err != nil {
		return err
	}
	addresses := map[netip.Addr]bool{}
	prefixes := map[netip.Prefix]bool{}
	scalars, parentScalars := tagScalarFacts{}, tagScalarFacts{}
	currentInterface := false
	for _, row := range observations {
		if err := ctx.Err(); err != nil {
			return err
		}
		epoch, exists := latest[tagSourceCollection{agent: row.agent, configured: row.configured}]
		if !exists || !row.observed.Equal(epoch) {
			continue
		}
		own := row.entityID == subject.ID
		if row.aliasKind == "address" && subject.Kind != "prefix" && (own || subject.Kind == "device") {
			address, err := netip.ParseAddr(row.aliasValue)
			if err != nil || address.Zone() != "" {
				return tags.ErrInvalid
			}
			addresses[address.Unmap()] = true
		}
		if row.aliasKind == "prefix" && subject.Kind == "prefix" && own {
			prefix, err := netip.ParsePrefix(row.aliasValue)
			if err != nil || prefix.Addr().Zone() != "" || prefix != prefix.Masked() {
				return tags.ErrInvalid
			}
			prefixes[prefix] = true
		}
		target := scalars
		if subject.Kind == "interface" && row.entityID == parent {
			target = parentScalars
		}
		add := func(field, value string) error {
			return target.add(tagScalarLineage{field: field, agent: row.agent, configured: row.configured, sourceRef: row.sourceRef, entity: row.entityID}, row.observed, value)
		}
		if row.aliasKind == "snmp_device_id" && (own || (subject.Kind == "interface" && row.entityID == parent)) {
			value, err := rawNames.legacyValue(row)
			if err != nil {
				return err
			}
			if err := add("sys_name", value); err != nil {
				return err
			}
		}
		if row.aliasKind == "address" && row.sourceRef == "snmp:configured-target" && (own || (subject.Kind == "interface" && row.entityID == parent)) {
			if err := add("sys_descr", row.sysDescr); err != nil {
				return err
			}
			if row.sysName != nil {
				if err := add("sys_name", *row.sysName); err != nil {
					return err
				}
			}
		}
		if subject.Kind == "interface" && own && row.aliasKind == "snmp_interface_id" {
			currentInterface = true
			if err := add("if_name", row.ifName); err != nil {
				return err
			}
			if err := add("if_descr", row.ifDescr); err != nil {
				return err
			}
		}
	}
	if subject.Kind == "interface" {
		if currentInterface {
			for lineage, fact := range parentScalars {
				scalars[lineage] = fact
			}
		} else {
			// A stale/removed interface cannot inherit current parent facts.
			addresses = map[netip.Addr]bool{}
			scalars = tagScalarFacts{}
		}
	}
	values, err := scalars.values()
	if err != nil {
		return err
	}
	subject.SNMP = values
	for address := range addresses {
		subject.Addresses = append(subject.Addresses, address)
	}
	for prefix := range prefixes {
		subject.Prefixes = append(subject.Prefixes, prefix)
	}
	sort.Slice(subject.Addresses, func(i, j int) bool { return subject.Addresses[i].Less(subject.Addresses[j]) })
	sort.Slice(subject.Prefixes, func(i, j int) bool { return subject.Prefixes[i].String() < subject.Prefixes[j].String() })
	for _, field := range []string{"sys_name", "if_name"} {
		if value := values[field]; value != "" {
			subject.Names = append(subject.Names, value)
		}
	}
	return ctx.Err()
}

type tagSystemNameLineage struct{ entity, agent, configured string }
type tagSystemNames map[tagSystemNameLineage]string

// An optional raw value overrides the legacy normalized alias in the same
// complete poll, even when empty. Index storage shares each charged row's
// fixed overhead; strings refer to the already charged observation bytes.
func currentTagSystemNames(ctx context.Context, observations []tagEntityFactRow, latest map[tagSourceCollection]time.Time) (tagSystemNames, error) {
	names := tagSystemNames{}
	for _, row := range observations {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if row.sysName == nil || row.aliasKind != "address" || row.sourceRef != "snmp:configured-target" ||
			!row.observed.Equal(latest[tagSourceCollection{agent: row.agent, configured: row.configured}]) {
			continue
		}
		if err := tags.ValidateSNMPFact("sys_name", *row.sysName); err != nil {
			return nil, err
		}
		key := tagSystemNameLineage{entity: row.entityID, agent: row.agent, configured: row.configured}
		if previous, exists := names[key]; exists && previous != *row.sysName {
			return nil, ErrTagSubjectFactsAmbiguous
		}
		names[key] = *row.sysName
	}
	return names, nil
}

func (names tagSystemNames) legacyValue(row tagEntityFactRow) (string, error) {
	value, present := names[tagSystemNameLineage{entity: row.entityID, agent: row.agent, configured: row.configured}]
	if !present {
		return row.aliasValue, nil
	}
	if strings.TrimSpace(value) != row.aliasValue {
		return "", ErrTagSubjectFactsAmbiguous
	}
	// The root observation supplies the raw fact. Do not add the trimmed alias
	// as a second scalar or a name-pattern candidate.
	return "", nil
}
