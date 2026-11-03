// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tags"
)

func TestTagScalarFactsReplaceClearAndRejectCurrentConflicts(t *testing.T) {
	first := tagScalarLineage{field: "sys_descr", agent: "one", configured: "target", sourceRef: "snmp:configured-target", entity: "device"}
	second := first
	second.agent = "two"
	old := time.Unix(1, 0)
	current := old.Add(time.Second)
	for _, reverse := range []bool{false, true} {
		facts := tagScalarFacts{}
		rows := []tagScalarFact{{at: old, value: "old"}, {at: current, value: "new"}}
		if reverse {
			rows[0], rows[1] = rows[1], rows[0]
		}
		for _, row := range rows {
			if err := facts.add(first, row.at, row.value); err != nil {
				t.Fatal(err)
			}
		}
		values, err := facts.values()
		if err != nil || values["sys_descr"] != "new" {
			t.Fatal("source ordering revived an old scalar")
		}
		if err := facts.add(first, current.Add(time.Second), ""); err != nil {
			t.Fatal(err)
		}
		values, err = facts.values()
		if err != nil || len(values) != 0 {
			t.Fatal("newest empty observation revived an old value")
		}
	}
	facts := tagScalarFacts{}
	for _, value := range []string{"one", "two"} {
		if err := facts.add(first, current, value); err != nil {
			t.Fatal(err)
		}
	}
	if values, err := facts.values(); !errors.Is(err, ErrTagSubjectFactsAmbiguous) || values != nil {
		t.Fatal("equal-time disagreement chose a row")
	}
	if err := facts.add(first, current.Add(time.Second), "latest"); err != nil {
		t.Fatal(err)
	}
	if values, err := facts.values(); err != nil || values["sys_descr"] != "latest" {
		t.Fatal("a superseded conflict poisoned the latest fact")
	}
	if err := facts.add(second, current, "other"); err != nil {
		t.Fatal(err)
	}
	if values, err := facts.values(); !errors.Is(err, ErrTagSubjectFactsAmbiguous) || values != nil {
		t.Fatal("independent current sources chose a winner")
	}
	if err := facts.add(first, current.Add(2*time.Second), "invalid\x00text"); !errors.Is(err, tags.ErrInvalid) {
		t.Fatal("invalid source text became a rule fact")
	}
}

func TestCurrentTagPollClearsRemovedNamesAddressesAndInterfaceInheritance(t *testing.T) {
	old, current := time.Unix(1, 0), time.Unix(2, 0)
	rows := []tagEntityFactRow{
		{entityID: "device", aliasKind: "snmp_device_id", aliasValue: "old-name", agent: "agent", configured: "target", sourceRef: "snmp:sysName", observed: old},
		{entityID: "device", aliasKind: "address", aliasValue: "10.2.0.1", agent: "agent", configured: "target", sourceRef: "snmp:configured-target", observed: current},
		{entityID: "interface", aliasKind: "snmp_interface_id", aliasValue: "7", agent: "agent", configured: "target", sourceRef: "snmp:ifIndex:7", ifName: "old-interface", observed: old},
		{entityID: "interface", aliasKind: "address", aliasValue: "10.2.0.9", agent: "agent", configured: "target", sourceRef: "snmp:ifIndex:7", observed: old},
	}
	latest := map[tagSourceCollection]time.Time{{agent: "agent", configured: "target"}: current}
	device := tags.Subject{Kind: "device", ID: "device", Name: "operator-name"}
	if err := applyCurrentTagEntityFacts(t.Context(), &device, "", rows, latest); err != nil {
		t.Fatal(err)
	}
	if len(device.SNMP) != 0 || len(device.Names) != 0 || len(device.Addresses) != 1 || device.Addresses[0] != netip.MustParseAddr("10.2.0.1") {
		t.Fatal("new poll retained removed scalar or interface address")
	}
	iface := tags.Subject{Kind: "interface", ID: "interface"}
	if err := applyCurrentTagEntityFacts(t.Context(), &iface, "device", rows, latest); err != nil {
		t.Fatal(err)
	}
	if len(iface.SNMP) != 0 || len(iface.Names) != 0 || len(iface.Addresses) != 0 {
		t.Fatal("removed interface inherited parent or stale own facts")
	}
	rows = append(rows,
		tagEntityFactRow{entityID: "interface", aliasKind: "snmp_interface_id", aliasValue: "7", agent: "agent", configured: "target", sourceRef: "snmp:ifIndex:7", ifName: "Gig0/7", observed: current},
		tagEntityFactRow{entityID: "interface", aliasKind: "address", aliasValue: "10.2.0.7", agent: "agent", configured: "target", sourceRef: "snmp:ifIndex:7", observed: current},
		tagEntityFactRow{entityID: "device", aliasKind: "snmp_device_id", aliasValue: "new-name", agent: "agent", configured: "target", sourceRef: "snmp:sysName", observed: current})
	iface = tags.Subject{Kind: "interface", ID: "interface"}
	if err := applyCurrentTagEntityFacts(t.Context(), &iface, "device", rows, latest); err != nil {
		t.Fatal(err)
	}
	if iface.SNMP["sys_name"] != "new-name" || iface.SNMP["if_name"] != "Gig0/7" || len(iface.Addresses) != 1 || iface.Addresses[0] != netip.MustParseAddr("10.2.0.7") {
		t.Fatal("current interface lost its own facts or attested parent metadata")
	}
	for _, fence := range []map[tagSourceCollection]time.Time{
		{},
		{{agent: "agent", configured: "target"}: old},
		{{agent: "agent", configured: "target"}: current.Add(time.Second)},
	} {
		iface = tags.Subject{Kind: "interface", ID: "interface"}
		if err := applyCurrentTagEntityFacts(t.Context(), &iface, "device", rows[4:], fence); err != nil {
			t.Fatal(err)
		}
		if len(iface.SNMP) != 0 || len(iface.Addresses) != 0 || len(iface.Names) != 0 {
			t.Fatal("unmarked or superseded collection supplied observational facts")
		}
	}
}

func TestTagSubjectReferencesRejectFactAndIdentitySubstitution(t *testing.T) {
	for _, ref := range []TagSubjectReference{
		{Kind: "device", ID: "not-a-uuid"},
		{Kind: "agent", ID: "other\nagent"},
		{Kind: "agent", ID: "not-a-registered-agent-uuid"},
		{Kind: "device", ID: "11111111-1111-4111-8111-111111111111", ExporterAgentID: "hint"},
		{Kind: "exporter", ID: "hint", ExporterAgentID: "agent", ExporterSourceRef: "source"},
		{Kind: "exporter", ExporterAgentID: " agent", ExporterSourceRef: "source"},
		{Kind: "unknown", ID: "11111111-1111-4111-8111-111111111111"},
	} {
		if _, err := normalizeTagSubjectReference(ref); !errors.Is(err, tags.ErrInvalid) {
			t.Fatalf("invalid subject reference accepted: %+v", ref)
		}
	}
}

func TestCurrentTagRawSystemNameOverridesOnlyItsOwnPollAlias(t *testing.T) {
	at := time.Unix(10, 0)
	raw, empty, conflicting := "  edge-a  ", "", "different"
	root := tagEntityFactRow{entityID: "device", aliasKind: "address", aliasValue: "192.0.2.1", agent: "agent", configured: "target", sourceRef: "snmp:configured-target", observed: at}
	alias := root
	alias.aliasKind, alias.aliasValue, alias.sourceRef = "snmp_device_id", "edge-a", "snmp:sysName"
	rawRoot, clearRoot, otherRoot := root, root, root
	rawRoot.sysName, clearRoot.sysName, otherRoot.sysName = &raw, &empty, &conflicting
	oldAlias := alias
	oldAlias.observed = at.Add(-time.Second)
	for _, tc := range []struct {
		name      string
		rows      []tagEntityFactRow
		want      string
		ambiguous bool
	}{
		{"legacy", []tagEntityFactRow{root, alias}, "edge-a", false},
		{"raw and alias", []tagEntityFactRow{rawRoot, alias}, raw, false},
		{"alias arrives first", []tagEntityFactRow{alias, rawRoot}, raw, false},
		{"raw only", []tagEntityFactRow{rawRoot}, raw, false},
		{"empty", []tagEntityFactRow{clearRoot}, "", false},
		{"clear fences old alias", []tagEntityFactRow{oldAlias, clearRoot}, "", false},
		{"raw and contradictory alias", []tagEntityFactRow{otherRoot, alias}, "", true},
		{"clear and contradictory alias", []tagEntityFactRow{clearRoot, alias}, "", true},
		{"two contradictory raw roots", []tagEntityFactRow{rawRoot, otherRoot}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, kind := range []string{"device", "interface"} {
				subject := tags.Subject{Kind: kind, ID: "device"}
				rows := append([]tagEntityFactRow(nil), tc.rows...)
				if kind == "interface" {
					subject.ID = "interface"
					rows = append(rows, tagEntityFactRow{entityID: "interface", aliasKind: "snmp_interface_id", aliasValue: "7", agent: "agent", configured: "target", sourceRef: "snmp:ifIndex:7", observed: at})
				}
				err := applyCurrentTagEntityFacts(t.Context(), &subject, "device", rows, map[tagSourceCollection]time.Time{{agent: "agent", configured: "target"}: at})
				if tc.ambiguous {
					if !errors.Is(err, ErrTagSubjectFactsAmbiguous) || len(subject.SNMP) != 0 || len(subject.Names) != 0 {
						t.Fatal("conflicting raw/alias values selected partial facts")
					}
					continue
				}
				if err != nil || subject.SNMP["sys_name"] != tc.want {
					t.Fatalf("%s raw source name lost: %v", kind, err)
				}
				if tc.want != "" && (len(subject.Names) != 1 || subject.Names[0] != tc.want) {
					t.Fatal("name-pattern candidates include the trimmed identity alias")
				}
				if tc.want == "" && len(subject.Names) != 0 {
					t.Fatal("empty metadata revived an old name")
				}
			}
		})
	}
}

func TestFlowInterfaceIndexRequiresTheCurrentCompletePoll(t *testing.T) {
	old, current := time.Unix(1, 0), time.Unix(2, 0)
	latest := map[tagSourceCollection]time.Time{{agent: "agent", configured: "target"}: current}
	row := tagEntityFactRow{entityID: "interface", aliasKind: "snmp_interface_id", aliasValue: "7", agent: "agent", configured: "target", sourceRef: "snmp:ifIndex:7", observed: old}
	subject := tags.Subject{Kind: "interface", ID: "interface", Name: "operator label is not authority"}
	if err := requireCurrentTagInterfaceIndex(t.Context(), &subject, []tagEntityFactRow{row}, latest, 7); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("old interface index survived a newer complete poll: %v", err)
	}
	row.observed = current
	if err := requireCurrentTagInterfaceIndex(t.Context(), &subject, []tagEntityFactRow{row}, latest, 7); err != nil {
		t.Fatal(err)
	}
	row.aliasValue = "8"
	if err := requireCurrentTagInterfaceIndex(t.Context(), &subject, []tagEntityFactRow{row}, latest, 7); !errors.Is(err, ErrTagSubjectFactsAmbiguous) {
		t.Fatal("conflicting current index selected an interface")
	}
}
