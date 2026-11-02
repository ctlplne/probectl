// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tags

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

const (
	tenantA  = "11111111-1111-4111-8111-111111111111"
	tenantB  = "22222222-2222-4222-8222-222222222222"
	contextA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	contextB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	tagID    = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	ruleA    = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	ruleB    = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
)

func testScope() Scope { return Scope{TenantID: tenantA, ContextID: contextA} }

func testSubject() Subject {
	return Subject{Scope: testScope(), Kind: "exporter", ID: "exporter-1",
		AddressSide: "exporter", Address: netip.MustParseAddr("10.1.2.3"),
		Name: "edge-1", SNMP: map[string]string{"sys_name": "edge-1"}}
}

func testDefinition() Definition { return Definition{TenantID: tenantA, ID: tagID, Key: "customer"} }

func TestResolveCurrentRevisionRetagsHistoricalSubjectWithDeterministicPrecedence(t *testing.T) {
	scope, subject, definition := testScope(), testSubject(), testDefinition()
	imported := Assignment{Scope: scope, TagID: tagID, TargetKind: "exporter",
		TargetID: subject.ID, Value: "imported", Source: "netbox", SourceRef: "ci-17"}
	wide := Rule{Scope: scope, ID: ruleA, TagID: tagID, TargetKind: "exporter",
		Match: "cidr", AddressSide: "exporter", CIDR: "10.1.0.0/16", Value: "wide"}
	narrow := Rule{Scope: scope, ID: ruleB, TagID: tagID, TargetKind: "exporter",
		Match: "cidr", AddressSide: "exporter", CIDR: "10.1.2.0/24", Value: "narrow"}
	got, err := resolve(scope, 1, subject, []Definition{definition},
		[]Assignment{imported}, []Rule{wide, narrow})
	if err != nil || len(got) != 1 || got[0].Value != "narrow" ||
		got[0].Source != "rule" || got[0].SourceID != ruleB || got[0].Revision != 1 {
		t.Fatalf("longest prefix did not beat import: %+v, %v", got, err)
	}
	narrow.Value = "renamed"
	changed, err := resolve(scope, 2, subject, []Definition{definition},
		[]Assignment{imported}, []Rule{wide, narrow})
	if err != nil || len(changed) != 1 || changed[0].Value != "renamed" || changed[0].Revision != 2 {
		t.Fatalf("current rule revision did not retag the same subject: %+v, %v", changed, err)
	}
	manual := Assignment{Scope: scope, TagID: tagID, TargetKind: "exporter",
		TargetID: subject.ID, Value: "manual", Source: "manual"}
	got, err = resolve(scope, 2, subject, []Definition{definition},
		[]Assignment{imported, manual}, []Rule{wide, narrow})
	if err != nil || len(got) != 1 || got[0].Value != "manual" || got[0].Source != "manual" {
		t.Fatalf("manual value did not win: %+v, %v", got, err)
	}
	got, err = resolve(scope, 2, subject, []Definition{definition}, []Assignment{imported}, nil)
	if err != nil || len(got) != 1 || got[0].Value != "imported" || got[0].SourceID != "ci-17" {
		t.Fatalf("reviewed import did not remain a suggestion: %+v, %v", got, err)
	}
}

func TestResolveRulePriorityAndImmutableIDBreakTies(t *testing.T) {
	scope, subject, definition := testScope(), testSubject(), testDefinition()
	first := Rule{Scope: scope, ID: ruleA, TagID: tagID, TargetKind: "exporter",
		Match: "cidr", AddressSide: "exporter", CIDR: "10.1.2.0/24", Value: "first"}
	second := first
	second.ID, second.Value, second.Priority = ruleB, "second", 1
	got, err := resolve(scope, 1, subject, []Definition{definition}, nil, []Rule{first, second})
	if err != nil || got[0].Value != "second" {
		t.Fatalf("higher explicit priority lost: %+v, %v", got, err)
	}
	second.Priority = 0
	got, err = resolve(scope, 1, subject, []Definition{definition}, nil, []Rule{second, first})
	if err != nil || got[0].Value != "first" {
		t.Fatalf("immutable ID tie-break depended on input order: %+v, %v", got, err)
	}
}

func TestResolveNameAndCollectedSNMPFieldsStayBounded(t *testing.T) {
	scope, subject, definition := testScope(), testSubject(), testDefinition()
	nameRule := Rule{Scope: scope, ID: ruleA, TagID: tagID, TargetKind: "exporter",
		Match: "name_pattern", NamePattern: `^edge-[0-9]+$`, Value: "name"}
	got, err := resolve(scope, 1, subject, []Definition{definition}, nil, []Rule{nameRule})
	if err != nil || len(got) != 1 || got[0].Value != "name" {
		t.Fatalf("bounded name rule missed: %+v, %v", got, err)
	}
	snmpRule := Rule{Scope: scope, ID: ruleB, TagID: tagID, TargetKind: "exporter",
		Match: "snmp_field", SNMPField: "sys_name", SNMPValue: "edge-1", Value: "snmp", Priority: 1}
	got, err = resolve(scope, 1, subject, []Definition{definition}, nil,
		[]Rule{nameRule, snmpRule})
	if err != nil || len(got) != 1 || got[0].Value != "snmp" {
		t.Fatalf("collected SNMP field did not match: %+v, %v", got, err)
	}
	subject.Name, subject.SNMP = "", nil
	got, err = resolve(scope, 1, subject, []Definition{definition}, nil,
		[]Rule{nameRule, snmpRule})
	if err != nil || len(got) != 0 {
		t.Fatalf("missing name or inventory fact selected a tag: %+v, %v", got, err)
	}
}

func TestResolveRejectsMixedTenantContextAndUntrustedRuleShapes(t *testing.T) {
	scope, subject, definition := testScope(), testSubject(), testDefinition()
	base := Rule{Scope: scope, ID: ruleA, TagID: tagID, TargetKind: "exporter",
		Match: "cidr", AddressSide: "exporter", CIDR: "10.1.2.0/24", Value: "edge"}
	for _, tc := range []struct {
		name string
		edit func(*Rule)
		want error
	}{
		{"foreign tenant", func(r *Rule) { r.TenantID = tenantB }, ErrScopeMismatch},
		{"foreign context", func(r *Rule) { r.ContextID = contextB }, ErrScopeMismatch},
		{"host bits in CIDR", func(r *Rule) { r.CIDR = "10.1.2.3/24" }, ErrInvalid},
		{"wrong address side", func(r *Rule) { r.AddressSide = "secret" }, ErrInvalid},
		{"regex too long", func(r *Rule) {
			r.Match = "name_pattern"
			r.AddressSide, r.CIDR = "", ""
			r.NamePattern = strings.Repeat("x", 257)
		}, ErrInvalid},
		{"unsupported SNMP field", func(r *Rule) {
			r.Match = "snmp_field"
			r.AddressSide, r.CIDR = "", ""
			r.SNMPField, r.SNMPValue = "private_oid", "secret"
		}, ErrInvalid},
		{"oversize value", func(r *Rule) { r.Value = strings.Repeat("x", 129) }, ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := base
			tc.edit(&rule)
			if _, err := resolve(scope, 1, subject, []Definition{definition}, nil,
				[]Rule{rule}); !errors.Is(err, tc.want) {
				t.Fatalf("invalid rule admitted: %v", err)
			}
		})
	}
	foreignSubject := subject
	foreignSubject.TenantID = tenantB
	if _, err := resolve(scope, 1, foreignSubject, []Definition{definition}, nil, nil); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("foreign subject admitted: %v", err)
	}
	foreignDefinition := definition
	foreignDefinition.TenantID = tenantB
	if _, err := resolve(scope, 1, subject, []Definition{foreignDefinition}, nil, nil); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("foreign definition admitted: %v", err)
	}
	foreignAssignment := Assignment{Scope: Scope{TenantID: tenantB, ContextID: contextA},
		TagID: tagID, TargetKind: "exporter", TargetID: subject.ID,
		Value: "other tenant", Source: "manual"}
	if _, err := resolve(scope, 1, subject, []Definition{definition},
		[]Assignment{foreignAssignment}, nil); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("foreign assignment admitted: %v", err)
	}
}

func TestResolveRejectsReservedKeysAndDuplicateAssignments(t *testing.T) {
	scope, subject, definition := testScope(), testSubject(), testDefinition()
	for _, key := range []string{"tenant_id", "agent_id", "probectl_device_if_oper_status", "Bad Key"} {
		def := definition
		def.Key = key
		if _, err := resolve(scope, 1, subject, []Definition{def}, nil, nil); !errors.Is(err, ErrInvalid) {
			t.Fatalf("reserved key %q admitted: %v", key, err)
		}
	}
	assignment := Assignment{Scope: scope, TagID: tagID, TargetKind: "exporter",
		TargetID: subject.ID, Value: "one", Source: "manual"}
	if _, err := resolve(scope, 1, subject, []Definition{definition},
		[]Assignment{assignment, assignment}, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate manual assignment admitted: %v", err)
	}
}

func TestSnapshotPinsRevisionAndRejectsCrossContextSubject(t *testing.T) {
	scope, subject := testScope(), testSubject()
	definitions := []Definition{testDefinition()}
	rules := []Rule{{Scope: scope, ID: ruleA, TagID: tagID, TargetKind: "exporter",
		Match: "cidr", AddressSide: "exporter", CIDR: "10.1.0.0/16", Value: "old"}}
	snapshot, err := NewSnapshot(scope, 7, definitions, nil, rules)
	if err != nil {
		t.Fatal(err)
	}
	if revision, err := snapshot.Revision(); err != nil || revision != 7 {
		t.Fatalf("snapshot did not expose its pinned revision: %d, %v", revision, err)
	}
	rules[0].Value = "new"
	definitions[0].Key = "renamed"
	got, err := snapshot.Resolve(subject)
	if err != nil || len(got) != 1 || got[0].Key != "customer" ||
		got[0].Value != "old" || got[0].Revision != 7 {
		t.Fatalf("existing query page changed after rule edit: %+v, %v", got, err)
	}
	subject.ContextID = contextB
	if _, err := snapshot.Resolve(subject); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("foreign context resolved through snapshot: %v", err)
	}
}

func TestSnapshotZeroValueFailsClosed(t *testing.T) {
	var snapshot Snapshot
	if _, err := snapshot.Revision(); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("uninitialized snapshot exposed a revision: %v", err)
	}
	_, err := snapshot.Resolve(Subject{Kind: "exporter", ID: "exporter-1"})
	if !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("uninitialized snapshot silently returned untagged data: %v", err)
	}
}

func TestSnapshotAdmitsPublishedRuleCardinalityWithoutTruncating(t *testing.T) {
	scope, subject := testScope(), testSubject()
	rules := make([]Rule, maxRules)
	for i := range rules {
		// Distinct /32s force the snapshot to retain the complete candidate set;
		// a low input cap or silent truncation loses the final matching rule.
		address := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		rules[i] = Rule{Scope: scope, ID: fmt.Sprintf("00000000-0000-4000-8000-%012x", i+1),
			TagID: tagID, TargetKind: "exporter", Match: "cidr",
			AddressSide: "exporter", CIDR: netip.PrefixFrom(address, 32).String(), Value: "customer-a"}
	}
	lastPrefix := netip.MustParsePrefix(rules[len(rules)-1].CIDR)
	subject.Address = lastPrefix.Addr()
	snapshot, err := NewSnapshot(scope, 9, []Definition{testDefinition()}, nil, rules)
	if err != nil {
		t.Fatalf("published 25,000-rule tier rejected: %v", err)
	}
	got, err := snapshot.Resolve(subject)
	if err != nil || len(got) != 1 || got[0].SourceID != rules[len(rules)-1].ID {
		t.Fatalf("final rule missing or wrong: %+v, %v", got, err)
	}
}

func TestExporterTargetIDKeepsAgentAndSourceRefDistinctAtStoredLimit(t *testing.T) {
	first, err := ExporterTargetID("a.b", "c")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ExporterTargetID("a", "b.c")
	if err != nil || first == second {
		t.Fatalf("agent/source pair collided: %q, %q, %v", first, second, err)
	}
	long, err := ExporterTargetID("agent-1", strings.Repeat("r", 1024))
	if err != nil || len(long) > maxTargetIDBytes {
		t.Fatalf("stored 1024-byte source ref cannot form a target: %d, %v", len(long), err)
	}
	scope := testScope()
	assignment := Assignment{Scope: scope, TagID: tagID, TargetKind: "exporter",
		TargetID: long, Value: "customer-a", Source: "manual"}
	subject := Subject{Scope: scope, Kind: "exporter", ID: long}
	got, err := resolve(scope, 1, subject, []Definition{testDefinition()},
		[]Assignment{assignment}, nil)
	if err != nil || len(got) != 1 || got[0].Value != "customer-a" {
		t.Fatalf("long owned exporter ref was dropped: %+v, %v", got, err)
	}
	if _, err := ExporterTargetID("", "ref"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing agent admitted: %v", err)
	}
}
