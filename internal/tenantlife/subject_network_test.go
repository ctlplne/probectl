// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"regexp"
	"strings"
	"testing"
)

type networkSubjectCase struct {
	subject     string
	match, keep []string
}

func networkSubjectCases() []networkSubjectCase {
	return []networkSubjectCase{
		{"10.0.0.1", []string{"10.0.0.1", "snmp:10.0.0.1", "https://10.0.0.1:443/", "::ffff:10.0.0.1", "0:0:0:0:0:FFFF:0A00:0001", "Device 10.0.0.1. Next sentence."}, []string{"10.0.0.10", "110.0.0.1", "host10.0.0.1", "10.0.0.1.example", "::1:10.0.0.1", "10.0.0.1%zone"}},
		{"2001:db8::1", []string{"2001:db8::1", "[2001:DB8::1]:443", "snmp:2001:db8::1", "2001:0DB8:0:00::0001", "2001:db8:0:0:0:0:0.0.0.1"}, []string{"2001:db8::10", "2001:db8::1:1", "12001:db8::1", "fe80:2001:db8::1", "2001:db8::1%en1"}},
		{"fe80::1%en1", []string{"fe80::1%en1", "[FE80:0::1%en1]:161", "snmp:fe80::1%en1", `{"address":"fe80::1%en1"}`}, []string{"fe80::1%en10", "fe80::10%en1", "fe80::1%EN1", "fe80::1", "fe80::1%en1-extra", "fe80::1%en1]extra", "[fe80::1%en1]extra"}},
		{"::1", []string{"::1", "[::1]:443", "0:0:0:0:0:0:0:1"}, []string{"::10", "1::1", "::1:1", "::1%lo0"}},
	}
}

func TestNetworkSubjectMatchesCompleteEquivalentAddresses(t *testing.T) {
	for _, tc := range networkSubjectCases() {
		pattern, ok := literalSubjectPattern(tc.subject)
		if !ok {
			t.Fatal("missing network matcher", tc.subject)
		}
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range tc.match {
			if !compiled.MatchString(value) {
				t.Errorf("subject %q omitted %q", tc.subject, value)
			}
		}
		for _, value := range tc.keep {
			if compiled.MatchString(value) {
				t.Errorf("subject %q selected unrelated %q", tc.subject, value)
			}
		}
	}
}

func TestNetworkSubjectCannotUseUnboundedSubstringDeletion(t *testing.T) {
	for _, subject := range []string{"10.0.0.1", "2001:db8::1", "fe80::1%en1"} {
		aliases := newSubjectAliasSet(subject)
		if len(aliases.safeContainsPatterns()) == 0 {
			t.Fatal("network subject lost its literal text-reference reach", subject)
		}
		policy := subjectPostgresTablePolicies["device_counter_capture_sources"]
		predicate := subjectTableMatchPredicate(policy)
		args := subjectTableMatchArgs("11111111-1111-4111-8111-111111111111", aliases, policy)
		if !strings.Contains(predicate, "~ subject_pattern.value") || strings.Contains(predicate, "ILIKE") || len(args) != 4 {
			t.Fatal("source deletion has no bound complete network-identity matcher")
		}
	}
}

func TestNetworkSubjectAliasesPreserveDistinctZones(t *testing.T) {
	aliases := newSubjectAliasSet("fe80::1%en1")
	aliases.add("FE80:0::1%EN1")
	aliases.add("fe80:0:0:0:0:0:0:1%en1")
	plain, network := aliases.exactSubjectValues()
	if len(aliases.values()) != 2 || len(plain) != 0 || len(network) != 2 {
		t.Fatal("address aliases collapsed distinct case-sensitive zones or duplicated an equivalent address")
	}
}
