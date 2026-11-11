// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package govern

import (
	"regexp"
	"testing"
)

func TestSubjectNetworkPatternsPreserveEquivalentAddressesAndExactFields(t *testing.T) {
	for _, tc := range []struct {
		subject string
		aliases []string
	}{
		{"192.0.2.1", []string{"192.0.2.1", "::ffff:192.0.2.1", "0:0:0:0:0:ffff:c000:201"}},
		{"::ffff:192.0.2.1", []string{"192.0.2.1", "::FFFF:C000:0201"}},
		{"2001:db8::1", []string{"2001:db8::1", "2001:0DB8:0000:0:0:0:0:0001", "2001:db8::0.0.0.1"}},
		{"2001:db8:1:0:0:2:0:3", []string{"2001:db8:1::2:0:3", "2001:DB8:0001:0000::0002:0000:0003"}},
		{"::", []string{"::", "0::", "::0", "0:0:0:0:0:0:0:0", "::0.0.0.0"}},
		{"fe80::1%en0", []string{"fe80::1%en0", "FE80:0:0:0:0:0:0:1%en0"}},
		{"::ffff:192.0.2.1%en0", []string{"::ffff:192.0.2.1%en0", "::FFFF:C000:201%en0"}},
		{"fe80::1%en0.*", []string{"fe80::1%en0.*"}},
	} {
		source, ok := SubjectNetworkPattern(tc.subject)
		if !ok {
			t.Fatal("valid network identity was rejected", tc.subject)
		}
		exact, ok := SubjectNetworkExactPattern(tc.subject)
		if !ok {
			t.Fatal("valid exact network identity was rejected", tc.subject)
		}
		sourceRE, exactRE := regexp.MustCompile(source), regexp.MustCompile(exact)
		for _, alias := range tc.aliases {
			if !sourceRE.MatchString("source "+alias+" end") || !exactRE.MatchString(alias) {
				t.Fatal("network identity lost an equivalent spelling", tc.subject, alias)
			}
			if exactRE.MatchString("source "+alias) || exactRE.MatchString(alias+" ") || exactRE.MatchString("["+alias+"]:443") {
				t.Fatal("exact field matcher admitted surrounding source text", tc.subject, alias)
			}
		}
	}
}

func TestSubjectNetworkPatternsKeepNeighborsZonesAndUntrustedSyntaxSeparate(t *testing.T) {
	for _, tc := range []struct {
		subject, text string
		match         bool
	}{
		{"192.0.2.1", "snmp:192.0.2.1:161", true},
		{"192.0.2.1", "observed 192.0.2.1. Next sentence", true},
		{"192.0.2.1", "192.0.2.11", false},
		{"192.0.2.1", "1192.0.2.1", false},
		{"192.0.2.1", "192.0.2.1.example.test", false},
		{"192.0.2.1", "2001:db8::192.0.2.1", false},
		{"2001:db8::1", "snmp:2001:0DB8::0001", true},
		{"2001:db8::1", "[2001:db8::1]:443", true},
		{"2001:db8::1", "2001:db8::11", false},
		{"2001:db8::1", "12001:db8::1", false},
		{"fe80::1%en0", "snmp:[FE80::1%en0]:161", true},
		{"fe80::1%en0", "fe80::1%en1", false},
		{"fe80::1%en0", "fe80::1%EN0", false},
		{"fe80::1%en0", "fe80::1%en01", false},
		{"fe80::1%en0", "fe80::1%en0]suffix", false},
		{"fe80::1%en0", "[fe80::1%en0]suffix", false},
		{"fe80::1%en0.*", "fe80::1%en0anything", false},
		{"::ffff:192.0.2.1%en0", "192.0.2.1", false},
	} {
		pattern, ok := SubjectNetworkPattern(tc.subject)
		if !ok || regexp.MustCompile(pattern).MatchString(tc.text) != tc.match {
			t.Fatal("network subject matcher merged a neighbor, zone or executable expression", tc)
		}
	}
	for _, subject := range []string{"", "not an IP", "192.0.2.01", "192.0.2.1/24", "2001:db8::1::2"} {
		for _, build := range []func(string) (string, bool){SubjectNetworkPattern, SubjectNetworkExactPattern} {
			if pattern, ok := build(subject); ok || pattern != "" {
				t.Fatal("invalid network identity became an executable pattern", subject, pattern)
			}
		}
	}
}
