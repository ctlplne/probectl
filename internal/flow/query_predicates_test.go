// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"reflect"
	"strings"
	"testing"
)

func TestQueryPredicatesCanonicalizeTypedValues(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input QueryPredicate
		want  []string
	}{
		{"port range", QueryPredicate{"dst_port", QueryBetween, []string{"00443", "08443"}}, []string{"443", "8443"}},
		{"mapped address", QueryPredicate{"src_addr", QueryEqual, []string{"::ffff:192.0.2.7"}}, []string{"192.0.2.7"}},
		{"masked prefix", QueryPredicate{"src_addr", QueryCIDR, []string{"192.0.2.7/24"}}, []string{"192.0.2.0/24"}},
		{"mapped prefix", QueryPredicate{"dst_addr", QueryNotCIDR, []string{"::ffff:192.0.2.7/120"}}, []string{"192.0.2.0/24"}},
		{"v6 prefix", QueryPredicate{"src_prefix", QueryEqual, []string{"2001:db8:1234::7/48"}}, []string{"2001:db8:1234::/48"}},
		{"timestamp", QueryPredicate{"ts", QueryEqual, []string{"2026-10-27T14:00:00+02:00"}}, []string{"2026-10-27T12:00:00Z"}},
		{"flags", QueryPredicate{"tcp_flag_names", QueryEqual, []string{"ack,syn,syn"}}, []string{"SYN,ACK"}},
		{"zero flags", QueryPredicate{"tcp_flag_names", QueryEqual, []string{"none"}}, []string{"NONE"}},
		{"unknown next hop", QueryPredicate{"next_hop", QueryEqual, []string{""}}, []string{""}},
		{"missing ASN label", QueryPredicate{"src_as_name", QueryIn, []string{"", "Example", "Example"}}, []string{"", "Example"}},
		{"integer precision", QueryPredicate{"raw_bytes", QueryEqual, []string{"18446744073709551615"}}, []string{"18446744073709551615"}},
		{"literal text", QueryPredicate{"src_as_name", QueryEqual, []string{"customer' OR 1=1 --"}}, []string{"customer' OR 1=1 --"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeQueryPredicates([]QueryPredicate{tc.input})
			if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0].Values, tc.want) {
				t.Fatalf("normalized = %+v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestQueryPredicatesRefuseUntrustedGrammar(t *testing.T) {
	for _, predicate := range []QueryPredicate{
		{"tenant_id", QueryEqual, []string{"foreign"}},
		{"src_addr", "raw_sql", []string{"1=1"}},
		{"dst_port", QueryBetween, []string{"1024", "80"}},
		{"dst_port", QueryEqual, []string{"65536"}},
		{"src_asn", QueryEqual, []string{"4294967296"}},
		{"raw_bytes", QueryEqual, []string{"18446744073709551616"}},
		{"dst_port", QueryEqual, []string{"-1"}},
		{"dst_port", QueryEqual, []string{"1 OR 1=1"}},
		{"src_addr", QueryEqual, []string{"fe80::1%eth0"}},
		{"src_addr", QueryCIDR, []string{"192.0.2.1/33"}},
		{"src_addr", QueryCIDR, []string{"::ffff:192.0.2.1/80"}},
		{"src_addr", QueryCIDR, []string{""}},
		{"src_as_name", QueryBetween, []string{"A", "Z"}},
		{"ts", QueryBetween, []string{"2026-10-28T00:00:00Z", "2026-10-27T00:00:00Z"}},
		{"ts", QueryEqual, []string{"yesterday"}},
		{"tcp_flag_names", QueryHasAnyFlag, []string{"SYN,ACK"}},
		{"tcp_flag_names", QueryHasAnyFlag, []string{"NONE"}},
		{"tcp_flag_names", QueryEqual, []string{"UNKNOWN"}},
		{"src_as_name", QueryEqual, []string{strings.Repeat("x", MaxQueryValueBytes+1)}},
		{"src_addr", QueryEqual, []string{}},
		{"src_addr", QueryEqual, []string{"192.0.2.1", "192.0.2.2"}},
	} {
		if _, err := NormalizeQueryPredicates([]QueryPredicate{predicate}); err == nil {
			t.Fatalf("accepted invalid predicate %+v", predicate)
		}
	}
	tooMany := make([]QueryPredicate, MaxQueryPredicates+1)
	if _, err := NormalizeQueryPredicates(tooMany); err == nil {
		t.Fatal("predicate count is unbounded")
	}
}

func TestQueryPredicateErrorsDoNotEchoUntrustedContent(t *testing.T) {
	const marker = "private-input-marker"
	for _, predicate := range []QueryPredicate{
		{marker, QueryEqual, []string{"x"}},
		{"src_addr", QueryOperator(marker), []string{"192.0.2.1"}},
		{"src_addr", QueryEqual, []string{marker}},
	} {
		_, err := NormalizeQueryPredicates([]QueryPredicate{predicate})
		if err == nil || strings.Contains(err.Error(), marker) {
			t.Fatalf("predicate error must be sanitized: %v", err)
		}
	}
}
