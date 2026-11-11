// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"reflect"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestSNMPExactCountersKeepTypedFullWidthZeroAndRefuseRoundedOrForgedValues(t *testing.T) {
	for _, scenario := range []struct {
		name  string
		pdu   gosnmp.SnmpPDU
		width uint32
		want  *CounterValue
	}{
		{"wide64", gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: uint64(1<<53 + 1)}, 64, &CounterValue{Value: 1<<53 + 1, Width: 64}},
		{"max64", gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: ^uint64(0)}, 64, &CounterValue{Value: ^uint64(0), Width: 64}},
		{"max32", gosnmp.SnmpPDU{Type: gosnmp.Counter32, Value: uint32(1<<32 - 1)}, 32, &CounterValue{Value: 1<<32 - 1, Width: 32}},
		{"zero", gosnmp.SnmpPDU{Type: gosnmp.Counter32, Value: uint(0)}, 32, &CounterValue{Value: 0, Width: 32}},
		{"signed-nonnegative-decoder", gosnmp.SnmpPDU{Type: gosnmp.Counter32, Value: int64(42)}, 32, &CounterValue{Value: 42, Width: 32}},
		{"rounded", gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: float64(1 << 53)}, 64, nil},
		{"negative", gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: int64(-1)}, 64, nil},
		{"text", gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: "9007199254740993"}, 64, nil},
		{"bytes", gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: []byte("9007199254740993")}, 64, nil},
		{"out-of-width", gosnmp.SnmpPDU{Type: gosnmp.Counter32, Value: uint64(1 << 32)}, 32, nil},
		{"wrong-counter-type", gosnmp.SnmpPDU{Type: gosnmp.Counter32, Value: uint64(42)}, 64, nil},
		{"gauge", gosnmp.SnmpPDU{Type: gosnmp.Gauge32, Value: uint32(42)}, 32, nil},
		{"absent-type", gosnmp.SnmpPDU{Value: uint64(42)}, 64, nil},
		{"unsupported-width", gosnmp.SnmpPDU{Type: gosnmp.Counter32, Value: uint32(42)}, 16, nil},
		{"nil", gosnmp.SnmpPDU{Type: gosnmp.Counter32}, 32, nil},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if got := snmpExactCounter(scenario.pdu, scenario.width); !reflect.DeepEqual(got, scenario.want) {
				t.Fatal("SNMP source counter changed its original typed integer or invented exact evidence", got, scenario.want)
			}
		})
	}
}

func TestSNMPPollKeepsExactHCAndPerInterface32BitFallbackInBothTenants(t *testing.T) {
	for _, tenant := range []string{"red", "blue"} {
		conn := healthyConn()
		conn.tables[oidIfHCInOctets][1] = gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: uint64(1<<53 + 1)}
		conn.tables[oidIfHCOutOctets][1] = gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: ^uint64(0)}
		delete(conn.tables[oidIfHCInOctets], 2)
		delete(conn.tables[oidIfHCOutOctets], 2)
		conn.tables[oidIfInOctets] = map[uint32]gosnmp.SnmpPDU{1: {Type: gosnmp.Counter32, Value: uint32(123)}, 2: {Type: gosnmp.Counter32, Value: uint32(1<<32 - 1)}}
		conn.tables[oidIfOutOctets] = map[uint32]gosnmp.SnmpPDU{1: {Type: gosnmp.Counter32, Value: uint32(456)}, 2: {Type: gosnmp.Counter32, Value: uint32(0)}}
		metrics, _, err := pollSNMP(t.Context(), conn, Target{Address: "192.0.2.9", Transport: TransportSNMPv2c}, tenant, "same-agent", pollTime)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]int{}
		for _, metric := range metrics {
			if metric.TenantID != tenant || metric.AgentID != "same-agent" || metric.Device != "192.0.2.9" || metric.Source != SourceSNMP || !metric.At.Equal(pollTime) {
				t.Fatal("exact SNMP collection lost its original tenant/source observation scope", metric)
			}
			if metric.Name != MetricIfInOctets && metric.Name != MetricIfOutOctets {
				continue
			}
			seen[metric.IfName+metric.Name]++
		}
		for _, scenario := range []struct {
			iface, name string
			want        CounterValue
		}{{"eth0", MetricIfInOctets, CounterValue{Value: 1<<53 + 1, Width: 64}}, {"eth0", MetricIfOutOctets, CounterValue{Value: ^uint64(0), Width: 64}}, {"eth1", MetricIfInOctets, CounterValue{Value: 1<<32 - 1, Width: 32}}, {"eth1", MetricIfOutOctets, CounterValue{Value: 0, Width: 32}}} {
			metric := find(t, metrics, scenario.name, scenario.iface)
			if metric.ExactCounter == nil || metric.ExactCounter.Value != scenario.want.Value || metric.ExactCounter.Width != scenario.want.Width || seen[scenario.iface+scenario.name] != 1 {
				t.Fatal("SNMP poll rounded full counters, replaced HC width or omitted an interface-specific fallback", scenario, metric.ExactCounter, seen)
			}
		}
		original := find(t, metrics, MetricIfInOctets, "eth0")
		conn.tables[oidIfHCInOctets][1] = gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: uint64(7)}
		if original.ExactCounter.Value != 1<<53+1 {
			t.Fatal("retained exact SNMP sample aliased the next source observation")
		}
	}
}

func TestSNMPPollDoesNotPromoteMalformedHCCountersThroughA32BitFallback(t *testing.T) {
	conn := healthyConn()
	conn.tables[oidIfHCInOctets][1] = gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: float64(1 << 53)}
	conn.tables[oidIfInOctets] = map[uint32]gosnmp.SnmpPDU{1: {Type: gosnmp.Counter32, Value: uint32(42)}}
	metrics, _, err := pollSNMP(t.Context(), conn, Target{Address: "192.0.2.9", Transport: TransportSNMPv2c}, "red", "same-agent", pollTime)
	if err != nil {
		t.Fatal(err)
	}
	metric := find(t, metrics, MetricIfInOctets, "eth0")
	if metric.ExactCounter != nil || metric.Value != float64(1<<53) {
		t.Fatal("malformed HC observation was replaced with a convenient exact counter width", metric)
	}
}
