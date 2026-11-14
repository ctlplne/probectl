// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"errors"
	"testing"

	"github.com/gosnmp/gosnmp"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const testIfSpeedColumn = ".1.3.6.1.2.1.2.2.1.5"

type interfaceSpeedConn struct {
	*counterClockConn
	high, low             []gosnmp.SnmpPDU
	failedHigh, failedLow bool
}

func (c *interfaceSpeedConn) BulkWalk(root string, visit gosnmp.WalkFunc) error {
	var rows []gosnmp.SnmpPDU
	var failed bool
	switch root {
	case oidIfHighSpeed:
		rows, failed = c.high, c.failedHigh
	case testIfSpeedColumn:
		rows, failed = c.low, c.failedLow
	default:
		return c.counterClockConn.BulkWalk(root, visit)
	}
	for _, row := range rows {
		if err := visit(row); err != nil {
			return err
		}
	}
	if failed {
		return errors.New("modeled speed column tail failure")
	}
	return nil
}

func interfaceSpeedPDU(root, index string, value uint32) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: root + "." + index, Type: gosnmp.Gauge32, Value: value}
}

func TestSNMPInterfaceSpeedKeepsOriginalTypedRatesAndTenant(t *testing.T) {
	for _, tenant := range []string{"red", "blue"} {
		conn := &interfaceSpeedConn{counterClockConn: counterClockFixture(),
			high: []gosnmp.SnmpPDU{interfaceSpeedPDU(oidIfHighSpeed, "1", 1<<32-1), interfaceSpeedPDU(oidIfHighSpeed, "2", 0)},
			low:  []gosnmp.SnmpPDU{interfaceSpeedPDU(testIfSpeedColumn, "1", 1000), interfaceSpeedPDU(testIfSpeedColumn, "2", 64000)}}
		metrics, _, err := pollSNMP(t.Context(), conn, Target{Address: "192.0.2.9", Transport: TransportSNMPv2c}, tenant, "same-agent", pollTime)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, metric := range metrics {
			if metric.ExactCounter == nil {
				continue
			}
			count++
			wire := metric.ToProto()
			counter := wire.ExactCounter.ProtoReflect()
			field := counter.Descriptor().Fields().ByName(protoreflect.Name("interface_speed_bps"))
			want := uint64(4294967295000000)
			if metric.IfIndex == 2 {
				want = 64000
			}
			if field == nil || !counter.Has(field) || counter.Get(field).Uint() != want || wire.TenantId != tenant || !metric.ExactCounter.PollStartedAt.Equal(pollTime) {
				t.Fatal("original typed interface speed missing from tenant counter transport")
			}
		}
		if count != 4 {
			t.Fatal("speed evidence omitted part of the paired-direction population", count)
		}
	}
}

func TestSNMPInterfaceSpeedRefusesPartialMalformedAndUnobservedValues(t *testing.T) {
	for _, scenario := range []string{"absent", "partial-high", "duplicate", "noncanonical-index", "wrong-type", "rounded", "overflow", "partial-low", "duplicate-low", "observed-zero"} {
		t.Run(scenario, func(t *testing.T) {
			conn := &interfaceSpeedConn{counterClockConn: counterClockFixture(), high: []gosnmp.SnmpPDU{interfaceSpeedPDU(oidIfHighSpeed, "1", 1000)}}
			switch scenario {
			case "absent":
				conn.high = nil
			case "partial-high":
				conn.failedHigh = true
			case "duplicate":
				conn.high = append(conn.high, conn.high[0])
			case "noncanonical-index":
				conn.high[0].Name = oidIfHighSpeed + ".01"
			case "wrong-type":
				conn.high[0].Type = gosnmp.Integer
			case "rounded":
				conn.high[0].Value = float64(1000)
			case "overflow":
				conn.high[0].Value = uint64(1) << 32
			case "partial-low", "duplicate-low", "observed-zero":
				conn.high[0].Value = uint32(0)
				conn.low = []gosnmp.SnmpPDU{interfaceSpeedPDU(testIfSpeedColumn, "1", 0)}
				conn.failedLow = scenario == "partial-low"
				if scenario == "duplicate-low" {
					conn.low = append(conn.low, conn.low[0])
				}
			}
			metrics, _, err := pollSNMP(t.Context(), conn, Target{Address: "192.0.2.9", Transport: TransportSNMPv2c}, "red", "same-agent", pollTime)
			if err != nil {
				t.Fatal(err)
			}
			counter := find(t, metrics, MetricIfInOctets, "eth0").ToProto().ExactCounter.ProtoReflect()
			field := counter.Descriptor().Fields().ByName(protoreflect.Name("interface_speed_bps"))
			if field == nil {
				t.Fatal("original interface speed presence is absent from counter schema")
			}
			if counter.Has(field) != (scenario == "observed-zero") || scenario == "observed-zero" && counter.Get(field).Uint() != 0 {
				t.Fatal("unavailable speed became observed or explicit zero was lost")
			}
		})
	}
}
