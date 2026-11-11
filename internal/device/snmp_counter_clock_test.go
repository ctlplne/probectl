// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"errors"
	"testing"

	"github.com/gosnmp/gosnmp"
)

type counterClockConn struct {
	*fakeConn
	rows            []gosnmp.SnmpPDU
	partial         bool
	duplicateUptime bool
}

func (c *counterClockConn) Get(oids []string) ([]gosnmp.SnmpPDU, error) {
	rows, err := c.fakeConn.Get(oids)
	if c.duplicateUptime {
		rows = append(rows, gosnmp.SnmpPDU{Name: oidSysUpTime, Type: gosnmp.TimeTicks, Value: uint32(0)})
	}
	return rows, err
}

func (c *counterClockConn) BulkWalk(root string, fn gosnmp.WalkFunc) error {
	if root != oidIfCounterDiscontinuity {
		return c.fakeConn.BulkWalk(root, fn)
	}
	for _, row := range c.rows {
		if err := fn(row); err != nil {
			return err
		}
	}
	if c.partial {
		return errors.New("modeled counter clock tail failure")
	}
	return nil
}

func counterClockFixture() *counterClockConn {
	conn := &counterClockConn{fakeConn: healthyConn()}
	conn.scalars[oidSysUpTime] = gosnmp.SnmpPDU{Type: gosnmp.TimeTicks, Value: uint32(0)}
	for _, column := range []string{oidIfHCInOctets, oidIfHCOutOctets} {
		for index, pdu := range conn.tables[column] {
			pdu.Type = gosnmp.Counter64
			conn.tables[column][index] = pdu
		}
	}
	conn.rows = []gosnmp.SnmpPDU{
		{Name: oidIfCounterDiscontinuity + ".1", Type: gosnmp.TimeTicks, Value: uint32(0)},
		{Name: oidIfCounterDiscontinuity + ".2", Type: gosnmp.TimeTicks, Value: uint32(1<<32 - 1)},
	}
	return conn
}

func TestSNMPCounterClockKeepsObservedZeroFullWidthAndOriginalPollWindow(t *testing.T) {
	for _, tenant := range []string{"red", "blue"} {
		conn := counterClockFixture()
		metrics, _, err := pollSNMP(t.Context(), conn, Target{Address: "192.0.2.9", Transport: TransportSNMPv2c}, tenant, "same-agent", pollTime)
		if err != nil {
			t.Fatal(err)
		}
		counters := 0
		for _, metric := range metrics {
			if metric.ExactCounter == nil {
				continue
			}
			counter := metric.ExactCounter
			counters++
			wantTicks := uint32(0)
			if metric.IfIndex == 2 {
				wantTicks = 1<<32 - 1
			}
			if !counter.UptimeKnown || counter.UptimeTicks != 0 || !counter.DiscontinuityKnown || counter.DiscontinuityTicks != wantTicks || !counter.PollStartedAt.Equal(pollTime) || counter.PollCompletedAt.Before(pollTime) || !metric.At.Equal(pollTime) || metric.TenantID != tenant {
				t.Fatal("SNMP counter clock lost typed zero/full width, poll bounds or tenant", metric, counter)
			}
		}
		if counters != 4 {
			t.Fatal("counter clock proof omitted part of its paired-direction interface population", counters)
		}
		original := find(t, metrics, MetricIfInOctets, "eth0")
		if original.ExactCounter == nil {
			t.Fatal("typed counter clock proof had no observed counter")
		}
		conn.rows[0].Value = uint32(9)
		if original.ExactCounter.DiscontinuityTicks != 0 {
			t.Fatal("counter clock aliased a later source observation")
		}
	}
}

func TestSNMPCounterClockRefusesPartialMalformedDuplicateOrAbsentEvidence(t *testing.T) {
	for _, scenario := range []string{"absent", "partial", "duplicate", "wrong-index", "noncanonical-index", "wrong-type", "rounded-ticks", "overflow-ticks", "missing-uptime", "duplicate-uptime", "wrong-uptime-type", "rounded-uptime", "overflow-uptime"} {
		t.Run(scenario, func(t *testing.T) {
			conn := counterClockFixture()
			wantUptime, wantDiscontinuity := true, false
			switch scenario {
			case "absent":
				conn.rows = nil
			case "partial":
				conn.partial = true
			case "duplicate":
				conn.rows = append(conn.rows, conn.rows[0])
			case "wrong-index":
				conn.rows[0].Name += ".0"
			case "noncanonical-index":
				conn.rows[0].Name = oidIfCounterDiscontinuity + ".01"
			case "wrong-type":
				conn.rows[0].Type = gosnmp.Gauge32
			case "rounded-ticks":
				conn.rows[0].Value = float64(0)
			case "overflow-ticks":
				conn.rows[0].Value = uint64(1 << 32)
			case "missing-uptime":
				delete(conn.scalars, oidSysUpTime)
			case "duplicate-uptime":
				conn.duplicateUptime = true
			case "wrong-uptime-type":
				conn.scalars[oidSysUpTime] = gosnmp.SnmpPDU{Type: gosnmp.Gauge32, Value: uint32(0)}
			case "rounded-uptime":
				conn.scalars[oidSysUpTime] = gosnmp.SnmpPDU{Type: gosnmp.TimeTicks, Value: float64(0)}
			case "overflow-uptime":
				conn.scalars[oidSysUpTime] = gosnmp.SnmpPDU{Type: gosnmp.TimeTicks, Value: uint64(1 << 32)}
			}
			if scenario == "missing-uptime" || scenario == "duplicate-uptime" || scenario == "wrong-uptime-type" || scenario == "rounded-uptime" || scenario == "overflow-uptime" {
				wantUptime, wantDiscontinuity = false, true
			}
			metrics, _, err := pollSNMP(t.Context(), conn, Target{Address: "192.0.2.9", Transport: TransportSNMPv2c}, "red", "same-agent", pollTime)
			if err != nil {
				t.Fatal(err)
			}
			counters := 0
			for _, metric := range metrics {
				if metric.ExactCounter == nil {
					continue
				}
				counters++
				if metric.ExactCounter.UptimeKnown != wantUptime || metric.ExactCounter.DiscontinuityKnown != wantDiscontinuity {
					t.Fatal("partial or malformed counter clock became known evidence", scenario, metric.ExactCounter)
				}
			}
			if counters != 4 {
				t.Fatal("clock refusal silently discarded the original counter observations", counters)
			}
		})
	}
	conn := counterClockFixture()
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if values, complete := snmpCounterDiscontinuities(canceled, conn, map[uint32]Interface{1: {Index: 1}}); complete || values != nil {
		t.Fatal("canceled counter clock walk retained partial evidence", values, complete)
	}
}
