// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/gosnmp/gosnmp"
)

type rawCounterCapture struct {
	raw, legacy [][]Metric
	fail        bool
}

func (c *rawCounterCapture) Emit(_ context.Context, metrics []Metric) error {
	c.legacy = append(c.legacy, append([]Metric(nil), metrics...))
	return nil
}

func (c *rawCounterCapture) EmitCounters(_ context.Context, metrics []Metric) error {
	if c.fail {
		return errors.New("modeled exact counter delivery failure")
	}
	// Deliberately retain the caller's slice, so an in-place legacy filter
	// would destroy this proof unless the producer made its own full copy.
	c.raw = append(c.raw, metrics)
	return nil
}

func counterCaptureRuntime(tenant string, emitter Emitter) *Runtime {
	return &Runtime{cfg: &Config{TenantID: tenant, AgentID: "same-agent"}, emit: emitter, log: slog.New(slog.NewTextHandler(io.Discard, nil)), correlator: NewCorrelator(), counterCache: make(map[counterKey]float64)}
}

func TestExactCounterCapturePrecedesLegacyResetFilteringForBothWidthsAndTenants(t *testing.T) {
	for _, tenant := range []string{"red", "blue"} {
		for _, width := range []uint32{32, 64} {
			capture := &rawCounterCapture{}
			runtime := counterCaptureRuntime(tenant, capture)
			polls := []*counterClockConn{counterClockFixture(), counterClockFixture()}
			before := ^uint64(0) - 9
			if width == 32 {
				before = 1<<32 - 10
			}
			for i, conn := range polls {
				value := before
				if i == 1 {
					value = 10
				}
				for _, direction := range []struct{ hc, standard string }{{oidIfHCInOctets, oidIfInOctets}, {oidIfHCOutOctets, oidIfOutOctets}} {
					if width == 64 {
						conn.tables[direction.hc][1] = gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: value}
					} else {
						delete(conn.tables, direction.hc)
						conn.tables[direction.standard] = map[uint32]gosnmp.SnmpPDU{1: {Type: gosnmp.Counter32, Value: uint32(value)}, 2: {Type: gosnmp.Counter32, Value: uint32(50)}}
					}
				}
			}
			next := 0
			runtime.dialSNMP = func(Target, Credential) (snmpConn, error) {
				conn := polls[next]
				next++
				return conn, nil
			}
			target := Target{Address: "192.0.2.9", Transport: TransportSNMPv2c}
			runtime.pollOnce(t.Context(), target, Credential{})
			runtime.pollOnce(t.Context(), target, Credential{})
			if len(capture.raw) != 2 || len(capture.legacy) != 2 || runtime.stats.ExactCounterSamples.Load() != 8 || runtime.stats.ExactCounterBatches.Load() != 2 || runtime.stats.CounterResets.Load() != 2 {
				t.Fatal("exact counter capture lost an original source poll to legacy reset filtering", tenant, width, len(capture.raw), runtime.StatsSnapshot())
			}
			for i, batch := range capture.raw {
				if len(batch) != 4 {
					t.Fatal("exact counter capture lost an original source poll to legacy reset filtering", len(batch))
				}
				for _, metric := range batch {
					want := before
					if i == 1 {
						want = 10
					}
					if metric.ExactCounter == nil || metric.TenantID != tenant || metric.AgentID != "same-agent" || metric.ExactCounter.Width != width || (metric.IfIndex == 1 && metric.ExactCounter.Value != want) {
						t.Fatal("exact source capture lost full integers, width, original slice ownership or tenant", metric)
					}
				}
			}
			for _, metric := range capture.legacy[1] {
				if metric.IfIndex == 1 && (metric.Name == MetricIfInOctets || metric.Name == MetricIfOutOctets) {
					t.Fatal("separate raw capture changed the legacy reset/gap stream", metric)
				}
			}
		}
	}
}

func TestExactCounterCaptureRefusesMixedScopeOwnsMetadataAndKeepsLegacyOnFailure(t *testing.T) {
	base := Metric{TenantID: "red", AgentID: "same-agent", Source: SourceSNMP, Device: "192.0.2.9", IfIndex: 1, Name: MetricIfInOctets, InterfaceAddresses: []string{"192.0.2.1"}, ExactCounter: &CounterValue{Value: 42, Width: 64}}
	for _, change := range []func(*Metric){
		func(m *Metric) { m.TenantID = "blue" },
		func(m *Metric) { m.AgentID = "foreign-agent" },
		func(m *Metric) { m.Source = SourceGNMI },
		func(m *Metric) { m.Name = MetricCPUUtilization },
		func(m *Metric) { m.ExactCounter = &CounterValue{Value: 1 << 32, Width: 32} },
		func(m *Metric) { m.ExactCounter = &CounterValue{Value: 42, Width: 16} },
	} {
		capture := &rawCounterCapture{}
		runtime := counterCaptureRuntime("red", capture)
		bad := base
		change(&bad)
		runtime.emitExactCounters(t.Context(), []Metric{base, bad})
		if len(capture.raw) != 0 || runtime.stats.ExactCounterEmitErrors.Load() != 1 || runtime.stats.ExactCounterBatches.Load() != 0 {
			t.Fatal("mixed or malformed counter scope emitted a valid prefix", runtime.StatsSnapshot())
		}
	}
	capture := &rawCounterCapture{}
	runtime := counterCaptureRuntime("red", capture)
	metrics := []Metric{base}
	runtime.emitExactCounters(t.Context(), metrics)
	metrics[0].ExactCounter.Value = 99
	metrics[0].InterfaceAddresses[0] = "203.0.113.9"
	metrics[0].Name = MetricCPUUtilization
	if len(capture.raw) != 1 || capture.raw[0][0].ExactCounter.Value != 42 || capture.raw[0][0].InterfaceAddresses[0] != "192.0.2.1" || capture.raw[0][0].Name != MetricIfInOctets {
		t.Fatal("retained exact counter facts aliased source metadata or the mutable legacy slice")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	runtime.emitExactCounters(canceled, []Metric{base})
	if len(capture.raw) != 1 {
		t.Fatal("canceled counter capture published original facts")
	}
	capture = &rawCounterCapture{fail: true}
	runtime = counterCaptureRuntime("red", capture)
	runtime.dialSNMP = func(Target, Credential) (snmpConn, error) { return counterClockFixture(), nil }
	runtime.pollOnce(t.Context(), Target{Address: "192.0.2.9", Transport: TransportSNMPv2c}, Credential{})
	if len(capture.legacy) != 1 || len(capture.legacy[0]) == 0 || runtime.stats.ExactCounterEmitErrors.Load() != 1 || runtime.stats.ExactCounterBatches.Load() != 0 {
		t.Fatal("exact counter delivery failure broke legacy collection or claimed successful capture", runtime.StatsSnapshot())
	}
	unavailable := counterCaptureRuntime("red", &captureEmitter{})
	unavailable.emitExactCounters(t.Context(), []Metric{base})
	if unavailable.stats.ExactCounterUnavailable.Load() != 1 || unavailable.stats.ExactCounterBatches.Load() != 0 {
		t.Fatal("missing exact counter delivery channel invented a successful capture")
	}
}
