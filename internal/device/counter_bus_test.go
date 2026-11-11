// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
)

func TestExactCounterBusLaneKeepsOriginalWrapsClockAndLegacySeparation(t *testing.T) {
	b := bus.NewMemory()
	t.Cleanup(func() { _ = b.Close() })
	channels := map[string]chan bus.Message{}
	subscribe := func(topic string) chan bus.Message {
		t.Helper()
		if existing, ok := channels[topic]; ok {
			return existing
		}
		ch := make(chan bus.Message, 2)
		subscribeMemoryBusForTest(t, b, topic, "counter-source", func(_ context.Context, msg bus.Message) error { ch <- msg; return nil })
		channels[topic] = ch
		return ch
	}
	for _, scenario := range []struct{ tenant, namespace string }{{"red", ""}, {"blue", ""}, {"blue", "blue-counters"}} {
		tenant, namespace := scenario.tenant, scenario.namespace
		counterTopic, err := bus.TopicFor(namespace, bus.DeviceCountersTopic)
		if err != nil {
			t.Fatal(err)
		}
		legacyTopic, err := bus.TopicFor(namespace, bus.DeviceMetricsTopic)
		if err != nil {
			t.Fatal(err)
		}
		raw, legacy := subscribe(counterTopic), subscribe(legacyTopic)
		emitter, err := NewNamespacedBusEmitter(b, tenant, namespace)
		if err != nil {
			t.Fatal(err)
		}
		runtime := counterCaptureRuntime(tenant, emitter)
		polls := []*counterClockConn{counterClockFixture(), counterClockFixture()}
		for i, conn := range polls {
			value := ^uint64(0) - 9
			if i == 1 {
				value = 10
			}
			for _, column := range []string{oidIfHCInOctets, oidIfHCOutOctets} {
				conn.tables[column][1] = gosnmp.SnmpPDU{Type: gosnmp.Counter64, Value: value}
			}
		}
		next := 0
		runtime.dialSNMP = func(Target, Credential) (snmpConn, error) { conn := polls[next]; next++; return conn, nil }
		for range 2 {
			runtime.pollOnce(t.Context(), Target{Address: "192.0.2.9", Transport: TransportSNMPv2c}, Credential{})
		}
		read := func(ch <-chan bus.Message, topic string) *devicev1.DeviceMetricBatch {
			t.Helper()
			select {
			case msg := <-ch:
				if msg.Topic != topic || !bytes.Equal(msg.Key, bus.TenantKey(tenant, "same-agent")) {
					t.Fatal("counter lane lost tenant key or namespace", msg.Topic, string(msg.Key))
				}
				var batch devicev1.DeviceMetricBatch
				if err := proto.Unmarshal(msg.Value, &batch); err != nil {
					t.Fatal(err)
				}
				return &batch
			case <-time.After(2 * time.Second):
				t.Fatal("counter source did not deliver its complete original poll")
				return nil
			}
		}
		for poll := range 2 {
			batch := read(raw, counterTopic)
			if len(batch.Metrics) != 4 {
				t.Fatal("raw counter lane dropped a wrapped source observation", len(batch.Metrics))
			}
			for _, metric := range batch.Metrics {
				counter := metric.ExactCounter
				want := ^uint64(0) - 9
				if poll == 1 {
					want = 10
				}
				if metric.TenantId != tenant || metric.AgentId != "same-agent" || counter == nil || counter.Width != 64 || (metric.IfIndex == 1 && counter.Value != want) || counter.UptimeTicks == nil || *counter.UptimeTicks != 0 || counter.DiscontinuityTicks == nil || counter.PollStartedAtUnixNano != metric.TimeUnixNano || counter.PollCompletedAtUnixNano < counter.PollStartedAtUnixNano {
					t.Fatal("counter bus rounded integers or lost original clock presence/tenant", metric)
				}
			}
			old := read(legacy, legacyTopic)
			if poll == 1 {
				for _, metric := range old.Metrics {
					if metric.IfIndex == 1 && (metric.Name == MetricIfInOctets || metric.Name == MetricIfOutOctets) {
						t.Fatal("exact counter lane changed the independent legacy reset filter", metric)
					}
				}
			}
		}
		if runtime.StatsSnapshot()["exact_counter_samples"] != 8 || runtime.StatsSnapshot()["exact_counter_emit_errors"] != 0 {
			t.Fatal("counter delivery accounting differs from complete source polls", runtime.StatsSnapshot())
		}
	}
	ensured := false
	for _, topic := range bus.AllTopics() {
		ensured = ensured || topic == bus.DeviceCountersTopic
	}
	if !ensured {
		t.Fatal("shipped counter lane is absent from startup topic registry")
	}
}

type counterBusRecorder struct{ records []bus.Message }

func (b *counterBusRecorder) Publish(_ context.Context, topic string, key, value []byte) error {
	b.records = append(b.records, bus.Message{Topic: topic, Key: key, Value: value})
	return nil
}
func (*counterBusRecorder) Subscribe(context.Context, string, string, bus.Handler) error { return nil }
func (*counterBusRecorder) Close() error                                                 { return nil }

func TestExactCounterBusRefusesMixedTenantSenderAndMalformedWholeBatches(t *testing.T) {
	for _, tenant := range []string{"red", "blue"} {
		base := Metric{TenantID: tenant, AgentID: "same-agent", Source: SourceSNMP, Device: "192.0.2.9", IfIndex: 1, Name: MetricIfInOctets, At: pollTime, ExactCounter: &CounterValue{Value: 0, Width: 32, PollStartedAt: pollTime, PollCompletedAt: pollTime.Add(time.Second)}}
		for _, change := range []func(*Metric){
			func(m *Metric) { m.TenantID = "foreign-tenant" },
			func(m *Metric) { m.AgentID = "foreign-agent" },
			func(m *Metric) { m.ExactCounter = nil },
			func(m *Metric) { m.IfIndex = 0 },
			func(m *Metric) {
				m.ExactCounter = &CounterValue{Value: 1 << 32, Width: 32, PollStartedAt: pollTime, PollCompletedAt: pollTime}
			},
			func(m *Metric) {
				m.ExactCounter = &CounterValue{Value: 1, Width: 64, PollStartedAt: pollTime, PollCompletedAt: pollTime.Add(-time.Second)}
			},
		} {
			backend := &counterBusRecorder{}
			emitter := NewBusEmitter(backend, tenant)
			bad := base
			change(&bad)
			if err := emitter.EmitCounters(t.Context(), []Metric{base, bad}); err == nil || len(backend.records) != 0 {
				t.Fatal("counter bus published a prefix of a foreign or malformed batch", err, len(backend.records))
			}
		}
		backend := &counterBusRecorder{}
		emitter := NewBusEmitter(backend, tenant)
		if err := emitter.EmitCounters(t.Context(), []Metric{base}); err != nil || len(backend.records) != 1 {
			t.Fatal("valid observed zero counter could not be delivered", err)
		}
		canceled, cancel := context.WithCancel(t.Context())
		cancel()
		if err := emitter.EmitCounters(canceled, []Metric{base}); err == nil || len(backend.records) != 1 {
			t.Fatal("canceled counter delivery escaped onto the bus", err)
		}
	}
}
