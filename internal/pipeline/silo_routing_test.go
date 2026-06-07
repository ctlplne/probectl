package pipeline_test

// TENANT-107 (Sprint 4/6): a siloed tenant's records must appear ONLY on its
// namespaced bus topic — the shared (pooled) topic must never carry them — and
// a malformed namespace must REFUSE construction (RED-006, fail closed) rather
// than silently fall back to the shared lane. This test needs no infrastructure
// (a capture bus), so it runs in the normal suite as well as the isolation gate.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/device"
	"github.com/imfeelingtheagi/probectl/internal/ebpf"
	"github.com/imfeelingtheagi/probectl/internal/endpoint"
	"github.com/imfeelingtheagi/probectl/internal/flow"
)

type captureBus struct {
	mu     sync.Mutex
	topics []string
}

func (c *captureBus) Publish(_ context.Context, topic string, _, _ []byte) error {
	c.mu.Lock()
	c.topics = append(c.topics, topic)
	c.mu.Unlock()
	return nil
}
func (c *captureBus) Subscribe(context.Context, string, string, bus.Handler) error { return nil }
func (c *captureBus) Close() error                                                 { return nil }

// assertOnly fails if the bus saw anything other than want, or saw nothing, or
// ever touched the forbidden shared topic.
func (c *captureBus) assertOnly(t *testing.T, want, forbidden string) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.topics) == 0 {
		t.Fatalf("nothing published (want %q)", want)
	}
	for _, got := range c.topics {
		if got == forbidden {
			t.Fatalf("SILO LEAK: siloed record published to the shared topic %q", forbidden)
		}
		if got != want {
			t.Fatalf("published to %q, want only %q", got, want)
		}
	}
}

func TestSiloedRecordsRouteToNamespacedTopicsOnly(t *testing.T) {
	ctx := context.Background()
	const ns = "t-acme"
	const tid = "t-acme-id"

	cases := []struct {
		surface  string
		base     string
		emitNS   func(b bus.Bus) error // construct a namespaced emitter and emit one record
		emitPool func(b bus.Bus) error // pooled emitter, one record
	}{
		{
			surface: "device", base: bus.DeviceMetricsTopic,
			emitNS: func(b bus.Bus) error {
				e, err := device.NewNamespacedBusEmitter(b, tid, ns)
				if err != nil {
					return err
				}
				return e.Emit(ctx, []device.Metric{{TenantID: tid, Name: "probectl.device.if.in.octets", Value: 1, At: time.Now()}})
			},
			emitPool: func(b bus.Bus) error {
				return device.NewBusEmitter(b, tid).Emit(ctx, []device.Metric{{TenantID: tid, Name: "x", Value: 1, At: time.Now()}})
			},
		},
		{
			surface: "flow", base: bus.FlowEventsTopic,
			emitNS: func(b bus.Bus) error {
				e, err := flow.NewNamespacedBusEmitter(b, tid, ns)
				if err != nil {
					return err
				}
				return e.Emit(ctx, []flow.Record{{TenantID: tid, Protocol: "netflow", Bytes: 1, Packets: 1}})
			},
			emitPool: func(b bus.Bus) error {
				return flow.NewBusEmitter(b, tid).Emit(ctx, []flow.Record{{TenantID: tid, Protocol: "netflow", Bytes: 1}})
			},
		},
		{
			surface: "ebpf", base: bus.EBPFFlowsTopic,
			emitNS: func(b bus.Bus) error {
				e, err := ebpf.NewNamespacedBusEmitter(b, tid, ns)
				if err != nil {
					return err
				}
				return e.Emit(ctx, []ebpf.Flow{{TenantID: tid, Transport: "tcp", NetworkType: "ipv4"}}, nil, nil)
			},
			emitPool: func(b bus.Bus) error {
				return ebpf.NewBusEmitter(b, tid).Emit(ctx, []ebpf.Flow{{TenantID: tid, Transport: "tcp"}}, nil, nil)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.surface+"/namespaced-only", func(t *testing.T) {
			want, err := bus.TopicFor(ns, tc.base)
			if err != nil {
				t.Fatalf("TopicFor: %v", err)
			}
			cb := &captureBus{}
			if err := tc.emitNS(cb); err != nil {
				t.Fatalf("emit: %v", err)
			}
			cb.assertOnly(t, want, tc.base)
		})
		t.Run(tc.surface+"/pooled-uses-shared", func(t *testing.T) {
			cb := &captureBus{}
			if err := tc.emitPool(cb); err != nil {
				t.Fatalf("emit: %v", err)
			}
			cb.assertOnly(t, tc.base, "") // pooled → the shared topic, exclusively
		})
	}
}

// RED-006: every surface refuses to construct a namespaced emitter for a
// malformed namespace — it must error, never silently route to the shared lane.
func TestNamespacedEmitterFailsClosedOnBadNamespace(t *testing.T) {
	cb := &captureBus{}
	const bad = "Bad.Namespace"
	if _, err := device.NewNamespacedBusEmitter(cb, "t", bad); err == nil {
		t.Error("device emitter accepted a malformed namespace (RED-006)")
	}
	if _, err := flow.NewNamespacedBusEmitter(cb, "t", bad); err == nil {
		t.Error("flow emitter accepted a malformed namespace (RED-006)")
	}
	if _, err := ebpf.NewNamespacedBusEmitter(cb, "t", bad); err == nil {
		t.Error("ebpf emitter accepted a malformed namespace (RED-006)")
	}
	if _, err := endpoint.NewNamespacedBusEmitter(cb, "t", "agent", bad); err == nil {
		t.Error("endpoint emitter accepted a malformed namespace (RED-006)")
	}
	if len(cb.topics) != 0 {
		t.Fatalf("construction must not publish anything, saw %v", cb.topics)
	}
}
