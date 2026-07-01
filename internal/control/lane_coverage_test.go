// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
)

// CORRECT-005 lane-coverage gate: every consumer that subscribes to a
// tenant-keyed topic must fan out across siloed-tenant lanes (implement
// pipeline.LaneFanout) rather than ship shared-only and silently miss siloed
// tenants. A NEW consumer added here that forgets WithNamespaceTenants/RunLanes
// fails to compile against this list — the regression guard the audit asked for.
func TestConsumersFanOutAcrossLanes(t *testing.T) {
	consumers := []any{
		(*pipeline.Consumer)(nil),
		(*pipeline.FlowConsumer)(nil),
		(*pipeline.DeviceConsumer)(nil),
		(*ResultFan)(nil),
		(*ResultViewConsumer)(nil),
		(*TLSPostureConsumer)(nil),
		(*IOCConsumer)(nil),
		(*SLOConsumer)(nil),
		(*CarbonConsumer)(nil),
		(*TopologyConsumer)(nil),
		(*NDRConsumer)(nil),
		(*ComplianceConsumer)(nil),
		(*CostConsumer)(nil),
		(*EndpointViewConsumer)(nil),
		(*RUMConsumer)(nil),
		(*OutageConsumer)(nil),
		(*BGPIncidentConsumer)(nil),
	}
	for _, c := range consumers {
		if _, ok := c.(pipeline.LaneFanout); !ok {
			t.Fatalf("%T does not implement pipeline.LaneFanout — it would be blind to siloed tenants (CORRECT-005)", c)
		}
	}
}

func TestDeclaredConsumersSubscribeToNamespacedLanes(t *testing.T) {
	const namespace = "acme"
	nsTenants := map[string]string{namespace: "tenant-acme"}
	for _, spec := range laneConsumerRegistry() {
		t.Run(spec.name, func(t *testing.T) {
			b := newCaptureLaneBus()
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- spec.run(ctx, b, nsTenants) }()

			var expected []string
			for _, topic := range spec.topics {
				expected = append(expected, topic)
				namespaced, err := bus.TopicFor(namespace, topic)
				if err != nil {
					t.Fatal(err)
				}
				expected = append(expected, namespaced)
			}
			b.waitForTopics(t, expected)
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("consumer returned error after cancel: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("consumer did not stop after cancel")
			}
		})
	}
}

type laneConsumerSpec struct {
	name   string
	topics []string
	run    func(context.Context, bus.Bus, map[string]string) error
}

func laneConsumerRegistry() []laneConsumerSpec {
	log := intelTestLog()
	return []laneConsumerSpec{
		{
			name:   "result-fan",
			topics: []string{bus.NetworkResultsTopic},
			run: func(ctx context.Context, b bus.Bus, ns map[string]string) error {
				return NewResultFan(b, log).WithNamespaceTenants(ns).Run(ctx)
			},
		},
		{
			name:   "result-view-standalone",
			topics: []string{bus.NetworkResultsTopic},
			run: func(ctx context.Context, b bus.Bus, ns map[string]string) error {
				return NewResultViewConsumer(b, nil, log).WithNamespaceTenants(ns).Run(ctx)
			},
		},
		{
			name:   "tls-posture-standalone",
			topics: []string{bus.NetworkResultsTopic},
			run: func(ctx context.Context, b bus.Bus, ns map[string]string) error {
				return NewTLSPostureConsumer(b, nil, nil, log).WithNamespaceTenants(ns).Run(ctx)
			},
		},
		{
			name:   "ioc-standalone",
			topics: []string{bus.NetworkResultsTopic},
			run: func(ctx context.Context, b bus.Bus, ns map[string]string) error {
				return NewIOCConsumer(b, nil, nil, log).WithNamespaceTenants(ns).Run(ctx)
			},
		},
		{
			name:   "slo",
			topics: []string{bus.NetworkResultsTopic},
			run: func(ctx context.Context, b bus.Bus, ns map[string]string) error {
				return NewSLOConsumer(b, nil, nil, log).WithNamespaceTenants(ns).Run(ctx)
			},
		},
		{
			name:   "carbon",
			topics: []string{bus.FlowEventsTopic},
			run: func(ctx context.Context, b bus.Bus, ns map[string]string) error {
				return NewCarbonConsumer(b, nil, log).WithNamespaceTenants(ns).Run(ctx)
			},
		},
		{
			name:   "topology",
			topics: []string{bus.EBPFFlowsTopic, bus.BGPEventsTopic, bus.DeviceMetricsTopic},
			run: func(ctx context.Context, b bus.Bus, ns map[string]string) error {
				return NewTopologyConsumer(b, nil, log).WithNamespaceTenants(ns).Run(ctx)
			},
		},
		{
			name:   "ndr",
			topics: []string{bus.FlowEventsTopic, bus.EBPFFlowsTopic},
			run: func(ctx context.Context, b bus.Bus, ns map[string]string) error {
				return NewNDRConsumer(b, nil, nil, log).WithNamespaceTenants(ns).RunFlowLanes(ctx)
			},
		},
		{
			name:   "compliance",
			topics: []string{bus.FlowEventsTopic, bus.EBPFFlowsTopic},
			run: func(ctx context.Context, b bus.Bus, ns map[string]string) error {
				return NewComplianceConsumer(b, nil, nil, log).WithNamespaceTenants(ns).Run(ctx)
			},
		},
		{
			name:   "cost",
			topics: []string{bus.FlowEventsTopic},
			run: func(ctx context.Context, b bus.Bus, ns map[string]string) error {
				return NewCostConsumer(b, nil, nil, log).WithNamespaceTenants(ns).Run(ctx)
			},
		},
		{
			name:   "endpoint-view",
			topics: []string{bus.EndpointResultsTopic},
			run: func(ctx context.Context, b bus.Bus, ns map[string]string) error {
				return NewEndpointViewConsumer(b, nil, log).WithNamespaceTenants(ns).Run(ctx)
			},
		},
		{
			name:   "rum-views",
			topics: []string{bus.RUMEventsTopic},
			run: func(ctx context.Context, b bus.Bus, ns map[string]string) error {
				return NewRUMConsumer(b, nil, nil, log).WithNamespaceTenants(ns).RunViews(ctx)
			},
		},
		{
			name:   "outage",
			topics: []string{bus.NetworkResultsTopic},
			run: func(ctx context.Context, b bus.Bus, ns map[string]string) error {
				return NewOutageConsumer(b, nil, nil, log).WithNamespaceTenants(ns).Run(ctx)
			},
		},
		{
			name:   "bgp-incident",
			topics: []string{bus.BGPEventsTopic},
			run: func(ctx context.Context, b bus.Bus, ns map[string]string) error {
				return NewBGPIncidentConsumer(b, nil, log).WithNamespaceTenants(ns).Run(ctx)
			},
		},
	}
}

type captureLaneBus struct {
	mu     sync.Mutex
	topics map[string]int
}

func newCaptureLaneBus() *captureLaneBus {
	return &captureLaneBus{topics: map[string]int{}}
}

func (b *captureLaneBus) Publish(context.Context, string, []byte, []byte) error { return nil }

func (b *captureLaneBus) Subscribe(ctx context.Context, topic, _ string, _ bus.Handler) error {
	b.mu.Lock()
	b.topics[topic]++
	b.mu.Unlock()
	<-ctx.Done()
	return ctx.Err()
}

func (b *captureLaneBus) Close() error { return nil }

func (b *captureLaneBus) waitForTopics(t *testing.T, expected []string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		missing := missingTopics(b.topics, expected)
		b.mu.Unlock()
		if len(missing) == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	t.Fatalf("missing lane subscriptions: %v; got=%v", missingTopics(b.topics, expected), b.topics)
}

func missingTopics(got map[string]int, expected []string) []string {
	var missing []string
	for _, topic := range expected {
		if got[topic] == 0 {
			missing = append(missing, topic)
		}
	}
	return missing
}
