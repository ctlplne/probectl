// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"context"
	"sync"

	"github.com/imfeelingtheagi/probectl/internal/bus"
)

// LaneHandler processes one bus message known to belong to laneTenant. On the
// shared lane laneTenant is "" (the handler then derives + verifies the tenant
// from the payload); on a namespaced lane it is the lane's authoritative
// tenant, which the handler must treat as overriding the payload.
type LaneHandler func(ctx context.Context, msg bus.Message, laneTenant string) error

// RunLanes is the generalized laneSub fan-out (CORRECT-005). The flow, device,
// and result consumers each grew their own copy of "subscribe to the shared
// topic plus one namespaced lane per siloed tenant"; every OTHER consumer
// (SLO, topology, threat, cost, carbon, RUM, endpoint, incident, compliance)
// subscribed shared-only and was therefore BLIND to siloed tenants whose
// telemetry rides a per-tenant topic. RunLanes gives them all the same fan-out
// from one place: pass the base topic, the consumer group, the namespace->tenant
// map, and a LaneHandler, and it subscribes the shared lane plus every siloed
// lane, invoking the handler with the lane's authoritative tenant.
//
// A malformed namespace is fatal (RED-006): a siloed tenant's traffic must
// never silently degrade onto the shared lane. It blocks until ctx is canceled
// or a subscription fails.
func RunLanes(ctx context.Context, b bus.Bus, base, group string, nsTenants map[string]string, handler LaneHandler) error {
	subs := []laneSub{{topic: base, group: group}}
	for ns, tid := range nsTenants {
		t, err := bus.TopicFor(ns, base)
		if err != nil {
			return err // RED-006: never shared-lane fallback
		}
		subs = append(subs, laneSub{topic: t, group: group + "-" + ns, laneTenant: tid})
	}
	if len(subs) == 1 {
		return b.Subscribe(ctx, base, group, func(c context.Context, m bus.Message) error {
			return handler(c, m, "")
		})
	}
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(subs))
	var wg sync.WaitGroup
	for _, s := range subs {
		wg.Add(1)
		go func(s laneSub) {
			defer wg.Done()
			h := func(c context.Context, m bus.Message) error { return handler(c, m, s.laneTenant) }
			if err := b.Subscribe(ctx2, s.topic, s.group, h); err != nil && ctx2.Err() == nil {
				errs <- err
				cancel()
			}
		}(s)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// LaneFanout marks a bus consumer that fans out across siloed-tenant lanes
// (CORRECT-005). The lane-coverage test holds the list of every registered
// consumer and asserts each implements this, so a NEW consumer that subscribes
// shared-only cannot ship without either fanning out or explicitly opting out.
type LaneFanout interface {
	// LaneFanoutEnabled reports that the consumer subscribes per-siloed-tenant
	// (via RunLanes or its own equivalent), not shared-only.
	LaneFanoutEnabled() bool
}

// The result, flow, and device consumers fan out via their own lanes() copies
// (kept for their per-plane retry/DLQ specifics); they declare coverage here.

// LaneFanoutEnabled satisfies LaneFanout for the result consumer.
func (*Consumer) LaneFanoutEnabled() bool { return true }

// LaneFanoutEnabled satisfies LaneFanout for the flow consumer.
func (*FlowConsumer) LaneFanoutEnabled() bool { return true }

// LaneFanoutEnabled satisfies LaneFanout for the device consumer.
func (*DeviceConsumer) LaneFanoutEnabled() bool { return true }
