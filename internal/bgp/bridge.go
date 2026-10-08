// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package bgp bridges BGP observations into the control plane (S14).
//
// The analyzer (analyzer/) ingests public collector data and emits
// probectl.bgp.events as JSON Lines. The BMP listener accepts direct router BMP
// sessions over tenant-bound mTLS. Both paths validate each event's tenant (the
// outermost scope — F50), and publish the canonical probectl.bgp.v1.BGPEvent
// protobuf keyed by tenant plus collector/peer entropy so large tenant route
// storms spread across tenant-preserving bus buckets. Detections are signals,
// not actions (docs/guardrails.md G7-9): this package transports them, it does
// not act on routing.
package bgp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// maxEventLine bounds a single JSONL record (defensive: collector-derived input
// is untrusted — docs/guardrails.md G7-10).
const maxEventLine = 1 << 20

// Publisher is the subset of the bus the bridge needs.
type Publisher interface {
	Publish(ctx context.Context, topic string, key, value []byte) error
}

// Bridge republishes analyzer events onto the bus.
type Bridge struct {
	bus            Publisher
	log            *slog.Logger
	expectedTenant string
	busNamespace   string // the tenant's lane; "" = route via the isolation router
}

// Stats summarizes an ingest run.
type Stats struct {
	Published int // events published to the bus
	Skipped   int // events rejected (malformed or missing tenant) — never published
}

// NewBridge constructs a Bridge over the given bus.
func NewBridge(b Publisher, log *slog.Logger) *Bridge {
	if log == nil {
		log = slog.Default()
	}
	return &Bridge{bus: b, log: log}
}

// WithExpectedTenant binds analyzer output to the tenant named by the runner's
// trusted configuration. The Python payload still carries tenant_id as a
// defense-in-depth assertion, but it cannot use that field to switch tenants:
// a mismatch is rejected before publication (guardrail 7.1).
func (br *Bridge) WithExpectedTenant(tenantID string) *Bridge {
	br.expectedTenant = tenantID
	return br
}

// WithBusNamespace publishes every event on the tenant's own namespaced lane
// (PublishEventOnLane) — the lane collector registration prints and strict-lane
// deployments require. "" keeps routing through the isolation router.
func (br *Bridge) WithBusNamespace(namespace string) *Bridge {
	br.busNamespace = namespace
	return br
}

// PublishEvent validates and publishes one canonical BGP event. It is shared by
// the JSONL analyzer bridge and the BMP listener so every source uses the same
// tenant fail-closed path and the same bus key. The topic comes from the
// installed isolation router, which puts a pooled tenant on the shared lane;
// a collector that carries its tenant's lane uses PublishEventOnLane.
func PublishEvent(ctx context.Context, pub Publisher, ev Event) error {
	if err := ev.validate(); err != nil {
		return err
	}
	targets, err := tenancy.CurrentRouter().TargetsFor(ctx, ev.TenantID)
	if err != nil {
		return fmt.Errorf("bgp: resolve isolation targets for tenant %s: %w", ev.TenantID, err)
	}
	return publishOn(ctx, pub, ev, targets.BusNamespace)
}

// PublishEventOnLane publishes one canonical BGP event on its tenant's own
// namespaced lane (probectl.t-<slug>.bgp.events, DPR-049). The out-of-process
// BGP collectors — the analyzer bridge and the BMP listener — carry that lane
// from collector registration exactly like the flow, device, endpoint and eBPF
// agents, because a strict-lane deployment (WIRE-001; mandatory for the
// multi-tenant and regulated profiles) refuses BGP events on the shared lane.
// An empty or malformed namespace is refused rather than falling back to the
// shared lane (fail closed).
func PublishEventOnLane(ctx context.Context, pub Publisher, ev Event, namespace string) error {
	if strings.TrimSpace(namespace) == "" {
		return fmt.Errorf("bgp: a tenant lane namespace is required")
	}
	if err := ev.validate(); err != nil {
		return err
	}
	return publishOn(ctx, pub, ev, namespace)
}

func publishOn(ctx context.Context, pub Publisher, ev Event, namespace string) error {
	value, err := proto.Marshal(ev.toProto())
	if err != nil {
		return fmt.Errorf("bgp: marshal event: %w", err)
	}
	topic, err := bus.TopicFor(namespace, bus.BGPEventsTopic)
	if err != nil {
		return fmt.Errorf("bgp: route topic for tenant %s: %w", ev.TenantID, err)
	}
	if err := pub.Publish(ctx, topic, bus.TenantKey(ev.TenantID, bgpPartitionEntropy(ev)), value); err != nil {
		return fmt.Errorf("bgp: publish event: %w", err)
	}
	return nil
}

func bgpPartitionEntropy(ev Event) string {
	parts := make([]string, 0, 4)
	if ev.Collector != "" {
		parts = append(parts, "collector:"+ev.Collector)
	}
	if ev.PeerASN != 0 {
		parts = append(parts, "peer_asn:"+strconv.FormatUint(uint64(ev.PeerASN), 10))
	}
	if ev.PeerAddress != "" {
		parts = append(parts, "peer_address:"+ev.PeerAddress)
	}
	if len(parts) == 0 {
		parts = append(parts, "prefix:"+ev.Prefix)
	}
	return strings.Join(parts, "|")
}

func (br *Bridge) publish(ctx context.Context, ev Event) error {
	if br.busNamespace != "" {
		return PublishEventOnLane(ctx, br.bus, ev, br.busNamespace)
	}
	return PublishEvent(ctx, br.bus, ev)
}

// Ingest reads JSON-Lines events from r until EOF, publishing each valid event
// to probectl.bgp.events keyed by its tenant. A malformed or tenant-less line is
// logged and skipped (fail closed), so one bad record never blocks the stream or
// leaks across tenants. It returns the stats and the first transport error
// (a publish failure is fatal to the run; a parse/validation failure is not).
func (br *Bridge) Ingest(ctx context.Context, r io.Reader) (Stats, error) {
	var stats Stats
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxEventLine)

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			stats.Skipped++
			br.log.Warn("skipping malformed bgp event", "error", err)
			continue
		}
		if err := ev.validate(); err != nil {
			stats.Skipped++
			br.log.Warn("skipping invalid bgp event", "error", err)
			continue
		}
		if br.expectedTenant != "" && ev.TenantID != br.expectedTenant {
			stats.Skipped++
			br.log.Error("rejecting bgp event with mismatched tenant binding",
				"expected_tenant_id", br.expectedTenant,
				"payload_binding_mismatch", true,
			)
			continue
		}
		if err := br.publish(ctx, ev); err != nil {
			return stats, err
		}
		stats.Published++
		br.log.Info("bgp event bridged",
			"tenant_id", ev.TenantID,
			"event_type", ev.EventType,
			"prefix", ev.Prefix,
			"severity", ev.Severity,
		)
	}
	if err := sc.Err(); err != nil {
		return stats, fmt.Errorf("bgp: read event stream: %w", err)
	}
	return stats, nil
}
