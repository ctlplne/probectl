// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/device"
	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
	"github.com/ctlplne/probectl/internal/metrics"
)

// DeviceTrapGroup owns the trap read model's offsets. It is a SHARED group
// (one delivery per record across replicas), not a per-replica view group:
// the store is durable and the insert is idempotent, so one writer suffices.
const DeviceTrapGroup = DefaultGroup + "-device-traps"

// DeviceTrapConsumer drains probectl.device.trap-events (and every tenant's
// namespaced lane) into the durable trap read model (D-60, DPR-296).
//
// The tenant is never the payload's: on a namespaced lane the lane names the
// tenant and overwrites whatever the record claims; on the shared lane the
// claimed (tenant, agent) pair must be registered (TENANT-101), and in
// strict-lane mode (WIRE-001) the shared lane is refused outright. Records are
// bounded before they reach storage (device.ValidateTrapRecord) and stored
// idempotently on the agent's dedup fingerprint, so a redelivered record
// changes nothing. A persistence failure is returned so the bus redelivers.
type DeviceTrapConsumer struct {
	bus        bus.Bus
	store      device.TrapEventStore
	log        *slog.Logger
	binding    TenantBinding
	nsTenants  map[string]string
	strictLane bool
	clock      func() time.Time
	ledger     *integrityLedger
	duplicates atomic.Uint64
}

// NewDeviceTrapConsumer builds the consumer over the trap store (nil store:
// records are verified and counted but not persisted — unit tests only).
func NewDeviceTrapConsumer(b bus.Bus, store device.TrapEventStore, log *slog.Logger) *DeviceTrapConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &DeviceTrapConsumer{
		bus: b, store: store, log: log, clock: time.Now,
		ledger: newIntegrityLedger("device_traps"),
	}
}

// WithTenantBinding installs registry-backed tenant verification (TENANT-101).
func (c *DeviceTrapConsumer) WithTenantBinding(binding TenantBinding) *DeviceTrapConsumer {
	c.binding = binding
	return c
}

// WithNamespaceTenants adds each tenant's namespaced trap lane; the lane is
// the authoritative tenant for its records (TENANT-107).
func (c *DeviceTrapConsumer) WithNamespaceTenants(tenants map[string]string) *DeviceTrapConsumer {
	c.nsTenants = tenants
	return c
}

// WithStrictTenantLanes refuses the shared pooled lane (WIRE-001).
func (c *DeviceTrapConsumer) WithStrictTenantLanes(strict bool) *DeviceTrapConsumer {
	c.strictLane = strict
	return c
}

// WithMetrics exports the aggregate receipt ledger at /metrics.
func (c *DeviceTrapConsumer) WithMetrics(reg *metrics.Registry) *DeviceTrapConsumer {
	c.ledger.withMetrics(reg)
	return c
}

// LaneFanoutEnabled satisfies LaneFanout (CORRECT-005 coverage gate).
func (*DeviceTrapConsumer) LaneFanoutEnabled() bool { return true }

// Run subscribes the shared lane plus every tenant lane until ctx ends.
func (c *DeviceTrapConsumer) Run(ctx context.Context) error {
	c.log.Info("device trap consumer starting", "topic", bus.DeviceTrapEventsTopic, "group", DeviceTrapGroup, "lanes", len(c.nsTenants)+1)
	return RunLanes(ctx, c.bus, bus.DeviceTrapEventsTopic, DeviceTrapGroup, c.nsTenants, c.handleLane)
}

// integrityStats returns the aggregate receipt ledger for this consumer.
func (c *DeviceTrapConsumer) integrityStats() IntegrityStats { return c.ledger.stats() }

// duplicateCount reports redelivered records the store already held.
func (c *DeviceTrapConsumer) duplicateCount() uint64 { return c.duplicates.Load() }

func (c *DeviceTrapConsumer) handleLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	c.ledger.addReceived(1)
	var batch devicev1.DeviceTrapEventBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		c.ledger.addMalformed(1)
		c.log.Warn("dropping malformed device trap batch")
		return nil
	}
	events := batch.GetEvents()
	if len(events) == 0 || len(events) > device.MaxTrapEventsPerBatch {
		c.ledger.addMalformed(1)
		c.log.Warn("dropping device trap batch outside the event-count bound", "events", len(events))
		return nil
	}
	tenant, ok := c.verifyBatch(ctx, events, laneTenant)
	if !ok {
		return nil
	}
	receivedAt := c.clock().UTC()
	records := make([]device.TrapRecord, 0, len(events))
	for _, e := range events {
		rec := device.TrapRecordFromProto(e)
		rec.TenantID = tenant // the verified tenant, never the payload's
		rec.ReceivedAt = receivedAt
		rec.ObservedAt = NormalizeEventTimeUnixNano(e.GetObservedAtUnixNano(), receivedAt)
		valid, err := device.ValidateTrapRecord(rec)
		if err != nil {
			c.ledger.addMalformed(1)
			c.log.Warn("dropping invalid device trap", "tenant_id", tenant, "agent_id", rec.AgentID, "error", err.Error())
			continue
		}
		records = append(records, valid)
	}
	if c.store == nil {
		return nil
	}
	for _, rec := range records {
		inserted, err := c.store.RecordTrapEvent(ctx, tenant, rec)
		if err != nil {
			c.log.Error("device trap persist failed; refusing ack so the bus can redeliver",
				"tenant_id", tenant, "agent_id", rec.AgentID, "error", err.Error())
			return fmt.Errorf("device trap persist failed: %w", err)
		}
		if !inserted {
			c.duplicates.Add(1)
			continue
		}
		c.ledger.addStored(1)
	}
	return nil
}

// verifyBatch re-stamps a namespaced lane's records with the lane tenant,
// requires one (tenant, agent) identity across the batch, and verifies it
// (TENANT-101 / WIRE-001). It reports false — counted, logged — on any reject.
func (c *DeviceTrapConsumer) verifyBatch(ctx context.Context, events []*devicev1.DeviceTrapEvent, laneTenant string) (string, bool) {
	if laneTenant != "" {
		for _, e := range events {
			e.TenantId = laneTenant
		}
	}
	first := events[0]
	if first.GetTenantId() == "" || first.GetAgentId() == "" {
		c.ledger.addTenantRejected(1)
		noteTenantRejection()
		c.log.Error("REJECTED device trap batch: no tenant or agent identity (fail closed)", "lane_tenant", laneTenant)
		return "", false
	}
	ids := make([]Identity, 0, len(events))
	for _, e := range events {
		if e.GetTenantId() != first.GetTenantId() || e.GetAgentId() != first.GetAgentId() {
			c.ledger.addTenantRejected(1)
			noteTenantRejection()
			c.log.Error("REJECTED device trap batch: mixed tenant or agent identities (fail closed)",
				"tenant_id", first.GetTenantId(), "agent_id", first.GetAgentId())
			return "", false
		}
		ids = append(ids, Identity{Tenant: e.GetTenantId(), Agent: e.GetAgentId()})
	}
	tenant, _, err := VerifyBatchTenantStrict(ctx, c.binding, laneTenant, c.strictLane, ids)
	if err != nil {
		c.ledger.addTenantRejected(1)
		noteTenantRejection()
		c.log.Error("REJECTED device trap batch: tenant verification failed (TENANT-101, fail closed)",
			"claimed_tenant", first.GetTenantId(), "agent_id", first.GetAgentId(),
			"lane_tenant", laneTenant, "error", err.Error())
		return "", false
	}
	return tenant, true
}
