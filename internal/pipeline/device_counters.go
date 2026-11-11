// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/metrics"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const DeviceCounterGroup = DefaultGroup + "-device-counters"

type counterPublicationWitness interface {
	PublishUnderWitness(context.Context, string, [32]byte, entity.CounterCaptureInput, int, func(context.Context, store.DeviceCounterCapture) error) error
}

// DeviceCounterConsumer preserves original words in an independent history
// plane. Bus tenant attribution alone never authorizes a sender: every whole
// poll must match an already-persisted, current mTLS witness under tenant RLS.
type DeviceCounterConsumer struct {
	bus           bus.Bus
	history       flowstore.CounterHistory
	witness       counterPublicationWitness
	budget        flowstore.CounterBudget
	retentionDays int
	log           *slog.Logger
	binding       TenantBinding
	nsTenants     map[string]string
	strictLane    bool
	gate          *fairness.Gate
	ledger        *integrityLedger
}

func NewDeviceCounterConsumer(b bus.Bus, history flowstore.CounterHistory, witness counterPublicationWitness, budget flowstore.CounterBudget, retentionDays int, log *slog.Logger) *DeviceCounterConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &DeviceCounterConsumer{bus: b, history: history, witness: witness, budget: budget, retentionDays: retentionDays, log: log, ledger: newIntegrityLedger("device_counters")}
}

func (c *DeviceCounterConsumer) WithTenantBinding(binding TenantBinding) *DeviceCounterConsumer {
	c.binding = binding
	return c
}
func (c *DeviceCounterConsumer) WithNamespaceTenants(tenants map[string]string) *DeviceCounterConsumer {
	c.nsTenants = tenants
	return c
}
func (c *DeviceCounterConsumer) WithStrictTenantLanes(strict bool) *DeviceCounterConsumer {
	c.strictLane = strict
	return c
}
func (c *DeviceCounterConsumer) WithFairness(gate *fairness.Gate) *DeviceCounterConsumer {
	c.gate = gate
	return c
}
func (c *DeviceCounterConsumer) WithMetrics(reg *metrics.Registry) *DeviceCounterConsumer {
	c.ledger.withMetrics(reg)
	return c
}
func (*DeviceCounterConsumer) LaneFanoutEnabled() bool { return true }

func (c *DeviceCounterConsumer) Run(ctx context.Context) error {
	if c.bus == nil || c.history == nil || c.witness == nil || c.binding == nil || c.budget.MemoryBytes < 64<<10 || c.budget.WorkUnits < 64<<10 || c.budget.Timeout <= 0 || c.retentionDays < 0 {
		return flowstore.ErrCounterHistoryUnavailable
	}
	return RunLanes(ctx, c.bus, bus.DeviceCountersTopic, DeviceCounterGroup, c.nsTenants, c.handleLane)
}

func (c *DeviceCounterConsumer) reject(reason string) error {
	c.ledger.addTenantRejected(1)
	noteTenantRejection()
	c.log.Warn("counter poll refused", "reason", reason)
	return nil
}

func (c *DeviceCounterConsumer) handleLane(ctx context.Context, message bus.Message, laneTenant string) error {
	c.ledger.addReceived(1)
	if refuse, held := refuseSharedOrQuarantined(ctx, c.log, DeviceCounterGroup, message, laneTenant); held != nil {
		return held
	} else if refuse {
		return c.reject("tenant_lane")
	}
	tenant := bus.TenantFromKey(message.Key)
	if laneTenant != "" && tenant != laneTenant {
		return c.reject("tenant_key_disagrees_with_lane")
	}
	id, err := uuid.Parse(tenant)
	if err != nil || id == uuid.Nil || id.String() != tenant || c.binding == nil || (laneTenant == "" && c.strictLane) {
		return c.reject("tenant_identity")
	}
	if c.history == nil || c.witness == nil {
		return flowstore.ErrCounterHistoryUnavailable
	}
	ctx, cancel := context.WithTimeout(tenancy.WithTenant(ctx, tenancy.ID(tenant)), c.budget.Timeout)
	defer cancel()
	// Reserve half the operation for decode/wire ownership and half for
	// typed rows/backend IO. Work and memory never reset for a partial poll.
	batch, err := device.ParseCounterBatch(ctx, tenant, message.Value, c.budget.MemoryBytes/2, c.budget.WorkUnits/2)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, device.ErrCounterBatchBudget) {
			return flowstore.ErrCounterHistoryBudget
		}
		c.ledger.addMalformed(1)
		return nil
	}
	if _, overwritten, err := VerifyBatchTenantStrict(ctx, c.binding, laneTenant, c.strictLane, []Identity{{Tenant: tenant, Agent: batch.Sender}}); err != nil || overwritten {
		if errors.Is(err, ErrBindingUnavailable) {
			return flowstore.ErrCounterHistoryUnavailable
		}
		return c.reject("sender_registry")
	}
	if c.gate != nil && !c.gate.AdmitN(ctx, tenant, fairness.MeterDeviceMetrics, int64(len(batch.Metrics))) {
		c.ledger.addFairnessShed(1)
		return flowstore.ErrCounterHistoryBudget // Leave the complete poll on the bus.
	}
	writeBudget := c.budget
	writeBudget.MemoryBytes /= 2
	writeBudget.WorkUnits /= 2
	if int64(len(batch.Metrics)) > writeBudget.MemoryBytes/4096 || int64(len(batch.Metrics)) > writeBudget.WorkUnits/4096 {
		return flowstore.ErrCounterHistoryBudget
	}
	err = c.witness.PublishUnderWitness(ctx, batch.Sender, batch.Digest, batch.Input, c.retentionDays, func(ctx context.Context, witness store.DeviceCounterCapture) error {
		key, err := entity.CounterCaptureKey(tenant, batch.Sender, batch.Digest, batch.Input)
		if err != nil || witness.Key != key || witness.Scope.TenantID != tenant {
			return store.ErrCounterCaptureUnavailable
		}
		rows := make([]flowstore.CounterRow, len(batch.Metrics))
		for i, point := range batch.Metrics {
			if err := ctx.Err(); err != nil {
				return err
			}
			word := point.ExactCounter
			row := flowstore.CounterRow{TenantID: tenant, CounterSource: flowstore.CounterSource{ContextID: witness.Scope.ContextID, DeviceID: witness.DeviceID, AgentID: batch.Sender, SourceRef: batch.Input.ConfiguredTarget, SourceAssignedAt: witness.SourceAssignedAt, AgentAssignedAt: witness.AgentAssignedAt}, SenderSerial: witness.SenderSerial, CaptureKey: witness.Key, RawDigest: batch.Digest, CapturedAt: witness.CapturedAt, PollStartedAt: batch.Input.PollStartedAt, PollCompletedAt: batch.Input.PollCompletedAt, Population: batch.Input.PointCount, IfIndex: point.IfIndex, Name: point.Name, Value: word.Value, Width: word.Width}
			if word.UptimeTicks != nil {
				row.UptimeKnown = true
				row.UptimeTicks = *word.UptimeTicks
			}
			if word.DiscontinuityTicks != nil {
				row.DiscontinuityKnown = true
				row.DiscontinuityTicks = *word.DiscontinuityTicks
			}
			rows[i] = row
		}
		return c.history.InsertCounterPoll(ctx, rows, writeBudget)
	})
	if errors.Is(err, store.ErrCounterCaptureUnavailable) {
		return c.reject("current_sender_witness")
	}
	if err != nil {
		c.log.Warn("counter history publication held for retry", "tenant_id", tenant)
		return flowstore.ErrCounterHistoryUnavailable
	}
	c.ledger.addStored(1)
	return nil
}
