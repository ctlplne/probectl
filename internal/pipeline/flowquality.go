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
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/flow"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/metrics"
)

// FlowQualityGroup owns offsets for the current receipt path independently of
// the high-volume analytics consumer.
const FlowQualityGroup = DefaultGroup + "-flow-quality"

// FlowQualityConsumer verifies producer identity before persisting bounded
// quality receipts. Invalid/untrusted payloads fail closed; persistence errors
// are returned so the bus can redeliver.
type FlowQualityConsumer struct {
	bus        bus.Bus
	store      flow.QualityStore
	log        *slog.Logger
	binding    TenantBinding
	nsTenants  map[string]string
	strictLane bool
	clock      func() time.Time
	ledger     *integrityLedger
}

func NewFlowQualityConsumer(b bus.Bus, store flow.QualityStore, log *slog.Logger) *FlowQualityConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &FlowQualityConsumer{
		bus: b, store: store, log: log, clock: time.Now,
		ledger: newIntegrityLedger("flow_quality"),
	}
}

func (c *FlowQualityConsumer) WithTenantBinding(binding TenantBinding) *FlowQualityConsumer {
	c.binding = binding
	return c
}

func (c *FlowQualityConsumer) WithNamespaceTenants(tenants map[string]string) *FlowQualityConsumer {
	c.nsTenants = tenants
	return c
}

func (c *FlowQualityConsumer) WithStrictTenantLanes(strict bool) *FlowQualityConsumer {
	c.strictLane = strict
	return c
}

func (c *FlowQualityConsumer) WithMetrics(reg *metrics.Registry) *FlowQualityConsumer {
	c.ledger.withMetrics(reg)
	return c
}

func (*FlowQualityConsumer) LaneFanoutEnabled() bool { return true }

func (c *FlowQualityConsumer) Run(ctx context.Context) error {
	return RunLanes(
		ctx, c.bus, bus.FlowIngestQualityTopic, FlowQualityGroup,
		c.nsTenants, c.handleLane,
	)
}

func (c *FlowQualityConsumer) handle(ctx context.Context, msg bus.Message) error {
	return c.handleLane(ctx, msg, "")
}

func (c *FlowQualityConsumer) handleLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	c.ledger.addReceived(1)
	var batch flowv1.FlowIngestQualityBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		c.ledger.addMalformed(1)
		c.log.Warn("dropping malformed flow quality receipt batch")
		return nil
	}
	if batch.GetContractVersion() != flow.QualityContractVersion ||
		len(batch.GetReceipts()) == 0 ||
		len(batch.GetReceipts()) > flow.MaxQualityReceiptBatch {
		c.ledger.addMalformed(1)
		return nil
	}
	for _, receipt := range batch.GetReceipts() {
		if receipt == nil ||
			receipt.GetWindowStartedAtUnixNano() == 0 ||
			receipt.GetWindowEndedAtUnixNano() == 0 ||
			receipt.GetLastPacketAtUnixNano() == 0 {
			c.ledger.addMalformed(1)
			return nil
		}
	}
	if laneTenant != "" {
		for _, receipt := range batch.GetReceipts() {
			receipt.TenantId = laneTenant
		}
	}
	first := batch.GetReceipts()[0]
	if first.GetTenantId() == "" || first.GetAgentId() == "" {
		c.ledger.addTenantRejected(1)
		return nil
	}
	ids := make([]Identity, 0, len(batch.GetReceipts()))
	for _, receipt := range batch.GetReceipts() {
		if receipt.GetTenantId() != first.GetTenantId() || receipt.GetAgentId() != first.GetAgentId() {
			c.ledger.addTenantRejected(1)
			c.log.Error("REJECTED flow quality batch: mixed tenant or agent identities",
				"tenant_id", first.GetTenantId(), "agent_id", first.GetAgentId())
			return nil
		}
		ids = append(ids, Identity{Tenant: receipt.GetTenantId(), Agent: receipt.GetAgentId()})
	}
	tenant, _, err := VerifyBatchTenantStrict(ctx, c.binding, laneTenant, c.strictLane, ids)
	if err != nil {
		c.ledger.addTenantRejected(1)
		noteTenantRejection()
		c.log.Error("REJECTED flow quality batch: tenant verification failed",
			"claimed_tenant", first.GetTenantId(), "agent_id", first.GetAgentId(),
			"lane_tenant", laneTenant)
		return nil
	}

	receivedAt := c.clock().UTC()
	validated := make([]flow.QualityReceipt, 0, len(batch.GetReceipts()))
	for _, raw := range batch.GetReceipts() {
		raw.TenantId = tenant
		receipt := flow.QualityReceiptFromProto(raw)
		receipt.WindowStartedAt = NormalizeEventTimeUnixNano(raw.GetWindowStartedAtUnixNano(), receivedAt)
		receipt.WindowEndedAt = NormalizeEventTimeUnixNano(raw.GetWindowEndedAtUnixNano(), receivedAt)
		receipt.LastPacketAt = NormalizeEventTimeUnixNano(raw.GetLastPacketAtUnixNano(), receivedAt)
		if raw.GetLastValidRecordAtUnixNano() != 0 {
			at := NormalizeEventTimeUnixNano(raw.GetLastValidRecordAtUnixNano(), receivedAt)
			receipt.LastValidRecordAt = &at
		}
		valid, err := flow.ValidateQualityReceipt(receipt)
		if err != nil {
			c.ledger.addMalformed(1)
			c.log.Warn("dropping invalid flow quality receipt")
			return nil
		}
		validated = append(validated, valid)
	}
	if c.store == nil {
		return nil
	}
	for _, receipt := range validated {
		if err := c.store.UpsertQualityReceipt(ctx, tenant, receipt); err != nil {
			return fmt.Errorf("flow quality receipt persist failed: %w", err)
		}
		c.ledger.addStored(1)
	}
	return nil
}
