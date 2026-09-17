// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package flow

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/version"
)

// BusEmitter publishes FlowBatches to probectl.flow.events, tenant-keyed
// (pooled tenant-tagging, CLAUDE.md §6), mirroring the eBPF/endpoint emitters.
type BusEmitter struct {
	bus       bus.Bus
	tenant    string
	namespace string
	topic     string // shared, or the tenant's namespaced lane (TENANT-107)
}

// NewBusEmitter returns an Emitter publishing to bus.FlowEventsTopic, or to
// the tenant's namespaced lane when namespace is set (siloed/hybrid tenants,
// TENANT-107). A malformed namespace is a CONSTRUCTION error — the agent
// refuses to start rather than silently publishing on the shared lane
// (RED-006, fail closed).
func NewBusEmitter(b bus.Bus, tenant string) *BusEmitter {
	e, _ := NewNamespacedBusEmitter(b, tenant, "")
	return e
}

// NewNamespacedBusEmitter is NewBusEmitter with an optional silo namespace.
func NewNamespacedBusEmitter(b bus.Bus, tenant, namespace string) (*BusEmitter, error) {
	topic, err := bus.TopicFor(namespace, bus.FlowEventsTopic)
	if err != nil {
		return nil, fmt.Errorf("flow: refusing to start: %w", err)
	}
	return &BusEmitter{bus: b, tenant: tenant, namespace: namespace, topic: topic}, nil
}

// Emit marshals the batch and publishes it. An empty batch is a no-op.
func (e *BusEmitter) Emit(ctx context.Context, recs []Record) error {
	if len(recs) == 0 {
		return nil
	}
	// DPR-093: the batch names the collector's build version; the fleet view
	// and staged rollouts learn it from here.
	batch := &flowv1.FlowBatch{Flows: make([]*flowv1.FlowRecord, 0, len(recs)), AgentVersion: version.Get().Version}
	for i := range recs {
		batch.Flows = append(batch.Flows, recs[i].ToProto())
	}
	value, err := proto.Marshal(batch)
	if err != nil {
		return fmt.Errorf("flow: marshal batch: %w", err)
	}
	entropy := ""
	if len(recs) > 0 {
		entropy = recs[0].AgentID // stable per collector: per-agent FIFO holds
	}
	return e.bus.Publish(ctx, e.topic, bus.TenantKey(e.tenant, entropy), value)
}

// EmitQuality publishes one bounded versioned receipt batch on the separate
// flow-ingest quality topic. The analytics event payload is never duplicated.
func (e *BusEmitter) EmitQuality(ctx context.Context, receipts []QualityReceipt) error {
	if len(receipts) == 0 {
		return nil
	}
	if len(receipts) > MaxQualityReceiptBatch {
		return fmt.Errorf("flow: quality receipt batch exceeds %d", MaxQualityReceiptBatch)
	}
	batch := &flowv1.FlowIngestQualityBatch{
		ContractVersion: QualityContractVersion,
		Receipts:        make([]*flowv1.FlowIngestQualityReceipt, 0, len(receipts)),
	}
	agentID := ""
	for _, receipt := range receipts {
		if receipt.TenantID != e.tenant {
			return fmt.Errorf("flow: quality receipt tenant scope mismatch")
		}
		valid, err := ValidateQualityReceipt(receipt)
		if err != nil {
			return err
		}
		if agentID == "" {
			agentID = valid.AgentID
		} else if agentID != valid.AgentID {
			return fmt.Errorf("flow: quality receipt batch mixes agents")
		}
		batch.Receipts = append(batch.Receipts, valid.ToProto())
	}
	value, err := proto.Marshal(batch)
	if err != nil {
		return fmt.Errorf("flow: marshal quality receipt batch: %w", err)
	}
	topic, err := bus.TopicFor(e.namespace, bus.FlowIngestQualityTopic)
	if err != nil {
		return fmt.Errorf("flow: quality receipt topic: %w", err)
	}
	return e.bus.Publish(ctx, topic, bus.TenantKey(e.tenant, agentID), value)
}

var _ QualityEmitter = (*BusEmitter)(nil)
