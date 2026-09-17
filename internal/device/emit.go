// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package device

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
	"github.com/ctlplne/probectl/internal/version"
)

// Emitter receives normalized metric batches (the bus emitter in production,
// a capture in tests).
type Emitter interface {
	Emit(ctx context.Context, ms []Metric) error
}

// NeighborEmitter is an optional extension implemented by the production bus
// emitter. Existing metric-only test emitters remain source-compatible.
type NeighborEmitter interface {
	EmitNeighbors(context.Context, NeighborSnapshot) error
}

// CollectionOutcomeEmitter is an optional extension implemented by the
// production bus emitter. It never carries raw SNMP values or credentials.
type CollectionOutcomeEmitter interface {
	EmitCollectionOutcome(context.Context, CollectionOutcome) error
}

// BusEmitter publishes DeviceMetricBatches to probectl.device.metrics,
// tenant-keyed (pooled tenant-tagging, CLAUDE.md §6).
type BusEmitter struct {
	bus       bus.Bus
	tenant    string
	namespace string
	topic     string // shared, or the tenant's namespaced lane (TENANT-107)
}

// NewBusEmitter returns an Emitter publishing to bus.DeviceMetricsTopic.
func NewBusEmitter(b bus.Bus, tenant string) *BusEmitter {
	e, _ := NewNamespacedBusEmitter(b, tenant, "")
	return e
}

// NewNamespacedBusEmitter publishes to the tenant's namespaced lane when
// namespace is set (TENANT-107). A malformed namespace refuses construction
// (RED-006: never a silent shared-lane fallback).
func NewNamespacedBusEmitter(b bus.Bus, tenant, namespace string) (*BusEmitter, error) {
	topic, err := bus.TopicFor(namespace, bus.DeviceMetricsTopic)
	if err != nil {
		return nil, fmt.Errorf("device: refusing to start: %w", err)
	}
	return &BusEmitter{bus: b, tenant: tenant, namespace: namespace, topic: topic}, nil
}

// Emit marshals the batch and publishes it. An empty batch is a no-op.
func (e *BusEmitter) Emit(ctx context.Context, ms []Metric) error {
	if len(ms) == 0 {
		return nil
	}
	// DPR-093: the batch names the collector's build version.
	batch := &devicev1.DeviceMetricBatch{Metrics: make([]*devicev1.DeviceMetric, 0, len(ms)), AgentVersion: version.Get().Version}
	for i := range ms {
		batch.Metrics = append(batch.Metrics, ms[i].ToProto())
	}
	value, err := proto.Marshal(batch)
	if err != nil {
		return fmt.Errorf("device: marshal batch: %w", err)
	}
	entropy := ""
	if len(ms) > 0 {
		entropy = ms[0].AgentID
	}
	return e.bus.Publish(ctx, e.topic, bus.TenantKey(e.tenant, entropy), value)
}

// EmitNeighbors publishes one bounded current-evidence snapshot. Empty
// snapshots are meaningful: they clear a device's previously observed rows.
func (e *BusEmitter) EmitNeighbors(ctx context.Context, snapshot NeighborSnapshot) error {
	valid, err := ValidateNeighborSnapshot(snapshot)
	if err != nil {
		return err
	}
	batch := &devicev1.DeviceNeighborSnapshot{
		TenantId: valid.TenantID, AgentId: valid.AgentID,
		DeviceAddress: valid.DeviceAddress, DeviceName: valid.DeviceName,
		ObservedAtUnixNano: valid.ObservedAt.UnixNano(),
		Neighbors:          make([]*devicev1.DeviceNeighborEvidence, 0, len(valid.Neighbors)),
	}
	for _, neighbor := range valid.Neighbors {
		batch.Neighbors = append(batch.Neighbors, neighbor.ToProto())
	}
	value, err := proto.Marshal(batch)
	if err != nil {
		return fmt.Errorf("device: marshal neighbor snapshot: %w", err)
	}
	topic, err := bus.TopicFor(e.namespace, bus.DeviceNeighborsTopic)
	if err != nil {
		return err // constructor already validates; fail closed if state changes
	}
	return e.bus.Publish(ctx, topic, bus.TenantKey(e.tenant, valid.AgentID), value)
}

// EmitCollectionOutcome publishes one bounded readiness receipt on the
// existing tenant-tagged bus. A separate topic prevents a failed attempt from
// being mistaken for an authoritative empty adjacency snapshot.
func (e *BusEmitter) EmitCollectionOutcome(ctx context.Context, outcome CollectionOutcome) error {
	valid, err := ValidateCollectionOutcome(outcome)
	if err != nil {
		return err
	}
	value, err := proto.Marshal(&devicev1.DeviceCollectionOutcomeBatch{
		Outcomes: []*devicev1.DeviceCollectionOutcome{valid.ToProto()},
	})
	if err != nil {
		return fmt.Errorf("device: marshal collection outcome: %w", err)
	}
	topic, err := bus.TopicFor(e.namespace, bus.DeviceCollectionOutcomesTopic)
	if err != nil {
		return err
	}
	return e.bus.Publish(ctx, topic, bus.TenantKey(e.tenant, valid.AgentID), value)
}
