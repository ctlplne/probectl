// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"net/netip"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

// RoutingWitnessEmitter is optional on the existing asynchronous evidence
// worker. The client verifies complete certificate-bound receipts. The runtime
// wrapper supplies this interface only when the complete ingestion adapter is
// wired; raw bus publication never waits for a witness RPC.
type RoutingWitnessEmitter interface {
	SubmitFlowRouting(context.Context, []*agentv1.FlowRoutingWitness) ([]*agentv1.FlowRoutingCapture, error)
}

func (c *Collector) routingWitnesses(ctx context.Context, batch []Record) ([]*agentv1.FlowRoutingWitness, error) {
	if c.cfg.BatchSize <= 0 || len(batch) > c.cfg.BatchSize {
		return nil, ErrRoutingCaptureAdmission
	}
	// The configured raw batch is already finite. This representation account
	// covers the full descriptor, pointers, key and address strings per record;
	// no independent count ceiling reduces the configured workload.
	count := int64(c.cfg.BatchSize)
	if count > int64(^uint64(0)>>1)/32768 {
		return nil, ErrRoutingCaptureAdmission
	}
	memory, work := count*4096, count*32768
	out := make([]*agentv1.FlowRoutingWitness, 0, len(batch))
	for _, record := range batch {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if record.TenantID != c.cfg.TenantID || record.AgentID != c.cfg.AgentID {
			return nil, entity.ErrScopeMismatch
		}
		switch record.Protocol {
		case ProtoNetFlow5, ProtoNetFlow9, ProtoIPFIX, ProtoSFlow5:
		default:
			continue
		}
		exporter, err := netip.ParseAddr(record.Exporter)
		if err != nil {
			return nil, entity.ErrInvalidClaim
		}
		if _, configured := c.evidenceSources[exporter.Unmap().String()]; !configured {
			continue
		}
		digest, input, err := RoutingCaptureWitness(ctx, record.ToProto(), memory, work)
		if err != nil {
			return nil, err
		}
		out = append(out, &agentv1.FlowRoutingWitness{RawDigest: append([]byte(nil), digest[:]...), ExporterAddress: input.Exporter.String(), FlowProtocol: input.Protocol, ObservationDomain: input.Domain, SourceAddress: input.Source.String(), DestinationAddress: input.Destination.String()})
	}
	return out, nil
}

func (c *Collector) sendRoutingWitnesses(ctx context.Context, batch []Record) {
	emitter, ok := c.evidence.(RoutingWitnessEmitter)
	if !ok {
		return
	}
	witnesses, err := c.routingWitnesses(ctx, batch)
	if err == nil && len(witnesses) == 0 {
		return
	}
	if err == nil {
		var receipts []*agentv1.FlowRoutingCapture
		receipts, err = emitter.SubmitFlowRouting(ctx, witnesses)
		if err == nil && len(receipts) != len(witnesses) {
			err = ErrRoutingCaptureAdmission
		}
		if err == nil {
			c.stats.RoutingWitnessReceipts.Add(uint64(len(receipts)))
			return
		}
	}
	c.stats.RoutingWitnessErrors.Add(1)
	c.log.Warn("flow routing witness unavailable; raw events retained", "tenant_id", c.cfg.TenantID, "agent_id", c.cfg.AgentID, "count", len(batch), "error", err.Error())
}
