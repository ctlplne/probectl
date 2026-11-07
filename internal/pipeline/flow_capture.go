// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// FlowRoutingCaptureResolver may resolve a certificate-attested witness or
// seal unavailable. Its sender argument is an untrusted lookup selector. The
// runtime must never wire the evidence writer's CaptureAuthenticated method.
type FlowRoutingCaptureResolver func(context.Context, string, [32]byte, entity.FlowCaptureInput) (entity.FlowCaptureReference, error)

type flowRoutingCaptures struct {
	resolve           FlowRoutingCaptureResolver
	memoryBytes, work int64
}

type flowCaptureProjection struct {
	digest [32]byte
	input  entity.FlowCaptureInput
	key    [32]byte
	ref    entity.FlowCaptureReference
}

var errFlowCaptureReference = errors.New("pipeline: incomplete or mismatched original flow capture reference")

// WithRoutingCaptures installs finite byte/work admission for a whole raw
// batch. No source lookup or canonical grant is derived from bus payloads.
// Nil retains legacy ingestion. The runtime activates this only together with
// the producer timing and durable first-receipt adapter.
func (c *FlowConsumer) WithRoutingCaptures(resolve FlowRoutingCaptureResolver, memoryBytes, workUnits int64) *FlowConsumer {
	if resolve == nil {
		c.captures = nil
	} else {
		c.captures = &flowRoutingCaptures{resolve: resolve, memoryBytes: memoryBytes, work: workUnits}
	}
	return c
}

func (c *FlowConsumer) resolveFlowCaptures(ctx context.Context, tenant string, records []*flowv1.FlowRecord) ([]flowCaptureProjection, error) {
	if c.captures == nil {
		return nil, nil
	}
	if current, ok := tenancy.FromContext(ctx); ok && current.String() != tenant {
		return nil, entity.ErrScopeMismatch
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))
	memory, work := c.captures.memoryBytes, c.captures.work
	// Account for the complete descriptor/reference population before making
	// any durable calls. The native source payload is separately charged below.
	if memory <= 0 || work <= 0 || int64(len(records)) > memory/256 || int64(len(records)) > work/256 {
		return nil, flow.ErrRoutingCaptureAdmission
	}
	memory -= int64(len(records)) * 256
	work -= int64(len(records)) * 256
	projections := make([]flowCaptureProjection, len(records))
	for i, record := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		input, eligible := flowCaptureTuple(record)
		if !eligible {
			continue // raw malformed/cloud data cannot invent a routing receipt
		}
		digest, err := flow.OriginalFlowDigest(ctx, record, memory, work)
		if err != nil {
			return nil, err
		}
		cost := int64(proto.Size(record))
		memory -= cost * 4
		work -= cost * 8
		key, err := entity.FlowCaptureKey(tenant, record.GetAgentId(), digest, input)
		if err != nil {
			continue // invalid sender/tuple remains raw data without authority
		}
		projections[i] = flowCaptureProjection{digest: digest, input: input, key: key}
	}
	for i := range projections {
		projection := &projections[i]
		if projection.key == ([32]byte{}) {
			continue
		}
		ref, err := c.captures.resolve(ctx, records[i].GetAgentId(), projection.digest, projection.input)
		if err != nil {
			return nil, err
		}
		clock := ref.CapturedAt.UnixNano()
		if ref.Key != projection.key || clock <= 0 || !time.Unix(0, clock).Equal(ref.CapturedAt) {
			return nil, errFlowCaptureReference
		}
		projection.ref = ref
	}
	return projections, nil
}

func flowCaptureTuple(record *flowv1.FlowRecord) (entity.FlowCaptureInput, bool) {
	switch record.GetFlowProtocol() {
	case "netflow5", "netflow9", "ipfix", "sflow5":
	default:
		return entity.FlowCaptureInput{}, false
	}
	exporter, e1 := netip.ParseAddr(record.GetExporterAddress())
	source, e2 := netip.ParseAddr(record.GetSourceAddress())
	destination, e3 := netip.ParseAddr(record.GetDestinationAddress())
	return entity.FlowCaptureInput{Exporter: exporter, Source: source, Destination: destination, Protocol: record.GetFlowProtocol(), Domain: record.GetObservationDomain()}, e1 == nil && e2 == nil && e3 == nil
}

func projectedFlowCapture(record *flowv1.FlowRecord, captures []flowCaptureProjection, i int) flowstore.Row {
	if len(captures) == 0 || captures[i].ref.Key == ([32]byte{}) {
		return rowFromProto(record)
	}
	captured := captures[i]
	row := rowFromProtoAt(record, captured.ref.CapturedAt)
	row.RawFlowDigest = hex.EncodeToString(captured.digest[:])
	row.RoutingCaptureKey = hex.EncodeToString(captured.ref.Key[:])
	row.RoutingCapturedUnixNanos = captured.ref.CapturedAt.UnixNano()
	return row
}
