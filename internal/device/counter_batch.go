// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"errors"
	"math"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
)

var ErrCounterBatchInvalid = errors.New("device: complete scoped exact counter batch required")

// RawCounterBatch owns its decoded observations. Its identity fields are lookup
// selectors, not authenticated authority; a current stored sender witness must
// independently match the complete raw digest before history accepts anything.
type RawCounterBatch struct {
	Sender  string
	Digest  [32]byte
	Input   entity.CounterCaptureInput
	Metrics []*devicev1.DeviceMetric
}

// ParseCounterBatch validates the whole original poll under the authenticated
// bus tenant. Count and wire admission happen before protobuf allocations.
func ParseCounterBatch(ctx context.Context, tenant string, raw []byte, memoryBytes, workUnits int64) (RawCounterBatch, error) {
	none := RawCounterBatch{}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	size := int64(len(raw))
	if size == 0 || memoryBytes <= 0 || workUnits <= 0 || size > memoryBytes/8 || size > workUnits/8 {
		return none, ErrCounterBatchInvalid
	}
	count, err := counterBatchWireCount(ctx, raw)
	if err != nil {
		return none, err
	}
	if count == 0 || count > math.MaxUint32 || int64(count) > (memoryBytes-size*8)/1024 || int64(count) > (workUnits-size*8)/1024 {
		return none, ErrCounterBatchInvalid
	}
	batch := &devicev1.DeviceMetricBatch{}
	if err := proto.Unmarshal(raw, batch); err != nil || len(batch.ProtoReflect().GetUnknown()) != 0 || len(batch.Metrics) != count {
		return none, ErrCounterBatchInvalid
	}
	result := RawCounterBatch{Metrics: batch.Metrics}
	type pointKey struct {
		iface uint32
		name  string
	}
	seen := make(map[pointKey]struct{}, count)
	for i, metric := range batch.Metrics {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		if metric == nil || metric.TenantId != tenant || metric.Source != SourceSNMP || metric.IfIndex == 0 || !isCounter(metric.Name) || len(metric.ProtoReflect().GetUnknown()) != 0 {
			return none, ErrCounterBatchInvalid
		}
		counter := metric.ExactCounter
		if counter == nil || len(counter.ProtoReflect().GetUnknown()) != 0 || (counter.Width != 32 && counter.Width != 64) || (counter.Width == 32 && counter.Value > math.MaxUint32) || counter.PollStartedAtUnixNano <= 0 || counter.PollCompletedAtUnixNano < counter.PollStartedAtUnixNano || metric.TimeUnixNano != counter.PollStartedAtUnixNano {
			return none, ErrCounterBatchInvalid
		}
		if i == 0 {
			result.Sender = metric.AgentId
			result.Input = entity.CounterCaptureInput{ConfiguredTarget: metric.DeviceAddress,
				PollStartedAt: time.Unix(0, counter.PollStartedAtUnixNano), PollCompletedAt: time.Unix(0, counter.PollCompletedAtUnixNano), PointCount: uint32(count)}
		}
		if metric.AgentId != result.Sender || metric.DeviceAddress != result.Input.ConfiguredTarget || counter.PollStartedAtUnixNano != result.Input.PollStartedAt.UnixNano() || counter.PollCompletedAtUnixNano != result.Input.PollCompletedAt.UnixNano() {
			return none, ErrCounterBatchInvalid
		}
		key := pointKey{metric.IfIndex, metric.Name}
		if _, duplicate := seen[key]; duplicate {
			return none, ErrCounterBatchInvalid
		}
		seen[key] = struct{}{}
	}
	copy(result.Digest[:], crypto.Hash(raw))
	if _, err := entity.CounterCaptureKey(tenant, result.Sender, result.Digest, result.Input); err != nil {
		return none, ErrCounterBatchInvalid
	}
	return result, nil
}

// Walk only the outer envelope, retaining no borrowed body slices. Unknown or
// wrongly typed envelope fields fail before an unsupported operation is decoded.
func counterBatchWireCount(ctx context.Context, raw []byte) (int, error) {
	count := 0
	for len(raw) != 0 {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		number, kind, n := protowire.ConsumeTag(raw)
		if n < 0 || kind != protowire.BytesType || (number != 1 && number != 2) {
			return 0, ErrCounterBatchInvalid
		}
		raw = raw[n:]
		_, n = protowire.ConsumeBytes(raw)
		if n < 0 {
			return 0, ErrCounterBatchInvalid
		}
		if number == 1 {
			count++
		}
		raw = raw[n:]
	}
	return count, nil
}
