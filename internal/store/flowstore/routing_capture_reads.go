// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"bytes"
	"context"
	"encoding/hex"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/store/chclient"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// RoutingCaptureRead identifies the original retained flow and observed tuple.
// These values are lookup selectors, never current source or context grants.
type RoutingCaptureRead struct {
	Sender  string
	Witness entity.FlowCaptureWitness
	Ref     entity.FlowCaptureReference
	Timing  FlowCaptureTiming
}

// FlowCaptureTiming retains the private raw clock used by temporal metadata
// reads. It cannot turn a fallback timestamp into an original observation.
type FlowCaptureTiming struct {
	Start, End time.Time
	Basis      flowv1.FlowClockBasis
}

// ObservationRange returns the conservative half-open event interval on the
// inventory clock. The start is rounded down to raw storage precision, and
// the interval includes the final stored millisecond and both error bounds.
func (clock FlowCaptureTiming) ObservationRange(protocol string, clockError time.Duration) (time.Time, time.Time, bool) {
	if clock.Start.UnixMilli() <= 0 || clock.End.Before(clock.Start) ||
		clockError < 0 || clockError > time.Duration(math.MaxInt64)-time.Millisecond {
		return time.Time{}, time.Time{}, false
	}
	switch clock.Basis {
	case flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL:
		if protocol != flow.ProtoIPFIX && protocol != flow.ProtoNetFlow9 && protocol != flow.ProtoNetFlow5 {
			return time.Time{}, time.Time{}, false
		}
	case flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_COLLECTOR_SAMPLE:
		if protocol != flow.ProtoSFlow5 || !clock.Start.Equal(clock.End) {
			return time.Time{}, time.Time{}, false
		}
	default:
		return time.Time{}, time.Time{}, false
	}
	start := time.UnixMilli(clock.Start.UnixMilli()).UTC().Add(-clockError)
	end := time.UnixMilli(clock.End.UnixMilli()).UTC().Add(time.Millisecond + clockError)
	return start, end, true
}

// ReadRoutingCaptureReferences enumerates the full tenant window through the
// configured backend's existing admission. Selectors are never source grants.
func ReadRoutingCaptureReferences(ctx context.Context, store Store, tenant string, from, to time.Time, series string) ([]RoutingCaptureRead, error) {
	return readFlowCaptureReferences(ctx, store, tenant, from, to, series, false)
}

// ReadTimedFlowCaptureReferences requests raw clock evidence alongside the
// original source selectors. The rollup may retain a start timestamp without
// retaining its provenance, so temporal attribution cannot use that lane.
func ReadTimedFlowCaptureReferences(ctx context.Context, store Store, tenant string, from, to time.Time, series string) ([]RoutingCaptureRead, error) {
	return readFlowCaptureReferences(ctx, store, tenant, from, to, series, true)
}

func readFlowCaptureReferences(ctx context.Context, store Store, tenant string, from, to time.Time, series string, withTiming bool) ([]RoutingCaptureRead, error) {
	backend, ok := PlanStoreOf(store)
	if !ok {
		return nil, ErrExplorerBudget
	}
	switch reader := backend.(type) {
	case *Memory:
		if reader != nil {
			return reader.routingCaptureReferences(ctx, tenant, from, to, series, withTiming)
		}
	case *ClickHouse:
		if reader != nil {
			return reader.routingCaptureReferences(ctx, tenant, from, to, series, withTiming)
		}
	}
	return nil, ErrExplorerBudget
}

// RoutingCaptureReferences shares the operation deadline, tenant and cumulative
// read envelope with the plans. Metadata does not consume another plan slot.
func (b *PlanBatch) RoutingCaptureReferences(from, to time.Time, series string) ([]RoutingCaptureRead, error) {
	return b.flowCaptureReferences(from, to, series, false)
}

func (b *PlanBatch) TimedFlowCaptureReferences(from, to time.Time, series string) ([]RoutingCaptureRead, error) {
	return b.flowCaptureReferences(from, to, series, true)
}

func (b *PlanBatch) flowCaptureReferences(from, to time.Time, series string, withTiming bool) ([]RoutingCaptureRead, error) {
	b.queryMu.Lock()
	defer b.queryMu.Unlock()
	if err := b.ctx.Err(); err != nil {
		return nil, err
	}
	if b.failed {
		return nil, ErrExplorerBudget
	}
	var out []RoutingCaptureRead
	var err error
	switch backend := b.backend.(type) {
	case *Memory:
		out, err = backend.routingCaptureReferences(b.queryContext(), b.tenant, from, to, series, withTiming)
	case *ClickHouse:
		out, err = backend.routingCaptureReferences(b.queryContext(), b.tenant, from, to, series, withTiming)
	default:
		err = ErrExplorerBudget
	}
	if err != nil {
		b.failed = true
		return nil, err
	}
	return out, nil
}

func routingReferencePlan(ctx context.Context, tenant string, from, to time.Time, series string) (flow.QueryPlan, error) {
	if err := ctx.Err(); err != nil {
		return flow.QueryPlan{}, err
	}
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenant || !validTagProjectionID(tenant) {
		return flow.QueryPlan{}, ErrNoTenant
	}
	return flow.NormalizeQueryPlan(flow.QueryPlan{From: from, To: to, DataSeries: series, GroupBy: []string{"exporter"}}, time.Now())
}

func routingReadFromRow(row Row) (RoutingCaptureRead, error) {
	if row.RoutingCaptureKey == "" {
		return RoutingCaptureRead{}, errRoutingCaptureRow
	}
	if err := validateRoutingCaptureRow(row); err != nil {
		return RoutingCaptureRead{}, err
	}
	raw, _ := hex.DecodeString(row.RawFlowDigest)
	key, _ := hex.DecodeString(row.RoutingCaptureKey)
	result := RoutingCaptureRead{Sender: row.AgentID}
	copy(result.Witness.RawDigest[:], raw)
	copy(result.Ref.Key[:], key)
	result.Ref.CapturedAt = time.Unix(0, row.RoutingCapturedUnixNanos).UTC()
	result.Witness.Input = entity.FlowCaptureInput{Exporter: netip.MustParseAddr(row.Exporter), Source: netip.MustParseAddr(row.SrcAddr), Destination: netip.MustParseAddr(row.DstAddr), Protocol: row.Protocol, Domain: row.ObsDomain}
	return result, nil
}

func sortedRoutingReads(rows map[[32]byte]RoutingCaptureRead) []RoutingCaptureRead {
	result := make([]RoutingCaptureRead, 0, len(rows))
	for _, row := range rows {
		result = append(result, row)
	}
	sort.Slice(result, func(i, j int) bool { return bytes.Compare(result[i].Ref.Key[:], result[j].Ref.Key[:]) < 0 })
	return result
}

// Enumerate the complete window before derived routing filters/grouping. No
// display/page limit truncates metadata; resource refusal returns no prefix.
func (m *Memory) routingCaptureReferences(ctx context.Context, tenant string, from, to time.Time, series string, withTiming bool) ([]RoutingCaptureRead, error) {
	plan, err := routingReferencePlan(ctx, tenant, from, to, series)
	if err != nil {
		return nil, err
	}
	if withTiming && plan.DataSeries == "rollup" {
		return nil, timedFlowCoverageError()
	}
	budget, err := explorerPlanBudget(ctx, m, tenant, m)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	reads := map[[32]byte]RoutingCaptureRead{}
	used := int64(0)
	scanned := 0
	for _, entry := range m.rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.row.TenantID != tenant || entry.row.TS.Before(plan.From) || !entry.row.TS.Before(plan.To) {
			continue
		}
		scanned++
		if scanned > budget.ReadRows || used > min(budget.MemoryBytes, budget.ReadBytes)-4096 {
			return nil, ErrExplorerBudget
		}
		used += 4096
		if err := chargeBatchRead(ctx, tenant, 1, 4096); err != nil {
			return nil, err
		}
		if entry.row.RoutingCaptureKey == "" {
			continue
		}
		read, err := routingReadFromRow(entry.row)
		if err != nil {
			return nil, err
		}
		if withTiming {
			read.Timing = FlowCaptureTiming{Start: entry.row.StartTS.UTC(), End: entry.row.TS.UTC(), Basis: entry.row.ClockBasis}
		}
		if previous, exists := reads[read.Ref.Key]; exists && previous != read {
			return nil, errRoutingCaptureRow
		}
		reads[read.Ref.Key] = read
	}
	return sortedRoutingReads(reads), nil
}

func (c *ClickHouse) routingCaptureReferences(ctx context.Context, tenant string, from, to time.Time, series string, withTiming bool) ([]RoutingCaptureRead, error) {
	plan, err := routingReferencePlan(ctx, tenant, from, to, series)
	if err != nil {
		return nil, err
	}
	budget, err := explorerPlanBudget(ctx, c, tenant, c)
	if err != nil {
		return nil, err
	}
	ctx = withExplorerBudget(ctx, budget)
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	target, err := c.route(ctx, tenant)
	if err != nil {
		return nil, err
	}
	lane, err := c.readLane(target, tenant)
	if err != nil {
		return nil, err
	}
	if !lane.Reader {
		return nil, chclient.ErrReaderRequired
	}
	source, err := c.planSourceFor(ctx, target, lane, tenant, plan)
	if err != nil {
		return nil, err
	}
	if withTiming && source.kind != "raw" {
		return nil, timedFlowCoverageError()
	}
	params := chParams{"tenant": tenant, "from": plan.From.UTC().Format("2006-01-02 15:04:05.999999999"), "to": plan.To.UTC().Format("2006-01-02 15:04:05.999999999")}
	columns := ""
	if withTiming {
		columns = ",toString(toUnixTimestamp64Milli(start_ts)) AS start_ms,toString(toUnixTimestamp64Milli(ts)) AS end_ms,toString(clock_basis) AS clock_basis"
	}
	sql := `SELECT DISTINCT tenant_id,agent_id,exporter,protocol,toString(obs_domain) AS obs_domain,src_addr,dst_addr,raw_flow_digest,routing_capture_key,toString(routing_captured_unix_nanos) AS routing_captured_unix_nanos` + columns + ` FROM ` + source.table + ` FINAL
 WHERE tenant_id={tenant:String} AND ts>={from:DateTime64(9,'UTC')} AND ts<{to:DateTime64(9,'UTC')} AND routing_capture_key!=''`
	settings, err := budget.settings()
	if err != nil {
		return nil, err
	}
	sql += settings
	rows, err := c.explorerQueryRows(ctx, target, lane, tenant, sql, params)
	if err != nil {
		return nil, err
	}
	return decodeRoutingReads(ctx, tenant, rows, budget.MemoryBytes, withTiming)
}

func decodeRoutingReads(ctx context.Context, tenant string, rows []map[string]any, memory int64, withTiming bool) ([]RoutingCaptureRead, error) {
	if memory <= 0 || int64(len(rows)) > memory/4096 {
		return nil, ErrExplorerBudget
	}
	reads := make(map[[32]byte]RoutingCaptureRead, len(rows))
	for _, source := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		domain, domainErr := strconv.ParseUint(chToString(source["obs_domain"]), 10, 32)
		clock, clockErr := strconv.ParseInt(chToString(source["routing_captured_unix_nanos"]), 10, 64)
		row := Row{TenantID: chToString(source["tenant_id"]), AgentID: chToString(source["agent_id"]), Exporter: chToString(source["exporter"]), Protocol: chToString(source["protocol"]), ObsDomain: uint32(domain), SrcAddr: chToString(source["src_addr"]), DstAddr: chToString(source["dst_addr"]), RawFlowDigest: chToString(source["raw_flow_digest"]), RoutingCaptureKey: chToString(source["routing_capture_key"]), RoutingCapturedUnixNanos: clock}
		if domainErr != nil || clockErr != nil || row.TenantID != tenant {
			return nil, errRoutingCaptureRow
		}
		read, err := routingReadFromRow(row)
		if err != nil {
			return nil, err
		}
		if withTiming {
			read.Timing, err = flowCaptureTimingFromStore(source)
			if err != nil {
				return nil, err
			}
		}
		if previous, exists := reads[read.Ref.Key]; exists && previous != read {
			return nil, errRoutingCaptureRow
		}
		reads[read.Ref.Key] = read
	}
	return sortedRoutingReads(reads), nil
}

func flowCaptureTimingFromStore(source map[string]any) (FlowCaptureTiming, error) {
	start, startErr := strconv.ParseInt(chToString(source["start_ms"]), 10, 64)
	end, endErr := strconv.ParseInt(chToString(source["end_ms"]), 10, 64)
	basis, basisErr := strconv.ParseUint(chToString(source["clock_basis"]), 10, 8)
	if startErr != nil || endErr != nil || basisErr != nil {
		return FlowCaptureTiming{}, errRoutingCaptureRow
	}
	clock := FlowCaptureTiming{Start: time.UnixMilli(start).UTC(), End: time.UnixMilli(end).UTC()}
	switch basis {
	case uint64(flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL):
		clock.Basis = flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL
	case uint64(flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_COLLECTOR_SAMPLE):
		clock.Basis = flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_COLLECTOR_SAMPLE
	}
	return clock, nil
}

func timedFlowCoverageError() error {
	return &PlanCoverageError{Reason: "time-based Kubernetes attribution requires retained raw clock provenance", ResolutionSeconds: 1}
}
