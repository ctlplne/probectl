// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package otelstore

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// httpObservationLimit includes a sentinel row. Reaching that row means the
// window cannot be used as evidence. This limit is independent of trace search.
const httpObservationLimit = 16_384

// ReadHTTPObservations reads an exact service and local TCP socket window.
// HTTP authority may come from a request header, so it provides no socket
// identity. A nil result with a nil error means no complete bounded projection.
func ReadHTTPObservations(ctx context.Context, store Store, tenant string, q SpanQuery) ([]Span, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || tenant == "" || tenant != bound.String() {
		return nil, ErrNoTenant
	}
	address, port, err := q.httpServerParams()
	if err != nil {
		return nil, err
	}
	if address == "" || q.TraceID != "" || q.Until.Sub(q.Since) > 5*time.Minute {
		return nil, nil
	}
	var rows []Span
	switch reader := UnderlyingStore(store).(type) {
	case *ClickHouse:
		rows, err = reader.readHTTPObservations(ctx, tenant, q, address, port)
	case *Memory:
		rows, err = reader.readHTTPObservations(ctx, tenant, q, address, port)
	default:
		return nil, nil
	}
	if err != nil || len(rows) >= httpObservationLimit {
		return nil, err
	}
	return rows, ctx.Err()
}

func (c *ClickHouse) readHTTPObservations(ctx context.Context, tenant string, q SpanQuery, address, port string) ([]Span, error) {
	target, err := c.route(ctx, tenant)
	if err != nil {
		return nil, err
	}
	table, err := qualify(target, spansTable)
	if err != nil {
		return nil, err
	}
	sql := `SELECT tenant_id, service, trace_id, span_id,
  toString(toUnixTimestamp64Micro(start)) AS start_us, toString(duration_ns) AS duration_ns, status_code,
  JSONExtractString(attrs, 'http.response.status_code') AS http_status
FROM ` + table + ` FINAL
WHERE tenant_id = {tenant:String} AND service = {svc:String} AND kind = 'server'
  AND start >= fromUnixTimestamp64Micro({since:Int64}) AND start < fromUnixTimestamp64Micro({until:Int64})
  AND JSONExtractString(attrs, 'network.local.address') = {http_addr:String}
  AND JSONExtractString(attrs, 'network.local.port') = {http_port:String}
  AND JSONExtractString(attrs, 'network.transport') = 'tcp'
LIMIT {lim:UInt32}
SETTINGS max_rows_to_read = 262144, read_overflow_mode = 'throw'`
	raw, err := c.queryScoped(ctx, target, tenant, sql, chParams{
		"tenant": tenant, "svc": q.Service, "http_addr": address, "http_port": port,
		"since": httpObservationClock(q.Since), "until": httpObservationClock(q.Until),
		"lim": strconv.Itoa(httpObservationLimit),
	})
	if err != nil || len(raw) >= httpObservationLimit {
		return nil, err
	}
	out := make([]Span, 0, len(raw))
	for _, row := range raw {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if str(row["tenant_id"]) != tenant || str(row["service"]) != q.Service {
			return nil, ErrNoTenant
		}
		startUS, startErr := strconv.ParseInt(str(row["start_us"]), 10, 64)
		durationNS, durationErr := strconv.ParseInt(str(row["duration_ns"]), 10, 64)
		start := time.UnixMicro(startUS).UTC()
		if startErr != nil || durationErr != nil || start.Before(q.Since) || !start.Before(q.Until) {
			return nil, errors.New("otelstore: invalid original HTTP observation clock or duration")
		}
		out = append(out, Span{TenantID: tenant, Service: q.Service, Kind: "server", TraceID: str(row["trace_id"]),
			SpanID: str(row["span_id"]), Start: start,
			Duration: time.Duration(durationNS), StatusCode: str(row["status_code"]),
			Attrs: httpObservationAttributes(address, port, str(row["http_status"]))})
	}
	return out, nil
}

// ClickHouse retains whole microseconds. The ceiling preserves both comparisons
// of the half-open interval for clocks with a sub-microsecond component.
func httpObservationClock(value time.Time) string {
	microsecond := value.Truncate(time.Microsecond)
	if microsecond.Before(value) {
		microsecond = microsecond.Add(time.Microsecond)
	}
	return strconv.FormatInt(microsecond.UnixMicro(), 10)
}

func (m *Memory) readHTTPObservations(ctx context.Context, tenant string, q SpanQuery, address, port string) ([]Span, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// The tenant ring can retain some rows from a window after dropping
	// others. A partially retained window cannot qualify a flash crowd.
	if evicted := m.spanEvictedThrough[tenant]; !evicted.IsZero() && !evicted.Before(q.Since) {
		return nil, nil
	}
	var out []Span
	for _, span := range m.spans[tenant] {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if span.Service != q.Service || span.Kind != "server" || span.Start.Before(q.Since) || !span.Start.Before(q.Until) ||
			span.Attrs["network.local.address"] != address || span.Attrs["network.local.port"] != port || span.Attrs["network.transport"] != "tcp" {
			continue
		}
		out = append(out, Span{TenantID: span.TenantID, Service: span.Service, Kind: span.Kind, TraceID: span.TraceID,
			SpanID: span.SpanID, Start: span.Start, Duration: span.Duration, StatusCode: span.StatusCode,
			Attrs: httpObservationAttributes(address, port, span.Attrs["http.response.status_code"])})
		if len(out) == httpObservationLimit {
			break
		}
	}
	return out, nil
}

func httpObservationAttributes(address, port, status string) map[string]string {
	return map[string]string{"network.local.address": address, "network.local.port": port,
		"network.transport": "tcp", "http.response.status_code": status}
}
