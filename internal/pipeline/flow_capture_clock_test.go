// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"reflect"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
)

func TestFlowProjectionUsesFrozenFirstProcessingClock(t *testing.T) {
	firstAt := time.Date(2024, 1, 1, 3, 4, 5, 123456789, time.UTC)
	raw := &flowv1.FlowRecord{TenantId: "verified-tenant", AgentId: "source", FlowProtocol: "ipfix", SourceAddress: "203.0.113.1", DestinationAddress: "2001:db8::1", ObservedAtUnixNano: firstAt.Add(24 * time.Hour).UnixNano(), EndUnixNano: firstAt.Add(24 * time.Hour).UnixNano(), StartUnixNano: firstAt.Add(24*time.Hour + time.Minute).UnixNano(), Bytes: ^uint64(0), BytesScaled: ^uint64(0)}
	original := proto.Clone(raw)
	first := rowFromProtoAt(raw, firstAt)
	retry := rowFromProtoAt(raw, firstAt)
	if !first.TS.Equal(firstAt) || !first.StartTS.Equal(firstAt) || !reflect.DeepEqual(first, retry) || !proto.Equal(raw, original) || first.Bytes != ^uint64(0) {
		t.Fatal("frozen first processing clock changed retry projection or original counters")
	}
	raw.EndUnixNano = 0
	raw.StartUnixNano = 0
	if got := rowFromProtoAt(raw, firstAt); !got.TS.Equal(firstAt) || !got.StartTS.Equal(firstAt) {
		t.Fatal("missing exporter clocks lost frozen receive-time fallback")
	}
	raw.EndUnixNano = firstAt.Add(-time.Minute).UnixNano()
	raw.StartUnixNano = raw.EndUnixNano
	if got := rowFromProtoAt(raw, firstAt); !got.TS.Equal(firstAt.Add(-time.Minute)) || !got.StartTS.Equal(got.TS) {
		t.Fatal("frozen processing projection replaced valid original event time")
	}
}

func TestFlowProjectionKeepsOnlyExactClockBasis(t *testing.T) {
	const unknown = flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_UNSPECIFIED
	const interval = flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL
	const sample = flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_COLLECTOR_SAMPLE
	now := time.Date(2026, 1, 1, 5, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name, protocol string
		start, end     time.Time
		claimed, want  flowv1.FlowClockBasis
	}{
		{"legacy interval", "ipfix", now.Add(-time.Second), now, unknown, unknown},
		{"exported interval", "ipfix", now.Add(-time.Second), now, interval, interval},
		{"exported point interval", "ipfix", now, now, interval, interval},
		{"collector sample", "sflow5", now, now, sample, sample},
		{"foreign sample type", "ipfix", now, now, sample, unknown},
		{"foreign interval type", "sflow5", now, now, interval, unknown},
		{"missing start", "ipfix", time.Time{}, now, interval, unknown},
		{"clamped end", "ipfix", now.Add(-time.Second), now.Add(time.Hour), interval, unknown},
		{"repaired start", "ipfix", now.Add(time.Second), now, interval, unknown},
		{"unknown enum", "ipfix", now.Add(-time.Second), now, flowv1.FlowClockBasis(99), unknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := &flowv1.FlowRecord{FlowProtocol: test.protocol, ObservedAtUnixNano: now.UnixNano(), ClockBasis: test.claimed}
			if !test.start.IsZero() {
				raw.StartUnixNano = test.start.UnixNano()
			}
			raw.EndUnixNano = test.end.UnixNano()
			if got := rowFromProtoAt(raw, now).ClockBasis; got != test.want {
				t.Fatal("unexpected stored clock evidence", got, test.want)
			}
		})
	}
}
