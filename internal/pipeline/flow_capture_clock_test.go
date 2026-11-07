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
