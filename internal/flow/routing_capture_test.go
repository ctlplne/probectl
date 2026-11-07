// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ctlplne/probectl/internal/entity"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
)

func captureRecordForTest() *flowv1.FlowRecord {
	return &flowv1.FlowRecord{TenantId: "11111111-1111-4111-8111-111111111111", AgentId: "sender-a", ExporterAddress: "192.0.2.1", SourceAddress: "203.0.113.1", DestinationAddress: "2001:db8::1", FlowProtocol: "ipfix", ObservationDomain: ^uint32(0), ObservedAtUnixNano: 1, EndUnixNano: 9000000000000000000, Bytes: ^uint64(0), SamplingRate: 1000, SourceAsName: "完整 source \"name\""}
}

func TestRoutingCaptureWitnessBindsEveryOriginalFieldAndUnknownWireData(t *testing.T) {
	base := captureRecordForTest()
	original := proto.Clone(base)
	first, input, err := RoutingCaptureWitness(t.Context(), base, 128<<20, 128<<20)
	if err != nil || first == ([32]byte{}) || input.Domain != ^uint32(0) {
		t.Fatal("complete original flow refused", err)
	}
	// Walk the actual descriptor: adding a new wire field cannot silently escape
	// the identity proof. Include device fields, raw counters and enrichment text.
	fields := base.ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		field := fields.Get(i)
		t.Run(string(field.Name()), func(t *testing.T) {
			changed := proto.Clone(base).(*flowv1.FlowRecord)
			current := changed.ProtoReflect().Get(field)
			var value protoreflect.Value
			switch field.Kind() {
			case protoreflect.StringKind:
				text := current.String() + " changed"
				switch field.Name() {
				case "agent_id":
					text = "sender-b"
				case "tenant_id":
					text = "22222222-2222-4222-8222-222222222222"
				case "exporter_address":
					text = "192.0.2.2"
				case "source_address":
					text = "203.0.113.2"
				case "destination_address":
					text = "2001:db8::2"
				case "flow_protocol":
					text = "netflow5"
				}
				value = protoreflect.ValueOfString(text)
			case protoreflect.Uint32Kind:
				value = protoreflect.ValueOfUint32(uint32(current.Uint()) ^ 1)
			case protoreflect.Uint64Kind:
				value = protoreflect.ValueOfUint64(current.Uint() ^ 1)
			case protoreflect.Int64Kind:
				value = protoreflect.ValueOfInt64(current.Int() ^ 1)
			default:
				t.Fatalf("new flow field needs identity mutation coverage: %s", field.Kind())
			}
			changed.ProtoReflect().Set(field, value)
			digest, _, err := RoutingCaptureWitness(t.Context(), changed, 128<<20, 128<<20)
			if err != nil || digest == first {
				t.Fatal("original flow field escaped capture identity", field.Name(), err)
			}
		})
	}
	unknown := proto.Clone(base).(*flowv1.FlowRecord)
	wire := protowire.AppendTag(nil, 1000, protowire.BytesType)
	wire = protowire.AppendBytes(wire, []byte("future complete source attribute"))
	unknown.ProtoReflect().SetUnknown(wire)
	unknownDigest, _, err := RoutingCaptureWitness(t.Context(), unknown, 128<<20, 128<<20)
	if err != nil || unknownDigest == first {
		t.Fatal("unknown source field escaped complete raw identity", err)
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(unknown)
	if err != nil {
		t.Fatal(err)
	}
	var decoded flowv1.FlowRecord
	if err := proto.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if got, _, err := RoutingCaptureWitness(t.Context(), &decoded, 128<<20, 128<<20); err != nil || got != unknownDigest {
		t.Fatal("producer/bus decode disagreed about immutable record identity", err)
	}
	if !proto.Equal(base, original) {
		t.Fatal("capture identity mutated original flow")
	}
	if got, tuple, err := RoutingCaptureWitness(t.Context(), base, 128<<20, 128<<20); err != nil || got != first || !reflect.DeepEqual(tuple, input) {
		t.Fatal("time-independent retry changed raw capture identity", err)
	}
}

func TestRoutingCaptureWitnessPreservesCompleteValuesAndRefusesPartialAdmission(t *testing.T) {
	base := captureRecordForTest()
	base.SourceAsName = strings.Repeat("完整 metadata ", 100000)
	first, _, err := RoutingCaptureWitness(t.Context(), base, 128<<20, 128<<20)
	if err != nil {
		t.Fatal("complete large original value was truncated or refused", err)
	}
	changed := proto.Clone(base).(*flowv1.FlowRecord)
	changed.SourceAsName += "last byte"
	if got, _, err := RoutingCaptureWitness(t.Context(), changed, 128<<20, 128<<20); err != nil || got == first {
		t.Fatal("capture digest truncated complete source value", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		ctx          context.Context
		record       *flowv1.FlowRecord
		memory, work int64
		want         error
	}{
		{t.Context(), base, 1, 128 << 20, ErrRoutingCaptureAdmission},
		{t.Context(), base, 128 << 20, 1, ErrRoutingCaptureAdmission},
		{ctx, base, 128 << 20, 128 << 20, context.Canceled},
		{t.Context(), nil, 128 << 20, 128 << 20, entity.ErrInvalidClaim},
	} {
		got, input, err := RoutingCaptureWitness(tc.ctx, tc.record, tc.memory, tc.work)
		if !errors.Is(err, tc.want) || got != ([32]byte{}) || input != (entity.FlowCaptureInput{}) {
			t.Fatal("refused capture exposed a partial witness", err)
		}
	}
	for _, mutate := range []func(*flowv1.FlowRecord){
		func(v *flowv1.FlowRecord) { v.TenantId = "foreign" },
		func(v *flowv1.FlowRecord) { v.AgentId = "" },
		func(v *flowv1.FlowRecord) { v.ExporterAddress = "224.0.0.1" },
		func(v *flowv1.FlowRecord) { v.SourceAddress = "fe80::1%other" },
		func(v *flowv1.FlowRecord) { v.DestinationAddress = "invalid" },
		func(v *flowv1.FlowRecord) { v.FlowProtocol = "unknown" },
	} {
		changed := captureRecordForTest()
		mutate(changed)
		if got, input, err := RoutingCaptureWitness(t.Context(), changed, 128<<20, 128<<20); err == nil || got != ([32]byte{}) || input != (entity.FlowCaptureInput{}) {
			t.Fatal("malformed source created partial capture identity", err)
		}
	}
}

// A fingerprint must preserve raw bytes even before a transport has corrected
// payload identity. Its existence is never a canonical routing grant.
func TestOriginalFlowDigestPreservesUntrustedAndCloudPayloadWithoutAuthority(t *testing.T) {
	raw := captureRecordForTest()
	raw.TenantId = "untrusted-payload-tenant"
	raw.AgentId = "untrusted-payload-sender"
	raw.FlowProtocol = ProtoAWSVPCFlowLogs
	first, err := OriginalFlowDigest(t.Context(), raw, 128<<20, 128<<20)
	if err != nil || first == ([32]byte{}) {
		t.Fatal("complete raw record lost its source-neutral fingerprint", err)
	}
	if digest, input, err := RoutingCaptureWitness(t.Context(), raw, 128<<20, 128<<20); err == nil || digest != ([32]byte{}) || input != (entity.FlowCaptureInput{}) {
		t.Fatal("raw fingerprint granted routing authority to an untrusted payload", err)
	}
	changed := proto.Clone(raw).(*flowv1.FlowRecord)
	changed.TenantId = "different-untrusted-payload"
	if got, err := OriginalFlowDigest(t.Context(), changed, 128<<20, 128<<20); err != nil || got == first {
		t.Fatal("raw fingerprint silently normalized untrusted original identity", err)
	}
}
