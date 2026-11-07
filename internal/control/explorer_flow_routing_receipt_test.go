// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestFlowRoutingValidityKeepsCompleteOriginalSelectorsAndAdmission(t *testing.T) {
	const count = 50_000
	const tenant = "11111111-1111-4111-8111-111111111111"
	const foreign = "22222222-2222-4222-8222-222222222222"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	memory := flowstore.DefaultExplorerBudget().MemoryBytes / 4
	input := entity.FlowCaptureInput{Exporter: netip.MustParseAddr("192.0.2.1"), Source: netip.MustParseAddr("203.0.113.1"), Destination: netip.MustParseAddr("2001:db8::1"), Protocol: "ipfix", Domain: ^uint32(0)}
	reads := make([]flowstore.RoutingCaptureRead, count)
	for i := range reads {
		read := flowstore.RoutingCaptureRead{Sender: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Witness: entity.FlowCaptureWitness{Input: input}}
		binary.BigEndian.PutUint64(read.Witness.RawDigest[:8], uint64(i+1))
		key, err := entity.FlowCaptureKey(tenant, read.Sender, read.Witness.RawDigest, input)
		if err != nil {
			t.Fatal(err)
		}
		read.Ref = entity.FlowCaptureReference{Key: key, CapturedAt: time.Unix(1700000000, 987654321+int64(i)).UTC()}
		reads[i] = read
	}
	wire, err := encodeFlowRoutingValidity(&flowstore.RoutingQueryProof{Digest: strings.Repeat("a", 64), InputDigest: strings.Repeat("b", 64), Captures: reads})
	if err != nil {
		t.Fatal(err)
	}
	// Both comparison periods retain their complete, independently checked
	// original selection. This is a codec/admission model, not a source grant.
	proof := flowSnapshotValidity{Inputs: []flowstore.SnapshotInputs{{Fields: []string{"src_bgp_as_paths"}}, {Fields: []string{"dst_bgp_origin_as"}}}, Routing: []*flowRoutingSnapshotValidity{wire, wire}}
	body, err := json.Marshal(proof)
	if err != nil || len(body) <= 8192 || !bytes.Contains(body, []byte(`"at":"1700000000987654321"`)) {
		t.Fatal("complete routing receipt lost its full first clock or intended population", err)
	}
	if err := admitFlowSnapshotValidity(ctx, body, flowsnapshot.DefaultConfig().SourceValidityBytes(), memory); err != nil {
		t.Fatal("complete original routing selectors still use the former receipt ceiling", len(body), err)
	}
	var restored flowSnapshotValidity
	if err := json.Unmarshal(body, &restored); err != nil || len(restored.Routing) != 2 {
		t.Fatal("complete comparison routing receipt failed to decode", err)
	}
	for _, period := range restored.Routing {
		decoded, err := decodeFlowRoutingValidity(ctx, tenant, period, memory)
		if err != nil || !reflect.DeepEqual(decoded, reads) {
			t.Fatal("routing receipt truncated, restamped or changed an original selector", err)
		}
	}
	changed := *wire
	changed.Captures = slices.Clone(wire.Captures)
	last := &changed.Captures[len(changed.Captures)-1]
	last.Raw = "f" + last.Raw[1:]
	if prefix, err := decodeFlowRoutingValidity(ctx, tenant, &changed, memory); !errors.Is(err, flowstore.ErrSnapshotInputs) || prefix != nil {
		t.Fatal("late changed routing witness disclosed a partial receipt", err)
	}
	if prefix, err := decodeFlowRoutingValidity(tenancy.WithTenant(t.Context(), tenancy.ID(foreign)), foreign, wire, memory); !errors.Is(err, flowstore.ErrSnapshotInputs) || prefix != nil {
		t.Fatal("routing receipt selected another tenant's original captures", err)
	}
	if prefix, err := decodeFlowRoutingValidity(ctx, tenant, wire, 4096); !errors.Is(err, flowstore.ErrSnapshotInputs) || prefix != nil {
		t.Fatal("routing receipt returned an unadmitted selector prefix", err)
	}
	if err := admitFlowSnapshotValidity(ctx, body, int64(len(body)-1), memory); !errors.Is(err, flowstore.ErrExplorerBudget) {
		t.Fatal("routing receipt ignored configured whole-byte admission", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := admitFlowSnapshotValidity(canceled, body, int64(len(body)), memory); !errors.Is(err, context.Canceled) {
		t.Fatal("routing receipt admission ignored cancellation", err)
	}
	t.Logf("simulation: complete two-period receipt, %d original selectors per period, %d encoded bytes; no source authority or database proof", count, len(body))
}

func TestRoutingSnapshotRefusesMissingForeignAndExtraneousAuthority(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	source := &flowSnapshotSource{server: &Server{}}
	scope := flowsnapshot.Scope{TenantID: tenant, Owner: "owner"}
	input := flowstore.SnapshotInputs{Fields: []string{"src_bgp_as_paths"}}
	ctx := auth.WithPrincipal(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), &auth.Principal{TenantID: tenant, UserID: "owner"})
	for _, proof := range []flowSnapshotValidity{
		{Inputs: []flowstore.SnapshotInputs{input}},
		{Inputs: []flowstore.SnapshotInputs{input}, Routing: []*flowRoutingSnapshotValidity{nil}},
		{Inputs: []flowstore.SnapshotInputs{{Fields: []string{"protocol"}}}, Routing: []*flowRoutingSnapshotValidity{{Digest: strings.Repeat("a", 64)}}},
	} {
		if err := source.validateRoutingAuthorization(ctx, scope, proof); err == nil {
			t.Fatal("routing snapshot invented an absent or unrelated source grant")
		}
	}
	wrongOwner := scope
	wrongOwner.Owner = "another-owner"
	proof := flowSnapshotValidity{Inputs: []flowstore.SnapshotInputs{input}, Routing: []*flowRoutingSnapshotValidity{{Digest: strings.Repeat("a", 64), InputDigest: strings.Repeat("b", 64)}}}
	if err := source.validateRoutingAuthorization(ctx, wrongOwner, proof); err == nil {
		t.Fatal("routing snapshot replaced the current credential owner")
	}
	if err := source.validateRoutingAuthorization(t.Context(), scope, flowSnapshotValidity{Inputs: []flowstore.SnapshotInputs{{Fields: []string{"protocol"}}}}); err != nil {
		t.Fatal("ordinary frozen query acquired a routing prerequisite", err)
	}
}
