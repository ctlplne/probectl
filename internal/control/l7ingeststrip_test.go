// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	ebpfv1 "github.com/ctlplne/probectl/internal/gen/probectl/ebpf/v1"
	"github.com/ctlplne/probectl/internal/metrics"
)

type fakeFloors struct {
	floors map[string]string
	err    error
	reads  int
}

func (f *fakeFloors) L7CaptureFloor(_ context.Context, tenant string, regulated bool) (string, error) {
	f.reads++
	if f.err != nil {
		return "", f.err
	}
	mode := f.floors[tenant]
	if mode == "" {
		mode = "metadata"
	}
	if regulated && (mode == "headers" || mode == "full") {
		mode = "metadata"
	}
	return mode, nil
}

func rawCall(tenant string) *ebpfv1.L7Call {
	return &ebpfv1.L7Call{
		TenantId: tenant, AgentId: "a1", Source: "portal", Destination: "records", DestinationPort: 443,
		Protocol: "http1", Method: "POST", Resource: "/contracts/W56HZV-23-C-0123/drawings?sig=QUERYSECRET", Status: "201",
	}
}

func TestL7IngestStripAppliesEachTenantsFloor(t *testing.T) {
	floors := &fakeFloors{floors: map[string]string{"t-headers": "headers"}}
	st := newL7IngestStrip(floors, false, nil)
	batch := &ebpfv1.FlowBatch{L7Calls: []*ebpfv1.L7Call{rawCall("t-meta"), rawCall("t-headers"), rawCall("t-meta")}}
	st.Apply(context.Background(), batch)

	if got := batch.L7Calls[0].GetResource(); got != "/contracts/{id}/drawings" {
		t.Fatalf("metadata tenant route = %q", got)
	}
	if got := batch.L7Calls[1].GetResource(); got != "/contracts/W56HZV-23-C-0123/drawings" {
		t.Fatalf("headers opt-in route = %q (literal segments, never the query)", got)
	}
	if floors.reads != 2 {
		t.Fatalf("floor reads = %d, want one per tenant (cached)", floors.reads)
	}
	counts := st.Counts()
	if counts["query"] != 3 || counts["identifier_segment"] != 2 {
		t.Fatalf("strip counts = %v", counts)
	}
}

func TestL7IngestStripRegulatedAndFailClosed(t *testing.T) {
	regulated := newL7IngestStrip(&fakeFloors{floors: map[string]string{"t": "headers"}}, true, nil)
	b := &ebpfv1.FlowBatch{L7Calls: []*ebpfv1.L7Call{rawCall("t")}}
	regulated.Apply(context.Background(), b)
	if got := b.L7Calls[0].GetResource(); got != "/contracts/{id}/drawings" {
		t.Fatalf("regulated profile let a headers row through: %q", got)
	}

	broken := newL7IngestStrip(&fakeFloors{err: errors.New("db down")}, false, nil)
	b = &ebpfv1.FlowBatch{L7Calls: []*ebpfv1.L7Call{rawCall("t")}}
	broken.Apply(context.Background(), b)
	if got := b.L7Calls[0].GetResource(); got != "/contracts/{id}/drawings" {
		t.Fatalf("an unreadable floor did not fail closed to metadata: %q", got)
	}

	// A consumer wired without a strip still strips to metadata.
	var unwired *L7IngestStrip
	b = &ebpfv1.FlowBatch{L7Calls: []*ebpfv1.L7Call{rawCall("t")}}
	unwired.ApplyUncounted(context.Background(), b)
	if got := b.L7Calls[0].GetResource(); got != "/contracts/{id}/drawings" {
		t.Fatalf("unwired consumer did not strip: %q", got)
	}
}

// Fields the schema does not know are where a newer or forged producer would
// carry header values or body bytes; the strip drops them from every message.
func TestL7IngestStripDropsUnknownFields(t *testing.T) {
	call := rawCall("t")
	raw, err := proto.Marshal(&ebpfv1.FlowBatch{L7Calls: []*ebpfv1.L7Call{call}, Flows: []*ebpfv1.Flow{{TenantId: "t", AgentId: "a1"}}})
	if err != nil {
		t.Fatal(err)
	}
	// Append unknown field 99 (bytes) carrying a body to the batch, and splice
	// another into the L7 call by re-encoding it with an extra field.
	body := []byte(`{"ssn":"BODYSECRET"}`)
	smuggled := protowire.AppendBytes(protowire.AppendTag(nil, 99, protowire.BytesType), body)
	callRaw, _ := proto.Marshal(call)
	callRaw = append(callRaw, protowire.AppendBytes(protowire.AppendTag(nil, 98, protowire.BytesType), []byte("Authorization: Bearer CREDSECRET"))...)
	raw = append(raw, smuggled...)
	raw = append(raw, protowire.AppendBytes(protowire.AppendTag(nil, 3, protowire.BytesType), callRaw)...)

	reg := metrics.New("test", "test")
	st := newL7IngestStrip(nil, false, nil).WithMetrics(reg)
	batch, err := decodeEBPFBatch(context.Background(), st, bus.Message{Value: raw}, "", true)
	if err != nil {
		t.Fatal(err)
	}
	out, err := proto.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"BODYSECRET", "CREDSECRET", "QUERYSECRET", "W56HZV-23-C-0123"} {
		if bytes.Contains(out, []byte(leak)) {
			t.Fatalf("ingest output still carries %q", leak)
		}
	}
	if st.Counts()[stripUnknownField] < 2 {
		t.Fatalf("unknown-field strips not counted: %v", st.Counts())
	}
}

// The door stamps the lane tenant BEFORE it strips, so the floor that applies
// is the lane tenant's, never a payload claim.
func TestL7IngestDoorUsesTheLaneTenantsFloor(t *testing.T) {
	floors := &fakeFloors{floors: map[string]string{"attacker": "full"}}
	st := newL7IngestStrip(floors, false, nil)
	raw, _ := proto.Marshal(&ebpfv1.FlowBatch{L7Calls: []*ebpfv1.L7Call{rawCall("attacker")}})
	batch, err := decodeEBPFBatch(context.Background(), st, bus.Message{Value: raw}, "victim", false)
	if err != nil {
		t.Fatal(err)
	}
	if c := batch.L7Calls[0]; c.GetTenantId() != "victim" || c.GetResource() != "/contracts/{id}/drawings" {
		t.Fatalf("door applied the payload tenant's floor: %+v", c)
	}
}
