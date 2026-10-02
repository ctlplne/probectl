// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/config"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
)

// RTP-02: the carbon consumer once performed NO tenant verification — it read
// each flow's payload tenant_id directly. A single batch naming two tenants (a
// forgery shape no honest single-tenant agent produces) was processed per flow,
// writing bytes into BOTH tenants' ESG accounting. The consumer now verifies
// the batch's tenancy and rejects anything that is not a single, coherent
// tenant, so a tenant named only inside a forged batch gets nothing. This test
// uses only long-standing APIs so it fails on the pre-fix tree and passes on
// the fix.
func TestCarbonRejectsMultiTenantForgedBatch(t *testing.T) {
	eng, on, err := BuildCarbon(&config.Config{CarbonEnabled: true, CarbonGridGCO2E: 400}, intelTestLog())
	if err != nil || !on {
		t.Fatalf("BuildCarbon: %v", err)
	}
	cc := NewCarbonConsumer(nil, eng, intelTestLog())

	raw, err := proto.Marshal(&flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{
		{TenantId: "tenant-a", AgentId: "agent-a", SourceAddress: "10.0.0.1",
			DestinationAddress: "203.0.113.9", Bytes: 1 << 30, EndUnixNano: time.Now().UnixNano()},
		{TenantId: "tenant-victim", AgentId: "agent-a", SourceAddress: "10.0.0.2",
			DestinationAddress: "203.0.113.10", Bytes: 1 << 30, EndUnixNano: time.Now().UnixNano()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := cc.handleLane(context.Background(), bus.Message{Value: raw}, ""); err != nil {
		t.Fatal(err)
	}
	if s := eng.Summary("tenant-victim"); s.TotalBytes != 0 {
		t.Fatalf("carbon stored %d bytes for a tenant named only inside a forged multi-tenant batch", s.TotalBytes)
	}
	if s := eng.Summary("tenant-a"); s.TotalBytes != 0 {
		t.Fatalf("carbon stored %d bytes from a mixed-tenant (forged) batch that must be rejected wholesale", s.TotalBytes)
	}
}
