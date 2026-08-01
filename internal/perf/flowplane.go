// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package perf

import (
	"context"
	"fmt"
	"os"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/pipeline"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

// Flow-plane drive (Sprint 17, SCALE-002 drive-set gap): the scale gate drove
// the RESULTS plane only; the FLOW plane — the volume plane where scale
// actually bites — was missing from the drive set. This drives tier-scaled
// NetFlow batches through the PRODUCTION FlowConsumer (verify + fairness +
// enrich seams identical to runtime) into the flow store and asserts
// completeness + throughput.
//
// In-process gate: memory bus + memory flow store (the same honesty contract
// as RunScaleGate — it proves the pipeline shape; the L/XL/XXL run drives real
// Kafka + ClickHouse via PROBECTL_FLOWSTORE_URL, runbook in
// docs/scale-gate.md).

// FlowPlaneReport is the drive outcome.
type FlowPlaneReport struct {
	Tier       Tier
	AtCIScale  bool
	Records    int
	Stored     int
	Rejected   uint64
	Elapsed    time.Duration
	RecordsSec float64
}

// String renders the operator row.
func (r FlowPlaneReport) String() string {
	return fmt.Sprintf("flow-plane %s (ci=%t): %d records → %d stored, %d rejected, %.0f records/s",
		r.Tier, r.AtCIScale, r.Records, r.Stored, r.Rejected, r.RecordsSec)
}

// DriveFlowPlane pushes the tier's flow volume (records ≈ 4× the tier's
// result count — flow outvolumes results in every real deployment) through
// the production consumer and verifies storage completeness.
func DriveFlowPlane(ctx context.Context, tier Tier, scale float64) (FlowPlaneReport, error) {
	profile, err := ProfileFor(tier, scale)
	if err != nil {
		return FlowPlaneReport{}, err
	}
	records := profile.Ingest.TotalResults() * 4
	if records < 200 {
		records = 200 // materiality floor (D12): never a vacuous drive
	}
	batchSize := flowPlaneBatchSize(scale)
	rep := FlowPlaneReport{Tier: tier, AtCIScale: scale < 1, Records: records}

	b := bus.NewMemory()
	st := flowstore.NewMemoryWithLimit(flowPlaneStoreLimit(records, scale))
	consumer := pipeline.NewFlowConsumer(b, st, nil, logging.New(os.Stderr, "error", "json"))
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() { _ = consumer.Run(cctx); close(done) }()
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	tenants := profile.Ingest.Tenants
	if tenants < 1 {
		tenants = 1
	}
	base := time.Now().Add(-time.Duration(records+1) * time.Millisecond)
	for sent := 0; sent < records; {
		n := batchSize
		if records-sent < n {
			n = records - sent
		}
		tenant := fmt.Sprintf("fp-tenant-%03d", sent%tenants)
		batch := &flowv1.FlowBatch{Flows: make([]*flowv1.FlowRecord, n)}
		for i := 0; i < n; i++ {
			seq := sent + i
			end := base.Add(time.Duration(seq) * time.Millisecond)
			bytes := uint64(1500 + seq%900)
			packets := uint64(3 + seq%7)
			batch.Flows[i] = &flowv1.FlowRecord{
				TenantId: tenant, AgentId: "fp-agent",
				ExporterAddress:    fmt.Sprintf("192.0.2.%d", 1+seq%250),
				ObservationDomain:  uint32(1 + seq%4096),
				FlowProtocol:       "netflow9",
				ObservedAtUnixNano: end.Add(time.Millisecond).UnixNano(),
				StartUnixNano:      end.Add(-time.Second).UnixNano(),
				EndUnixNano:        end.UnixNano(),
				SourceAddress:      fmt.Sprintf("10.%d.%d.%d", seq/65536%256, seq/256%256, seq%256),
				DestinationAddress: "203.0.113.9", SourcePort: 40000, DestinationPort: 443,
				NetworkTransport: "tcp", NetworkType: "ipv4",
				InputInterface: uint32(10 + seq%64), OutputInterface: uint32(20 + seq%64),
				Bytes: bytes, Packets: packets, SamplingRate: 1, BytesScaled: bytes, PacketsScaled: packets,
			}
		}
		payload, merr := proto.Marshal(batch)
		if merr != nil {
			return rep, merr
		}
		if perr := b.Publish(cctx, bus.FlowEventsTopic, bus.TenantKey(tenant, "fp-agent"), payload); perr != nil {
			return rep, fmt.Errorf("perf: flow publish: %w", perr)
		}
		sent += n
	}

	// Settle: every record visible in the store (completeness, the U-019 bar).
	deadline := time.Now().Add(2 * time.Minute)
	for st.Len() < records {
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	cancel()
	<-done

	rep.Stored = st.Len()
	rep.Rejected = consumer.RejectedBatches()
	rep.Elapsed = time.Since(start)
	if rep.Elapsed > 0 {
		rep.RecordsSec = float64(rep.Stored) / rep.Elapsed.Seconds()
	}
	if rep.Stored < records {
		return rep, fmt.Errorf("perf: flow plane INCOMPLETE: %d/%d records stored (rejected=%d)",
			rep.Stored, records, rep.Rejected)
	}
	return rep, nil
}

func flowPlaneBatchSize(scale float64) int {
	if scale < 1 {
		return 50
	}
	return 1000
}

func flowPlaneStoreLimit(records int, scale float64) int {
	if scale < 1 {
		return 1 << 20
	}
	return records
}
