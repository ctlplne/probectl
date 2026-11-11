// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/entity"
	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type counterWitnessFixture struct {
	calls   int
	refuse  bool
	foreign bool
}

func (w *counterWitnessFixture) PublishUnderWitness(ctx context.Context, sender string, digest [32]byte, input entity.CounterCaptureInput, _ int, publish func(context.Context, store.DeviceCounterCapture) error) error {
	w.calls++
	if w.refuse {
		return store.ErrCounterCaptureUnavailable
	}
	tenant, _ := tenancy.FromContext(ctx)
	key, err := entity.CounterCaptureKey(tenant.String(), sender, digest, input)
	if err != nil {
		return err
	}
	capture := store.DeviceCounterCapture{CounterCaptureReference: entity.CounterCaptureReference{Key: key, CapturedAt: input.PollCompletedAt.Add(time.Second)}, Scope: entity.Scope{TenantID: tenant.String(), ContextID: "22222222-2222-4222-8222-222222222222"}, DeviceID: "33333333-3333-4333-8333-333333333333", SenderSerial: "certified", SourceAssignedAt: input.PollStartedAt.Add(-time.Hour), AgentAssignedAt: input.PollStartedAt.Add(-time.Hour)}
	if w.foreign {
		capture.Scope.TenantID = "77777777-7777-4777-8777-777777777777"
	}
	return publish(ctx, capture)
}

func counterConsumerMessage(t *testing.T, tenant string) bus.Message {
	t.Helper()
	at := time.Unix(1794000000, 123456789)
	zero := uint32(0)
	batch := &devicev1.DeviceMetricBatch{Metrics: []*devicev1.DeviceMetric{
		{TenantId: tenant, AgentId: "same-agent", DeviceAddress: "192.0.2.1", Source: device.SourceSNMP, IfIndex: 7, Name: device.MetricIfInOctets, TimeUnixNano: at.UnixNano(), ExactCounter: &devicev1.DeviceCounter{Value: ^uint64(0), Width: 64, UptimeTicks: &zero, DiscontinuityTicks: &zero, PollStartedAtUnixNano: at.UnixNano(), PollCompletedAtUnixNano: at.Add(time.Second).UnixNano()}},
	}}
	raw, err := proto.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	return bus.Message{Topic: bus.DeviceCountersTopic, Key: bus.TenantKey(tenant, "same-agent"), Value: raw}
}

func TestDeviceCounterConsumerKeepsCertifiedWholeExactPollsAndTwoTenants(t *testing.T) {
	history := flowstore.NewMemory()
	witness := &counterWitnessFixture{}
	budget := flowstore.CounterBudget{MemoryBytes: 8 << 20, WorkUnits: 8 << 20, Timeout: time.Minute}
	consumer := NewDeviceCounterConsumer(nil, history, witness, budget, 90, nil).WithTenantBinding(plainBinding{})
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "66666666-6666-4666-8666-666666666666"} {
		message := counterConsumerMessage(t, tenant)
		for range 2 {
			if err := consumer.handleLane(t.Context(), message, tenant); err != nil {
				t.Fatal(err)
			}
		}
		batch, err := device.ParseCounterBatch(t.Context(), tenant, message.Value, 8<<20, 8<<20)
		if err != nil {
			t.Fatal(err)
		}
		query := flowstore.CounterQuery{TenantID: tenant, From: batch.Input.PollStartedAt.Add(-time.Minute), To: batch.Input.PollCompletedAt.Add(time.Minute), Budget: budget, Sources: []flowstore.CounterSelector{{CounterSource: flowstore.CounterSource{ContextID: "22222222-2222-4222-8222-222222222222", DeviceID: "33333333-3333-4333-8333-333333333333", AgentID: batch.Sender, SourceRef: batch.Input.ConfiguredTarget, SourceAssignedAt: batch.Input.PollStartedAt.Add(-time.Hour), AgentAssignedAt: batch.Input.PollStartedAt.Add(-time.Hour)}, IfIndexes: []uint32{7}}}}
		rows, err := history.CounterPoints(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), query)
		if err != nil || len(rows) != 1 || rows[0].Value != ^uint64(0) || rows[0].SenderSerial != "certified" || rows[0].RawDigest != batch.Digest || !rows[0].UptimeKnown || rows[0].UptimeTicks != 0 || !rows[0].PollStartedAt.Equal(batch.Input.PollStartedAt) {
			t.Fatal("history lost original values, certified provenance, retry identity or tenant", rows, err)
		}
	}
	if witness.calls != 4 || consumer.ledger.stats().Stored != 4 {
		t.Fatal("a complete poll bypassed its current witness", witness.calls, consumer.ledger.stats())
	}
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "66666666-6666-4666-8666-666666666666"} {
		if n, err := history.ExportCounterTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), tenant, io.Discard); err != nil || n != 1 {
			t.Fatal("later sibling publication changed an earlier tenant", n, err)
		}
	}
}

func TestDeviceCounterConsumerRefusesForeignLaneMissingWitnessAndKeepsBudgetRetry(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	for _, mode := range []string{"foreign-lane", "missing-witness", "foreign-witness", "resource"} {
		t.Run(mode, func(t *testing.T) {
			history := flowstore.NewMemory()
			witness := &counterWitnessFixture{refuse: mode == "missing-witness", foreign: mode == "foreign-witness"}
			budget := flowstore.CounterBudget{MemoryBytes: 8 << 20, WorkUnits: 8 << 20, Timeout: time.Minute}
			if mode == "resource" {
				budget.MemoryBytes = 64
			}
			consumer := NewDeviceCounterConsumer(nil, history, witness, budget, 90, nil).WithTenantBinding(plainBinding{})
			lane := tenant
			if mode == "foreign-lane" {
				lane = "66666666-6666-4666-8666-666666666666"
			}
			err := consumer.handleLane(t.Context(), counterConsumerMessage(t, tenant), lane)
			if mode == "resource" && !errors.Is(err, flowstore.ErrCounterHistoryBudget) {
				t.Fatal("resource refusal acknowledged and lost a complete retryable poll", err)
			}
			if consumer.ledger.stats().Stored != 0 {
				t.Fatal("unwitnessed or foreign input reached stored success")
			}
			if (mode == "foreign-lane" || mode == "resource") && witness.calls != 0 {
				t.Fatal("rejected lane or resources reached the witness store")
			}
			if n, err := history.ExportCounterTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), tenant, io.Discard); err != nil || n != 0 {
				t.Fatal("rejected input left history", n, err)
			}
		})
	}
}
