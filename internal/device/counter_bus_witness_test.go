// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
)

func TestCounterBusRequiresMatchingWholeWitnessBeforePublishing(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	batch := counterBatchFixture(tenant)
	metric := Metric{TenantID: tenant, AgentID: "same-agent", Device: batch.Metrics[0].DeviceAddress, Source: SourceSNMP, IfIndex: 32, Name: MetricIfInOctets, At: pollTime,
		ExactCounter: &CounterValue{Value: 1<<32 - 1, Width: 32, PollStartedAt: pollTime, PollCompletedAt: pollTime}}
	for _, mode := range []string{"missing", "refused", "wrong key", "missing clock", "resource refused", "raised", "good"} {
		backend := &counterBusRecorder{}
		emitter := NewBusEmitter(backend, tenant)
		if mode == "resource refused" {
			if err := emitter.WithCounterResources(1, 1); err != nil {
				t.Fatal(err)
			}
		}
		if mode == "raised" {
			if err := emitter.WithCounterResources(1<<40, 1<<40); err != nil {
				t.Fatal(err)
			}
		}
		called := 0
		if mode != "missing" {
			emitter.WithCounterWitness(counterWitnessFunc(func(ctx context.Context, sender string, digest [32]byte, input entity.CounterCaptureInput) (entity.CounterCaptureReference, error) {
				called++
				if len(backend.records) != 0 {
					t.Fatal("raw bytes published before their authenticated witness committed")
				}
				if input.PointCount != 1 || input.ConfiguredTarget != metric.Device || sender != metric.AgentID || digest == ([32]byte{}) {
					t.Fatal("witness dropped the original source, whole population or digest")
				}
				if mode == "refused" {
					return entity.CounterCaptureReference{}, errors.New("source refused")
				}
				got, err := counterWitnessStub(tenant)(ctx, sender, digest, input)
				if mode == "wrong key" {
					got.Key[0] ^= 255
				}
				if mode == "missing clock" {
					got.CapturedAt = time.Time{}
				}
				return got, err
			}))
		}
		err := emitter.EmitCounters(t.Context(), []Metric{metric})
		if mode == "good" || mode == "raised" {
			if err != nil || called != 1 || len(backend.records) != 1 {
				t.Fatal("complete authenticated counter publication failed", err)
			}
		} else if err == nil || len(backend.records) != 0 {
			t.Fatal("missing, refused or mismatched witness published raw bytes", mode)
		}
	}
}
