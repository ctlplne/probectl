// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func counterLifecycleFixture(t *testing.T, history *flowstore.Memory, tenant string, at time.Time) {
	t.Helper()
	input := entity.CounterCaptureInput{ConfiguredTarget: "192.0.2.1", PollStartedAt: at, PollCompletedAt: at.Add(time.Second), PointCount: 1}
	digest := [32]byte{1, 255}
	key, err := entity.CounterCaptureKey(tenant, "alice@example.test", digest, input)
	if err != nil {
		t.Fatal(err)
	}
	row := flowstore.CounterRow{TenantID: tenant, CounterSource: flowstore.CounterSource{ContextID: "22222222-2222-4222-8222-222222222222", DeviceID: "33333333-3333-4333-8333-333333333333", AgentID: "alice@example.test", SourceRef: input.ConfiguredTarget, SourceAssignedAt: at.Add(-time.Hour), AgentAssignedAt: at.Add(-time.Hour)}, SenderSerial: "issued", CaptureKey: key, RawDigest: digest, CapturedAt: at.Add(2 * time.Second), PollStartedAt: at, PollCompletedAt: input.PollCompletedAt, Population: 1, IfIndex: 7, Name: "probectl.device.if.in.octets", Value: ^uint64(0), Width: 64, UptimeKnown: true, DiscontinuityKnown: true}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	if err := history.InsertCounterPoll(ctx, []flowstore.CounterRow{row}, flowstore.CounterBudget{MemoryBytes: 8 << 20, WorkUnits: 8 << 20, Timeout: time.Minute}); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceCounterLifecycleExportsAndErasesOnlyValidatedTenantSubject(t *testing.T) {
	const red = "11111111-1111-4111-8111-111111111111"
	const blue = "66666666-6666-4666-8666-666666666666"
	for _, mode := range []string{"success", "invalid-selector", "barrier-refused"} {
		t.Run(mode, func(t *testing.T) {
			history := flowstore.NewMemory()
			for _, tenant := range []string{red, blue} {
				counterLifecycleFixture(t, history, tenant, time.Now().Add(-time.Hour))
			}
			engine := New(nil, history, nil, nil, nil, "", testLog()).WithCounterHistory(history, 90)
			var bundled bytes.Buffer
			manifest, err := engine.Export(t.Context(), red, &bundled)
			if err != nil || manifest.DeviceCounters != 1 {
				t.Fatal("complete ordinary counter portability failed", manifest.DeviceCounters, err)
			}
			data := fileFromBundle(t, &bundled, "device_counters.jsonl")
			if !bytes.Contains(data, []byte(`"counter_value":"18446744073709551615"`)) || bytes.Contains(data, []byte(blue)) {
				t.Fatal("portability rounded a word or included a sibling")
			}
			barrier := &fixtureSnapshotLifecycle{fn: func(ctx context.Context, tenant string, mutate func(context.Context) error) error {
				if n, err := history.ExportCounterTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), tenant, io.Discard); err != nil || n != 1 {
					t.Fatal("counter deletion preceded the cache/source barrier", n, err)
				}
				if mode == "barrier-refused" {
					return errors.New("cache deletion unavailable")
				}
				return mutate(ctx)
			}}
			engine.flowSnapshots = barrier
			subject := "alice@example.test"
			if mode == "invalid-selector" {
				subject = "a"
			}
			report, err := engine.EraseSubject(t.Context(), red, subject, "operator", "test")
			if err != nil {
				t.Fatal(err)
			}
			if report.Complete != (mode == "success") {
				t.Fatal("incomplete counter erasure reported success", report)
			}
			if mode == "invalid-selector" && barrier.called {
				t.Fatal("invalid destructive selector reached the barrier")
			}
			for _, tenant := range []string{red, blue} {
				want := int64(1)
				if tenant == red && mode == "success" {
					want = 0
				}
				if n, err := history.ExportCounterTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), tenant, io.Discard); err != nil || n != want {
					t.Fatal("erasure changed a sibling or deleted before validation", tenant, n, want, err)
				}
			}
		})
	}
}

func TestDeviceCounterLifecycleRetentionUsesExistingPolicyAndAuditBeforeDeletion(t *testing.T) {
	const red = "11111111-1111-4111-8111-111111111111"
	const blue = "66666666-6666-4666-8666-666666666666"
	now := time.Now()
	history := flowstore.NewMemory()
	for _, tenant := range []string{red, blue} {
		counterLifecycleFixture(t, history, tenant, now.Add(-72*time.Hour))
	}
	audit := &capturedAudit{}
	engine := New(nil, history, nil, nil, audit.sink, "", testLog()).WithCounterHistory(history, 90).WithClock(func() time.Time { return now })
	if err := engine.sweepCounterRetention(t.Context(), retentionSweepPolicy{tenant: red, days: map[string]int{"flows": 2}}); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{red, blue} {
		want := int64(1)
		if tenant == red {
			want = 0
		}
		if n, err := history.ExportCounterTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), tenant, io.Discard); err != nil || n != want {
			t.Fatal("retention ignored tenant policy or changed a sibling", n, err)
		}
	}
	var actions []string
	for _, action := range audit.events {
		if strings.Contains(action, "retention") {
			actions = append(actions, action)
		}
	}
	if len(actions) != 2 {
		t.Fatal("counter retention omitted intent or result audit", actions)
	}
}
