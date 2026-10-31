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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type fixtureSnapshotLifecycle struct {
	called bool
	fn     func(context.Context, string, func(context.Context) error) error
}

func (f *fixtureSnapshotLifecycle) Invalidate(ctx context.Context, tenant string, mutate func(context.Context) error) error {
	f.called = true
	return f.fn(ctx, tenant, mutate)
}

func TestSubjectFlowSnapshotInvalidationWrapsSourceErasureAndRefusesBadSelector(t *testing.T) {
	for _, name := range []string{"successful purge", "purge failed", "invalid selector"} {
		t.Run(name, func(t *testing.T) {
			flows := flowstore.NewMemory()
			row := flowstore.Row{TenantID: "tenant-a", AgentID: "alice@example.test", Exporter: "router", TS: time.Now(), SrcAddr: "192.0.2.1", DstAddr: "192.0.2.2", Bytes: 1}
			if err := flows.Insert(t.Context(), []flowstore.Row{row}); err != nil {
				t.Fatal(err)
			}
			lifecycle := &fixtureSnapshotLifecycle{fn: func(ctx context.Context, tenant string, mutate func(context.Context) error) error {
				if tenant != "tenant-a" {
					t.Fatal("wrong tenant in cache invalidation")
				}
				var before bytes.Buffer
				if _, err := flows.ExportTenant(ctx, tenant, &before); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(before.String(), "alice@example.test") {
					t.Fatal("source deleted before cache barrier")
				}
				if name == "purge failed" {
					return errors.New("cannot verify physical cache deletion")
				}
				return mutate(ctx)
			}}
			e := New(nil, flows, nil, nil, nil, "QA retention", nil)
			e.flowSnapshots = lifecycle
			subject := "alice@example.test"
			if name == "invalid selector" {
				subject = "a"
			}
			report, err := e.EraseSubject(t.Context(), "tenant-a", subject, "operator", "QA")
			if err != nil {
				t.Fatal(err)
			}
			var after bytes.Buffer
			if _, err := flows.ExportTenant(t.Context(), "tenant-a", &after); err != nil {
				t.Fatal(err)
			}
			if name == "successful purge" {
				if !report.Complete || after.Len() != 0 || !lifecycle.called {
					t.Fatalf("erasure incomplete: %+v", report)
				}
			} else {
				if report.Complete || after.Len() == 0 {
					t.Fatalf("unsafe destructive/complete receipt: %+v", report)
				}
				if name == "invalid selector" && lifecycle.called {
					t.Fatal("bad selector invalidated a cache")
				}
			}
		})
	}
}

func TestFlowSnapshotKeysAndObjectsAreNotPortableSourceData(t *testing.T) {
	input := []string{"users", "flow_snapshots", "flow_snapshot_epochs", "flow_query_filters"}
	if got := ordinaryPortabilityExportTables(input); !slices.Equal(got, []string{"users", "flow_query_filters"}) {
		t.Fatalf("cache/key table exported: %v", got)
	}
	objects := objectstore.NewMemory()
	for _, key := range []string{"tenant/tenant-a/flow-explorer/snapshots/one/0", "silo/tenant-a/flow-explorer/snapshots/two/0", "tenant/tenant-a/browser/one.png"} {
		if err := objects.Put(t.Context(), key, "application/octet-stream", []byte("QA ciphertext")); err != nil {
			t.Fatal(err)
		}
	}
	e := New(nil, nil, objects, nil, nil, "QA retention", nil)
	var archive bytes.Buffer
	manifest, err := e.Export(t.Context(), "tenant-a", &archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Objects) != 1 || manifest.Objects[0].Key != "tenant/tenant-a/browser/one.png" {
		t.Fatalf("cache inventory leaked into portability: %+v", manifest.Objects)
	}
	if !slices.Contains(manifest.Notes, ordinaryPortabilityFlowCacheNote) {
		t.Fatal("missing cache/source portability explanation")
	}
}

func TestFlowRetentionIntentPrecedesCacheBarrierAndSourcePrune(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "intent accepted", true: "intent refused"}[refuse], func(t *testing.T) {
			flows := &auditFlowRetentionPruner{}
			intent := false
			refused := errors.New("intent audit unavailable")
			engine := New(nil, flows, nil, nil, func(_ context.Context, _, _, _ string, data map[string]any) error {
				if data["status"] == "intent" {
					if refuse {
						return refused
					}
					intent = true
				}
				return nil
			}, "QA", testLog())
			barrier := &fixtureSnapshotLifecycle{fn: func(ctx context.Context, tenant string, mutate func(context.Context) error) error {
				if tenant != "tenant-a" {
					t.Fatal("retention crossed the cache tenant boundary")
				}
				if !intent {
					t.Fatal("cache barrier ran before successful prune intent")
				}
				if len(flows.calls) != 0 {
					t.Fatal("source pruned before cache barrier")
				}
				return mutate(ctx)
			}}
			engine.flowSnapshots = barrier
			err := engine.sweepFlowRetention(t.Context(), retentionSweepPolicy{tenant: "tenant-a", days: map[string]int{"flows": 1}})
			if refuse {
				if !errors.Is(err, refused) || barrier.called || len(flows.calls) != 0 {
					t.Fatalf("refused intent mutated cache/source: %v", err)
				}
			} else {
				if err != nil || !barrier.called || len(flows.calls) != 1 {
					t.Fatalf("successful intent did not wrap prune: %v", err)
				}
			}
		})
	}
}
