// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/pathstore"
)

func TestMCPFlowSourcesDoNotOpenDisabledExternalStores(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-credential.json")
	cfg := &config.Config{FlowStoreMode: "memory", TSDBMode: "memory", ObjectStoreDir: t.TempDir(), ClickHouseBasicAuthFile: missing, TSDBBasicAuthFile: missing}
	paths := pathstore.NewMemory()
	defer paths.Close()
	sources, closeSources, err := buildMCPFlowSources(cfg, quietLogger(), &store.DB{}, paths)
	if err != nil {
		t.Fatal("disabled external reader required credentials or connections", err)
	}
	defer closeSources()
	if sources.NativeFlow == nil || sources.Flow == nil || sources.Metrics == nil || sources.DeviceOps == nil {
		t.Fatal("standalone native source assembly is incomplete")
	}
}

func TestConfiguredFlowSnapshotCachePreservesDefaultsAndRejectsUnlimited(t *testing.T) {
	defaults, err := configuredFlowSnapshotCache(&config.Config{})
	if err != nil || defaults != flowsnapshot.DefaultConfig() {
		t.Fatal("constructor cache defaults changed", err)
	}
	cfg := &config.Config{FlowSnapshotLifetime: 2 * time.Minute, FlowSnapshotTenantBytes: 1 << 30, FlowSnapshotBytes: 256 << 20, FlowSnapshotObjectBytes: 96 << 20, FlowSnapshotExportBytes: 384 << 20}
	want := flowsnapshot.Config{Lifetime: 2 * time.Minute, TenantBytes: 1 << 30, SnapshotBytes: 256 << 20, ObjectBytes: 96 << 20, ExportBytes: 384 << 20}
	if got, err := configuredFlowSnapshotCache(cfg); err != nil || got != want {
		t.Fatal("operator cache policy was lost", err)
	}
	cfg.FlowSnapshotObjectBytes = -1
	if _, err := configuredFlowSnapshotCache(cfg); err == nil {
		t.Fatal("negative object admission silently became a default")
	}
}

func TestConfiguredFlowQueryBudgetSharedConstruction(t *testing.T) {
	defaults, err := configuredFlowQueryBudget(&config.Config{})
	if err != nil || defaults != flowstore.DefaultExplorerBudget() {
		t.Fatal("programmatic construction lost existing defaults", err)
	}
	cfg := &config.Config{FlowStoreMode: "memory", TSDBMode: "memory", ObjectStoreDir: t.TempDir(), FlowQueryExecutionLimit: 1250 * time.Millisecond, FlowQueryReadBytes: 384 << 20, FlowQueryReadRows: 12345678, FlowQueryResponseBytes: 96 << 20, FlowQueryMemoryBytes: 1 << 30, FlowQueryIntermediateGroups: 750000, FlowQueryInterfaceItems: 20000, FlowQueryThreads: 3}
	want := flowstore.ExplorerBudget{ExecutionLimit: 1250 * time.Millisecond, ReadBytes: 384 << 20, ReadRows: 12345678, ResponseBytes: 96 << 20, MemoryBytes: 1 << 30, IntermediateGroups: 750000, InterfaceItems: 20000, Threads: 3}
	got, err := configuredFlowQueryBudget(cfg)
	if err != nil || got != want {
		t.Fatal("operator budget mapping lost its values", err)
	}
	serving := flowstore.NewMemory()
	if err := scopeConfiguredFlowReads(cfg, quietLogger(), nil, serving); err != nil || flowstore.ExplorerQueryBudget(serving) != want {
		t.Fatal("serving construction did not attach the configured budget", err)
	}
	paths := pathstore.NewMemory()
	defer paths.Close()
	sources, closeSources, err := buildMCPFlowSources(cfg, quietLogger(), &store.DB{}, paths)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSources()
	if flowstore.ExplorerQueryBudget(sources.Flow) != want {
		t.Fatal("stdio construction diverged from the serving budget")
	}
	cfg.FlowQueryReadRows = -1
	if err := scopeConfiguredFlowReads(cfg, quietLogger(), nil, serving); err == nil {
		t.Fatal("invalid cost policy was attached")
	}
	if flowstore.ExplorerQueryBudget(serving) != want {
		t.Fatal("failed attachment changed the previous valid policy")
	}
}
