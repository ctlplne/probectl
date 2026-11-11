// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/inventory"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantlife"
)

// Both the serving process and standalone MCP must use the policy-bound
// reader and the same fail-closed boot proof, never the writer on a read path.
func scopeConfiguredFlowReads(cfg *config.Config, log *slog.Logger, readerAuth *crypto.BasicAuthClientFactory, flowStore flowstore.Store) error {
	budget, err := configuredFlowQueryBudget(cfg)
	if err != nil {
		return err
	}
	if err := installCHReaderPolicy(chReaderSpec{scopingOn: cfg.FlowCHTenantScoping, readerUser: cfg.FlowCHReaderUser,
		storeURL: cfg.FlowStoreURL, plane: "flowstore", finding: "TENANT-102", readerAuth: readerAuth}, log,
		func(reader *http.Client) (chReaderLane, bool) {
			ch, ok := flowStore.(*flowstore.ClickHouse)
			if !ok {
				return nil, false
			}
			return ch.WithTenantScoping(true).WithReader(reader), true
		}); err != nil {
		return err
	}

	return flowstore.AttachExplorerBudget(flowStore, budget)
}

func configuredFlowQueryBudget(cfg *config.Config) (flowstore.ExplorerBudget, error) {
	budget := flowstore.DefaultExplorerBudget()
	// Programmatic fixtures retain constructor defaults for absent fields.
	// Environment loading refuses zero before reaching this composition seam.
	if cfg.FlowQueryExecutionLimit != 0 {
		budget.ExecutionLimit = cfg.FlowQueryExecutionLimit
	}
	choose := func(value, fallback int) int {
		if value == 0 {
			return fallback
		}
		return value
	}
	budget.ReadBytes = int64(choose(cfg.FlowQueryReadBytes, int(budget.ReadBytes)))
	budget.ReadRows = choose(cfg.FlowQueryReadRows, budget.ReadRows)
	budget.ResponseBytes = int64(choose(cfg.FlowQueryResponseBytes, int(budget.ResponseBytes)))
	budget.MemoryBytes = int64(choose(cfg.FlowQueryMemoryBytes, int(budget.MemoryBytes)))
	budget.IntermediateGroups = choose(cfg.FlowQueryIntermediateGroups, budget.IntermediateGroups)
	budget.InterfaceItems = choose(cfg.FlowQueryInterfaceItems, budget.InterfaceItems)
	budget.Threads = choose(cfg.FlowQueryThreads, budget.Threads)
	return budget, budget.Validate()
}

func configuredFlowSnapshotCache(cfg *config.Config) (flowsnapshot.Config, error) {
	cache := flowsnapshot.DefaultConfig()
	if cfg.FlowSnapshotLifetime != 0 {
		cache.Lifetime = cfg.FlowSnapshotLifetime
	}
	if cfg.FlowSnapshotTenantBytes != 0 {
		cache.TenantBytes = int64(cfg.FlowSnapshotTenantBytes)
	}
	if cfg.FlowSnapshotBytes != 0 {
		cache.SnapshotBytes = int64(cfg.FlowSnapshotBytes)
	}
	if cfg.FlowSnapshotObjectBytes != 0 {
		cache.ObjectBytes = int64(cfg.FlowSnapshotObjectBytes)
	}
	if cfg.FlowSnapshotExportBytes != 0 {
		cache.ExportBytes = int64(cfg.FlowSnapshotExportBytes)
	}
	if cache.Lifetime <= 0 || cache.TenantBytes <= 0 || cache.SnapshotBytes <= 0 || cache.ObjectBytes <= 0 || cache.ExportBytes <= 0 {
		return flowsnapshot.Config{}, fmt.Errorf("flow snapshot cost budgets must be positive")
	}
	return cache, nil
}

// Assemble read/query/configuration services without starting the serving
// graph, consumers, maintenance controllers or another network listener.
func buildMCPFlowSources(cfg *config.Config, log *slog.Logger, db *store.DB, paths pathstore.Store) (control.AISources, func(), error) {
	var closers []func()
	closeSources := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}
	fail := func(err error) (control.AISources, func(), error) {
		closeSources()
		return control.AISources{}, nil, err
	}
	writerAuth, err := datastoreBasicAuthFactory(cfg.FlowStoreMode == "clickhouse", cfg.ClickHouseBasicAuthFile)
	if err == nil {
		err = attachDataPlaneCredentials(writerAuth, cfg.DataPlanes, cfg.DataPlaneBasicAuthFiles)
	}
	if err != nil {
		return fail(fmt.Errorf("mcp flow credentials: %w", err))
	}
	readerAuth, err := clickHouseReaderFactory(cfg, writerAuth)
	if err != nil {
		return fail(fmt.Errorf("mcp flow reader credentials: %w", err))
	}
	client, err := datastoreBasicAuthClient(cfg.FlowStoreMode == "clickhouse", cfg.FlowStoreURL, writerAuth)
	if err != nil {
		return fail(fmt.Errorf("mcp flow credentials: %w", err))
	}
	flows, err := flowstore.NewWithClient(cfg.FlowStoreMode, cfg.FlowStoreURL, cfg.FlowRetentionDays, client)
	if err != nil {
		return fail(fmt.Errorf("mcp flow store: %w", err))
	}
	closers = append(closers, func() { _ = flows.Close() })
	if memory, ok := flows.(*flowstore.Memory); ok {
		if err := memory.WithCounterMemoryBudget(int64(cfg.DeviceCounterTenantMemoryBytes), int64(cfg.DeviceCounterTotalMemoryBytes)); err != nil {
			return fail(fmt.Errorf("counter memory admission: %w", err))
		}
	}
	if ch, ok := flowstore.ClickHouseStore(flows); ok {
		ch.WithRouter(func(ctx context.Context, tenant string) (flowstore.Target, error) {
			target, err := tenancy.CurrentRouter().TargetsFor(ctx, tenant)
			if err != nil {
				return flowstore.Target{}, err
			}
			return flowstore.Target{BaseURL: target.CHBaseURL, Database: target.CHDatabase}, nil
		})
	}
	if err := scopeConfiguredFlowReads(cfg, log, readerAuth, flows); err != nil {
		return fail(err)
	}
	metricAuth, err := datastoreBasicAuthFactory(cfg.TSDBMode == "prometheus", cfg.TSDBBasicAuthFile)
	if err != nil {
		return fail(fmt.Errorf("mcp interface metrics credentials: %w", err))
	}
	metricClient, err := datastoreBasicAuthClient(cfg.TSDBMode == "prometheus", cfg.TSDBURL, metricAuth)
	if err != nil {
		return fail(fmt.Errorf("mcp interface metrics credentials: %w", err))
	}
	metrics, err := tsdb.NewWithLimitsAndClient(cfg.TSDBMode, cfg.TSDBURL, cfg.TSDBMemoryRetention, int64(cfg.TSDBMemoryMaxBytes), metricClient)
	if err != nil {
		return fail(fmt.Errorf("mcp interface metrics: %w", err))
	}
	closers = append(closers, func() { _ = metrics.Close() })
	objects, err := openObjectStore(cfg, log)
	if err != nil {
		return fail(err)
	}
	fence := tenancy.NewPostgresWriterFence(db.Pool())
	flows = flowstore.WithTenantWriteFence(flows, fence)
	deviceOps := device.NewPostgresOpsStore(db.Pool())
	core := control.New(cfg, log, db, db.Pool(), paths, nil).WithFlowStore(flows).WithTSDB(metrics).
		WithDeviceOps(deviceOps).WithInventoryViews(inventory.NewPostgresViewStore(db.Pool())).
		WithFlowQueryFilters(flow.NewPostgresQueryFilterStore(db.Pool(), cfg.FlowQueryLibraryBytes, audit.TenantRecord)).WithFlowQueryViews(flow.NewPostgresQueryViewStore(db.Pool(), cfg.FlowQueryLibraryBytes, audit.TenantRecord)).
		WithTenantStatus(control.NewTenantStatusCache(db.Pool(), 0))
	// Reuse the serving source constructor. The complete local IX generation
	// is public input, matched only after current tenant source authorization.
	// This attaches no refresh worker or outbound lookup to stdio.
	if en, enabled := control.BuildEnrichment(cfg, log); enabled {
		core.WithOpenDataStatus(en, nil, nil)
	}
	// Only RetentionFor and snapshot validity are reachable from this MCP
	// backend. No lifecycle/erasure or background maintenance tool is installed.
	lifecycle := tenantlife.NewWithBackupRetention(db.Pool(), flows, objects, nil, nil, cfg.BackupRetentionNote, cfg.BackupRetentionDays, log)
	cache, err := configuredFlowSnapshotCache(cfg)
	if err != nil {
		return fail(err)
	}
	core.WithTenantLife(lifecycle).WithFlowSnapshotStorage(control.FlowSnapshotStorage{Pool: db.Pool(), Objects: objects, Router: tenancy.CurrentRouter(), Fence: fence, DeploymentRetentionDays: cfg.FlowRetentionDays, Cache: cache})
	return control.AISources{NativeFlow: core, Flow: flows, Metrics: metrics, DeviceOps: deviceOps}, closeSources, nil
}
