// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/pipeline"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func (rt *serveRuntime) runDeviceCounterConsumer() error {
	history, ok := flowstore.CounterHistoryOf(rt.flowStore)
	if !ok {
		return fmt.Errorf("counter history backend is unavailable")
	}
	// The source guard holds its transaction throughout routed history IO.
	// Keep those leases off the main pool: a cold/expired silo router needs
	// that main pool to refresh, even when it has only one connection.
	settings := rt.db.Pool().Config()
	settings.MaxConns = min(settings.MaxConns, 4)
	settings.MinConns = 0
	settings.MinIdleConns = 0
	verifier, err := pgxpool.NewWithConfig(rt.gctx, settings)
	if err != nil {
		return fmt.Errorf("counter witness pool: %w", err)
	}
	defer verifier.Close()
	budget := flowstore.CounterBudget{MemoryBytes: int64(rt.cfg.DeviceCounterMemoryBytes), WorkUnits: int64(rt.cfg.DeviceCounterWorkUnits), Timeout: rt.cfg.DeviceCounterTimeout}
	return superviseBusLaneRestart(rt.gctx, "device-counter-pipeline", rt.log, func(ctx context.Context, snap busLaneSnapshot) error {
		return pipeline.NewDeviceCounterConsumer(rt.resultBus, history, store.NewDeviceCounterCaptures(verifier), budget, rt.cfg.FlowRetentionDays, rt.log).
			WithTenantBinding(rt.tenantBinding).
			WithNamespaceTenants(snap.tenants).
			WithStrictTenantLanes(rt.cfg.IngestStrictTenantLanes).
			WithFairness(rt.fairGate).
			WithMetrics(rt.srv.Metrics()).Run(ctx)
	})
}
