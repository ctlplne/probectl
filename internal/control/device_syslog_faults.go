// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type deviceSyslogFaultProcessor struct {
	pool     *pgxpool.Pool
	window   time.Duration
	log      *slog.Logger
	observer incident.Observer
}

// RunDeviceSyslogFaults processes only tenants with an explicitly configured
// authenticated syslog device binding. The original observation and the
// incident publication are separate durable operations.
func (s *Server) RunDeviceSyslogFaults(ctx context.Context, tenants []string, window time.Duration, observer incident.Observer) error {
	if s.pool == nil || len(tenants) == 0 {
		return nil
	}
	worker := deviceSyslogFaultProcessor{pool: s.pool, window: window, log: s.log, observer: observer}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			worker.processPending(ctx, tenants)
		}
	}
}

func (worker deviceSyslogFaultProcessor) processPending(ctx context.Context, tenants []string) {
	for _, tenant := range tenants {
		tenantCtx, cancel := context.WithTimeout(tenancy.WithTenant(ctx, tenancy.ID(tenant)), 750*time.Millisecond)
		for range 16 {
			processed, err := worker.processOne(tenantCtx, tenant)
			if err != nil {
				worker.log.Warn("device syslog fault publication failed", "tenant_id", tenant, "error", err)
				break
			}
			if !processed {
				break
			}
		}
		cancel()
		if ctx.Err() != nil {
			return
		}
	}
}

func (worker deviceSyslogFaultProcessor) processOne(ctx context.Context, tenant string) (bool, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenant {
		return false, tenancy.ErrNoTenant
	}
	var item *incident.Incident
	var opened bool
	err := tenancy.InTenant(tenancy.WithSiloTableLock(ctx), worker.pool, func(ctx context.Context, scope tenancy.Scope) error {
		if _, err := scope.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('incident:'||$1::text,0))`, tenant); err != nil {
			return err
		}
		event, err := claimDeviceSyslogFault(ctx, scope)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		signal := event.signal(tenant)
		correlator := incident.NewCorrelator(pgIncidentTxStore{scope: scope}, worker.window, worker.log,
			incident.WithObserver(func(_ context.Context, _ *incident.Incident, wasOpened bool) { opened = wasOpened }))
		item, err = correlator.Ingest(ctx, signal)
		if err != nil {
			return err
		}
		if item == nil || item.ID == "" || item.TenantID != tenant {
			return tenancy.ErrNoTenant
		}
		updated, err := scope.Q.Exec(ctx, `
UPDATE device_syslog_fault_queue SET incident_id=$3
 WHERE tenant_id=$1 AND event_id=$2 AND incident_id IS NULL`, tenant, event.id, item.ID)
		if err != nil {
			return err
		}
		if updated.RowsAffected() != 1 {
			return errors.New("device syslog fault receipt changed during correlation")
		}
		return audit.TenantRecord(ctx, scope, "system", "device.syslog.fault", item.ID,
			map[string]any{"device_syslog_id": event.id, "kind": event.kind})
	})
	if err != nil || item == nil {
		return false, err
	}
	if worker.observer != nil {
		worker.observer(ctx, item, opened)
	}
	return true, nil
}

type deviceSyslogFaultEvidence struct {
	id, target, subject, device, pattern string
	kind                                 device.SyslogPatternKind
	observed                             time.Time
}

func claimDeviceSyslogFault(ctx context.Context, scope tenancy.Scope) (deviceSyslogFaultEvidence, error) {
	var evidence deviceSyslogFaultEvidence
	err := scope.Q.QueryRow(ctx, `
SELECT q.event_id::text, q.target, q.subject, d.device, d.pattern_id, d.pattern_kind, d.observed_at
  FROM device_syslog_fault_queue AS q
  JOIN device_syslog AS d ON d.tenant_id=q.tenant_id AND d.id=q.event_id
 WHERE q.tenant_id=$1 AND q.incident_id IS NULL
 ORDER BY q.observed_at, q.event_id
 LIMIT 1
 FOR UPDATE OF q SKIP LOCKED`, scope.Tenant.String()).Scan(
		&evidence.id, &evidence.target, &evidence.subject, &evidence.device, &evidence.pattern, &evidence.kind, &evidence.observed)
	return evidence, err
}

func (evidence deviceSyslogFaultEvidence) signal(tenant string) incident.Signal {
	title := "Device syslog fault"
	switch evidence.kind {
	case device.SyslogPatternLinkDown:
		title = "Interface down"
	case device.SyslogPatternBGPDown:
		title = "BGP neighbor down"
	case device.SyslogPatternSupplyFault:
		title = "Power supply fault"
	}
	return incident.Signal{TenantID: tenant, Plane: "device", Kind: "device.syslog." + string(evidence.kind), Severity: incident.SeverityWarning,
		Title: title, Summary: title + " on " + evidence.device, Target: evidence.target, OccurredAt: evidence.observed,
		Attributes: map[string]string{"probectl.device.syslog.event_id": evidence.id,
			"probectl.device.syslog.pattern_id": evidence.pattern, "probectl.device.syslog.subject": evidence.subject}}
}
