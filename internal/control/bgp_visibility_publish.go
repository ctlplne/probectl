// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) publishBGPVisibility(ctx context.Context, tenant tenancy.ID, id string, prefix netip.Prefix,
	point store.BGPVisibilityObservation, eligibleForAlert bool, window time.Duration, observer incident.Observer) error {
	if s.pool == nil || tenant == "" {
		return tenancy.ErrNoTenant
	}
	if bound, ok := tenancy.FromContext(ctx); ok && bound != tenant {
		return tenancy.ErrNoTenant
	}
	ctx = tenancy.WithSiloTableLock(tenancy.WithTenant(ctx, tenant))
	var emitted *incident.Incident
	var opened bool
	err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := tenancy.AcquireTenantWriteLease(ctx, sc); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('bgp-visibility:'||$1::text,0))`, tenant.String()); err != nil {
			return err
		}
		monitor, err := store.BGPVisibilityMonitorInScope(ctx, sc, id)
		if errors.Is(err, store.ErrBGPVisibilityMissing) {
			return nil
		}
		if err != nil {
			return err
		}
		if monitor.Prefix != prefix {
			return store.ErrBGPVisibilityInput
		}
		storage := store.BGPVisibility{}
		added, err := storage.Record(ctx, sc, id, point)
		if err != nil || !added || !eligibleForAlert || point.Counts == nil || point.ObservedAt.Before(monitor.CreatedAt) {
			return err
		}
		prior, err := storage.Previous(ctx, sc, id, point)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		kind := bgpVisibilityAlertKind(monitor, prior, point)
		if kind == "" {
			return nil
		}
		if _, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('incident:'||$1::text,0))`, tenant.String()); err != nil {
			return err
		}
		correlator := incident.NewCorrelator(pgIncidentTxStore{scope: sc}, window, s.log,
			incident.WithObserver(func(_ context.Context, _ *incident.Incident, wasOpened bool) { opened = wasOpened }))
		signal := bgpVisibilityAlertSignal(tenant, monitor, point, kind)
		emitted, err = correlator.Ingest(ctx, signal)
		if err != nil {
			return err
		}
		if emitted == nil || emitted.ID == "" || emitted.TenantID != tenant.String() {
			return store.ErrBGPVisibilityInput
		}
		return audit.TenantRecord(ctx, sc, "system", "bgp.visibility.alert", monitor.ID,
			map[string]any{"incident_id": emitted.ID, "kind": kind, "archive_sha256": point.ArchiveSHA256})
	})
	if err == nil && emitted != nil && observer != nil {
		observer(ctx, emitted, opened)
	}
	return err
}

func bgpVisibilityAlertKind(monitor store.BGPVisibilityMonitor, prior, point store.BGPVisibilityObservation) string {
	if prior.Counts == nil || point.Counts == nil || prior.BaselineSHA256 != point.BaselineSHA256 ||
		prior.PolicyVersion != point.PolicyVersion || prior.Counts.EligiblePeers != point.Counts.EligiblePeers ||
		prior.Counts.VisiblePeers <= point.Counts.VisiblePeers {
		return ""
	}
	if point.Counts.VisiblePeers == 0 && monitor.AlertOnLoss {
		return "bgp.visibility_lost"
	}
	if point.Counts.VisiblePeers > 0 && monitor.AlertOnPartial {
		threshold := monitor.MinimumVisibleBasisPoints * point.Counts.EligiblePeers
		if prior.Counts.VisiblePeers*10000 >= threshold && point.Counts.VisiblePeers*10000 < threshold {
			return "bgp.visibility_partial"
		}
	}
	return ""
}

func bgpVisibilityAlertSignal(tenant tenancy.ID, monitor store.BGPVisibilityMonitor, point store.BGPVisibilityObservation, kind string) incident.Signal {
	title, severity := "BGP prefix visibility fell below its threshold", incident.SeverityWarning
	if kind == "bgp.visibility_lost" {
		title, severity = "BGP prefix lost visibility at a public collector", incident.SeverityCritical
	}
	prefix := monitor.Prefix.String()
	return incident.Signal{TenantID: tenant.String(), Plane: "bgp", Kind: kind, Severity: severity,
		Title: title, Target: prefix, Prefix: prefix, OccurredAt: point.ObservedAt,
		Attributes: map[string]string{
			"network.destination.prefix":              prefix,
			"probectl.bgp.visibility.monitor_id":      monitor.ID,
			"probectl.bgp.visibility.source":          point.Source,
			"probectl.bgp.visibility.collector":       point.Collector,
			"probectl.bgp.visibility.baseline_sha256": point.BaselineSHA256,
			"probectl.bgp.visibility.archive_sha256":  point.ArchiveSHA256,
			"probectl.bgp.visibility.eligible_peers":  strconv.Itoa(point.Counts.EligiblePeers),
			"probectl.bgp.visibility.visible_peers":   strconv.Itoa(point.Counts.VisiblePeers),
			"probectl.bgp.visibility.policy":          point.PolicyVersion,
		}}
}
