// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/support"
)

// PLAT-09 ("probectl observes probectl"): /readyz and /v1/diagnostics used to
// probe ONLY Postgres, so an outage of the result bus (Kafka/NATS), the TSDB
// (Prometheus/VictoriaMetrics), the ClickHouse event stores or the object store
// was invisible — and a deployment running a VOLATILE memory backend reported
// healthy while it silently lost telemetry on every restart. These per-subsystem
// deep-health checks make each configured external backend observable:
//
//   - a configured EXTERNAL backend that fails its reachability probe is DOWN
//     with a named finding, so the diagnostics aggregate degrades; and
//   - a VOLATILE memory backend is a DEGRADED warning (never a silent "ok"),
//     because memory mode is a dev/test choice that loses data on any restart.
//
// Reachability is surfaced on /v1/diagnostics (the admin deep-health surface),
// not on the hot /readyz path: these backends are shared infrastructure, so
// draining every replica over a shared-backend blip would remove working
// capacity without routing around the fault — the same reasoning the audit_worm
// check documents. /readyz keeps failing closed on the one per-replica-critical
// dependency (the database writer).

// subsystemHealthProbeTimeout bounds each external-backend reachability probe so
// a hung backend cannot stall the diagnostics aggregate.
const subsystemHealthProbeTimeout = 3 * time.Second

// SubsystemProbes are optional reachability probes for the external backends a
// deployment is configured to use (PLAT-09). Each is nil unless that subsystem
// is configured for an external backend AND the serve seam wired a probe (a
// pool-less unit server leaves them nil, which the checks report as "configured
// but not probed on this replica" rather than a false outage). A probe returning
// an error means the configured backend is unreachable; /v1/diagnostics names it
// and the aggregate degrades. Memory-mode volatility is a separate, cfg-driven
// warning that needs no probe.
type SubsystemProbes struct {
	Bus         func(context.Context) error
	TSDB        func(context.Context) error
	EventStore  func(context.Context) error
	ObjectStore func(context.Context) error
}

// WithSubsystemProbes wires the external-backend reachability probes used by the
// bus/tsdb/event_store/object_store deep-health checks (PLAT-09). The serve seam
// builds them from the live clients; tests inject fakes. nil probes are safe
// (the checks fall back to a cfg-only view).
func (s *Server) WithSubsystemProbes(p SubsystemProbes) *Server {
	s.subsystemProbes = p
	return s
}

// registerSubsystemChecks adds the per-subsystem external-backend checks to the
// deep-health set. It is only called when cfg is present (the check logic reads
// the configured modes).
func (s *Server) registerSubsystemChecks(checks map[string]support.CheckFunc) {
	checks["bus"] = s.busHealthCheck
	checks["tsdb"] = s.tsdbHealthCheck
	checks["event_store"] = s.eventStoreHealthCheck
	checks["object_store"] = s.objectStoreHealthCheck
}

// busHealthCheck observes the result bus: a volatile memory bus is a warning; a
// configured NATS/Kafka bus is probed for reachability.
func (s *Server) busHealthCheck(ctx context.Context) support.Check {
	switch s.cfg.BusMode {
	case "memory":
		return volatileBackendCheck("bus", "readiness.bus",
			"The result bus runs in memory mode",
			"PROBECTL_BUS_MODE=memory — published results live only in RAM and are lost on any restart, upgrade, OOM or node drain.",
			s.cfg.VolatileAcknowledged())
	case "nats", "kafka":
		return externalBackendCheck(ctx, "bus", "readiness.bus",
			"The result bus is unreachable", s.cfg.BusMode, s.subsystemProbes.Bus)
	default:
		return support.Check{Name: "bus", Status: support.StatusOK, Detail: "no result bus configured"}
	}
}

// tsdbHealthCheck observes the metrics store: a volatile memory TSDB is a
// warning; a configured Prometheus/VictoriaMetrics backend is probed.
func (s *Server) tsdbHealthCheck(ctx context.Context) support.Check {
	switch s.cfg.TSDBMode {
	case "memory":
		return volatileBackendCheck("tsdb", "readiness.tsdb",
			"The metrics store runs in memory mode",
			"PROBECTL_TSDB_MODE=memory — every metric lives only in RAM and is lost on any restart, upgrade, OOM or node drain.",
			s.cfg.VolatileAcknowledged())
	case "prometheus":
		return externalBackendCheck(ctx, "tsdb", "readiness.tsdb",
			"The metrics store is unreachable", "prometheus", s.subsystemProbes.TSDB)
	default:
		return support.Check{Name: "tsdb", Status: support.StatusOK, Detail: "no external metrics store configured"}
	}
}

// eventStoreHealthCheck observes the ClickHouse event store: it is probed
// whenever any event plane is ClickHouse-backed. Memory-mode volatility of the
// event planes is reported holistically by the volatile_stores check.
func (s *Server) eventStoreHealthCheck(ctx context.Context) support.Check {
	if !clickHouseEventStoreConfigured(s.cfg) {
		return support.Check{Name: "event_store", Status: support.StatusOK, Detail: "no ClickHouse event store configured"}
	}
	return externalBackendCheck(ctx, "event_store", "readiness.event_store",
		"The ClickHouse event store is unreachable", "clickhouse", s.subsystemProbes.EventStore)
}

// objectStoreHealthCheck observes the tenant object store: an external S3/MinIO
// store is probed; a filesystem/unconfigured store is local and durable.
func (s *Server) objectStoreHealthCheck(ctx context.Context) support.Check {
	switch s.cfg.ObjectStoreMode {
	case "s3":
		return externalBackendCheck(ctx, "object_store", "readiness.object_store",
			"The object store is unreachable", "s3", s.subsystemProbes.ObjectStore)
	default:
		return support.Check{Name: "object_store", Status: support.StatusOK, Detail: "object store is local or unconfigured"}
	}
}

// clickHouseEventStoreConfigured reports whether any telemetry event plane is
// ClickHouse-backed (mirrors the serve builder's clickHouseStoreEnabled).
func clickHouseEventStoreConfigured(cfg *config.Config) bool {
	return cfg.PathStoreMode == "clickhouse" || cfg.FlowStoreMode == "clickhouse" ||
		cfg.OTelStoreMode == "clickhouse" || cfg.EBPFStoreMode == "clickhouse" ||
		cfg.EndpointStoreMode == "clickhouse"
}

// externalBackendCheck probes one configured external backend. A nil probe (a
// pool-less unit server) reports ok-but-unprobed rather than a false outage; a
// probe error is a DOWN check with a named, critical finding whose evidence
// never carries the raw dependency error (it may hold DSNs/hosts/credentials —
// the same redaction the database check applies).
func externalBackendCheck(ctx context.Context, name, findingID, title, backend string, probe func(context.Context) error) support.Check {
	if probe == nil {
		return support.Check{Name: name, Status: support.StatusOK,
			Detail: backend + " backend configured; reachability not probed on this replica"}
	}
	pctx, cancel := context.WithTimeout(ctx, subsystemHealthProbeTimeout)
	defer cancel()
	if err := probe(pctx); err != nil {
		return support.Check{
			Name:   name,
			Status: support.StatusDown,
			Detail: "configured " + backend + " backend is unreachable",
			Finding: support.NewReadinessFinding(
				findingID,
				title,
				"The configured "+backend+" backend did not answer a health probe; connection details are redacted. "+
					"Telemetry that depends on it cannot be written or read until it recovers.",
				support.LocalAction{Label: "Download redacted support bundle", Href: "/v1/diagnostics/bundle", Kind: support.ActionDownload},
			),
		}
	}
	return support.Check{Name: name, Status: support.StatusOK, Detail: backend + " backend reachable"}
}

// volatileBackendCheck reports a memory-backed subsystem as a DEGRADED warning
// (or an explicitly acknowledged, still-named "ok" when PROBECTL_ALLOW_VOLATILE
// is set) — never a silent "ok".
func volatileBackendCheck(name, findingID, title, detail string, acknowledged bool) support.Check {
	if acknowledged {
		return support.Check{Name: name, Status: support.StatusOK,
			Detail: detail + " (acknowledged via PROBECTL_ALLOW_VOLATILE)"}
	}
	return support.Check{
		Name:   name,
		Status: support.StatusDegraded,
		Detail: detail,
		Finding: support.NewReadinessFinding(
			findingID,
			title,
			detail+" Configure a durable backend, or acknowledge a deliberate dev/test deployment with PROBECTL_ALLOW_VOLATILE="+config.VolatileAckPhrase+".",
			support.LocalAction{Label: "Storage configuration", Href: "/docs/configuration", Kind: support.ActionNavigate},
		),
	}
}
