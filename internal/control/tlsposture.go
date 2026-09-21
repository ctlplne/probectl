// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/threat"
)

// TLS/cert posture inventory API (S-FE2): the read side of S27. The inventory
// is the posture store the TLS consumer maintains from the result stream —
// the handler only serves the CALLER's tenant partition (tenant first, then
// the threat.read RBAC check on the route — CLAUDE.md §7 guardrails 1, 5).

// WithTLSPosture attaches the posture inventory backing GET /v1/tls/posture.
// nil is a no-op (the endpoint reports collector_running=false). Returns the
// server for chaining.
func (s *Server) WithTLSPosture(ps *threat.PostureStore) *Server {
	if ps != nil {
		s.tlsPostures = ps
	}
	return s
}

// WithAuditWORMStatus attaches the tamper-evident audit exporter's own view of
// itself, which becomes the `audit_worm` check on GET /v1/diagnostics and in the
// support bundle (DPR-200). nil is a no-op: WORM export is a deployment choice,
// and a deployment that has not configured it must not grow a check that is
// permanently unhappy about its absence.
func (s *Server) WithAuditWORMStatus(dir string, status func() audit.WormExportStatus) *Server {
	if status != nil {
		s.auditWORMStatus = status
		s.auditWORMDir = dir
	}
	return s
}

// handleTLSPosture serves GET /v1/tls/posture — the tenant's certificate
// inventory (latest analyzed posture per target, flagged findings + the
// verbatim trustctl handoff payload). collector_running=false distinguishes
// "no HTTPS targets observed" from "the collector is not wired".
func (s *Server) handleTLSPosture(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.tlsPostures == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []threat.Posture{}, "collector_running": false})
		return nil
	}
	items := s.tlsPostures.List(tid)
	if items == nil {
		items = []threat.Posture{}
	}
	now := time.Now()
	for i := range items {
		items[i] = items[i].WithFreshness(now)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "collector_running": true})
	return nil
}

// withDetections attaches the in-memory fallback backing GET
// /v1/threat/detections (S-FE3) when no Postgres pool is available. Production
// HA deployments prefer the durable incident_signals reader so every replica
// answers from the same tenant-scoped store.
func (s *Server) withDetections(ds *threat.DetectionStore) *Server {
	if ds != nil {
		s.detections = ds
	}
	return s
}

// handleThreatDetections serves GET /v1/threat/detections — the tenant's recent
// IOC/NDR detections (newest first) with source attribution + confidence and
// the correlated incident id (the triage pivot). Detections are SIGNALS —
// probectl never blocks (guardrail 9) — and feeds can list benign
// infrastructure, so provenance ships verbatim.
func (s *Server) handleThreatDetections(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.pool != nil {
		items, err := s.listDurableThreatDetections(r.Context(), tid)
		if err != nil {
			return err
		}
		if items == nil {
			items = []threat.Detection{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "detections_running": true})
		return nil
	}
	if s.detections == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []threat.Detection{}, "detections_running": false})
		return nil
	}
	items := s.detections.List(tid)
	if items == nil {
		items = []threat.Detection{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "detections_running": true})
	return nil
}

func (s *Server) listDurableThreatDetections(ctx context.Context, tenant string) ([]threat.Detection, error) {
	var items []threat.Detection
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), s.pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			items, err = store.Incidents{}.ThreatDetections(ctx, sc, threat.DefaultMaxDetectionsPerTenant)
			return err
		})
	return items, err
}
