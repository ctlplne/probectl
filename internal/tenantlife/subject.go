// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tenantlife

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// SubjectPlaneResult is one plane's subject-lifecycle receipt.
type SubjectPlaneResult struct {
	Plane     string `json:"plane"`
	Status    string `json:"status,omitempty"`
	Rows      int64  `json:"rows,omitempty"`
	Deleted   int64  `json:"deleted,omitempty"`
	Remaining int64  `json:"remaining,omitempty"`
	Projected bool   `json:"projected,omitempty"`
	Notes     string `json:"notes,omitempty"`
}

const (
	SubjectStatusExported       = "exported"
	SubjectStatusDeleted        = "deleted"
	SubjectStatusCoveredByPlane = "covered_by_parent"
	SubjectStatusRetainedIR     = "retained_encrypted_evidence"
	SubjectStatusProjected      = "projected"
	SubjectStatusFailed         = "failed"
	SubjectStatusNotDeployed    = "not_deployed"
	SubjectStatusNotCapable     = "not_capable"
	SubjectStatusNotAddressable = "not_subject_addressable"
)

// SubjectManifest describes a subject portability bundle.
type SubjectManifest struct {
	FormatVersion int                  `json:"format_version"`
	TenantID      string               `json:"tenant_id"`
	SubjectHash   string               `json:"subject_hash"`
	ExportedAt    time.Time            `json:"exported_at"`
	Planes        []SubjectPlaneResult `json:"planes"`
	Notes         []string             `json:"notes"`
	Redacted      bool                 `json:"redacted"`
}

// SubjectErasureReport is the receipt returned by EraseSubject. It is not a
// tenant deletion attestation: immutable audit rows are projected, and backup
// copies age out under the tenant backup policy. Complete is true only when
// every deployed plane was erased or count-verified clean; a deployed
// not-capable plane keeps the receipt incomplete. The report is still hashed
// and audited so the request has a durable proof.
type SubjectErasureReport struct {
	FormatVersion int                  `json:"format_version"`
	TenantID      string               `json:"tenant_id"`
	SubjectHash   string               `json:"subject_hash"`
	Actor         string               `json:"actor"`
	Reason        string               `json:"reason,omitempty"`
	StartedAt     time.Time            `json:"started_at"`
	FinishedAt    time.Time            `json:"finished_at"`
	Planes        []SubjectPlaneResult `json:"planes"`
	Complete      bool                 `json:"complete"`
	ReportSHA256  string               `json:"report_sha256"`
}

type flowSubjectDeleter interface {
	DeleteSubject(ctx context.Context, tenantID, subject string) (deleted, remaining int64, err error)
}

type otelSubjectDeleter interface {
	EraseSubject(ctx context.Context, tenantID, subject string) (deleted, remaining int, err error)
}

type otelSubjectExporter interface {
	ExportSubject(ctx context.Context, tenantID, subject string, spansW, logsW io.Writer) (spans, logs int64, err error)
}

type tsdbSubjectExporter interface {
	ExportSubject(ctx context.Context, tenantID, subject string, w io.Writer) (rows int64, err error)
}

type tsdbSubjectDeleter interface {
	DeleteSubject(ctx context.Context, tenantID, subject string) (deleted, remaining int64, err error)
}

type topologySubjectExporter interface {
	ExportSubject(tenantID, subject string, w io.Writer) (nodes, edges, deviceNodes int64, err error)
}

type topologySubjectDeleter interface {
	DeleteSubject(tenantID, subject string) (deleted, remaining, deviceDeleted, deviceRemaining int64)
}

type ebpfSubjectExporter interface {
	ExportSubject(ctx context.Context, tenantID, subject string, w io.Writer) (rows int64, err error)
}

type ebpfSubjectDeleter interface {
	DeleteSubject(ctx context.Context, tenantID, subject string) (deleted, remaining int64, err error)
}

type endpointSubjectExporter interface {
	ExportSubject(tenantID, subject string, w io.Writer) (rows int64, err error)
}

type endpointSubjectDeleter interface {
	DeleteSubject(tenantID, subject string) (deleted, remaining int64)
}

type subjectTableDisposition uint8

const (
	subjectTableDeleteMatches subjectTableDisposition = iota
	subjectTableProjectMatches
	subjectTableNoSubject
	subjectTableRetainEncryptedEvidence
)

type subjectTablePolicy struct {
	plane       string
	disposition subjectTableDisposition
	exact       []string
	contains    []string
}

// subjectPostgresTablePolicies is the fail-closed privacy inventory for the
// live tenant-owned PostgreSQL schema. subjectTenantOwnedTables derives the
// other side of this comparison from pg_catalog before any row is changed. A
// new tenant table therefore cannot silently inherit a "Complete" receipt: its
// migration must make an explicit delete-vs-project decision here.
//
// Every policy deliberately names only columns whose product contract makes
// them data-subject-bearing. Structured owner/actor identifiers compare exact
// normalized aliases. Escaped substring matching is limited to documented
// free-text/JSON evidence columns. Tables with no first-class subject fields
// say so explicitly; they are never searched with a generic row scan.
// audit_events is projected because mutating an old hash-chain row would
// destroy the evidence.
var subjectPostgresTablePolicies = map[string]subjectTablePolicy{
	"abac_policies": {plane: "postgres:abac_policies", disposition: subjectTableNoSubject},
	"agent_enroll_tokens": {
		plane: "postgres:agent_enroll_tokens", disposition: subjectTableDeleteMatches,
		exact: []string{"id", "agent_id", "created_by", "used_by_agent"},
	},
	"agent_identities": {
		plane: "postgres:agent_identities", disposition: subjectTableDeleteMatches,
		exact: []string{"id", "agent_id", "spiffe_id", "revoked_by"},
	},
	"agents": {
		plane: "postgres:agents", disposition: subjectTableDeleteMatches,
		exact:    []string{"id", "name", "hostname", "spiffe_id"},
		contains: []string{"labels"},
	},
	"ai_answers": {
		plane: "ai_answers", disposition: subjectTableDeleteMatches,
		contains: []string{"question", "root_cause", "payload"},
	},
	"ai_feedback": {
		plane: "postgres:ai_feedback", disposition: subjectTableDeleteMatches,
		exact:    []string{"user_id"},
		contains: []string{"question", "comment"},
	},
	"alert_evaluation_receipts": {
		plane: "postgres:alert_evaluation_receipts", disposition: subjectTableDeleteMatches,
		contains: []string{"labels"},
	},
	"alert_maintenance_windows": {
		plane: "postgres:alert_maintenance_windows", disposition: subjectTableDeleteMatches,
		exact:    []string{"created_by"},
		contains: []string{"match"},
	},
	"alert_ops": {
		plane: "postgres:alert_ops", disposition: subjectTableDeleteMatches,
		exact: []string{"acked_by"},
	},
	"alert_rules":  {plane: "postgres:alert_rules", disposition: subjectTableNoSubject},
	"audit_events": {plane: "audit", disposition: subjectTableProjectMatches},
	"audit_subject_erasures": {
		plane:       "audit:subject_erasure_projection",
		disposition: subjectTableProjectMatches,
	},
	"change_events": {
		plane: "postgres:change_events", disposition: subjectTableDeleteMatches,
		exact:    []string{"actor", "target"},
		contains: []string{"title", "summary", "attributes"},
	},
	"dashboard_report_artifacts": {
		plane: "postgres:dashboard_report_artifacts", disposition: subjectTableDeleteMatches,
		exact: []string{"generated_by"},
	},
	"dashboard_report_schedules": {
		plane: "postgres:dashboard_report_schedules", disposition: subjectTableDeleteMatches,
		exact: []string{"owner_id"},
	},
	"dashboard_views": {
		plane: "postgres:dashboard_views", disposition: subjectTableDeleteMatches,
		exact: []string{"owner_id"},
	},
	"device_collection_outcomes": {
		plane: "postgres:device_collection_outcomes", disposition: subjectTableDeleteMatches,
		exact: []string{"agent_id", "configured_target"},
	},
	"device_neighbor_evidence": {
		plane: "postgres:device_neighbor_evidence", disposition: subjectTableDeleteMatches,
		exact: []string{
			"agent_id", "local_device_address", "local_device_name", "local_port_id",
			"remote_chassis_id", "remote_device_name", "remote_port_id",
			"remote_management_address", "remote_platform",
		},
	},
	"flow_ingest_quality_receipts": {
		plane: "postgres:flow_ingest_quality_receipts", disposition: subjectTableDeleteMatches,
		exact: []string{"agent_id", "exporter_address"},
	},
	"incident_integrations": {plane: "postgres:incident_integrations", disposition: subjectTableNoSubject},
	"incident_journal_entries": {
		plane: "incident_journal", disposition: subjectTableDeleteMatches,
		exact:    []string{"created_by"},
		contains: []string{"body"},
	},
	"incident_share_artifacts": {
		plane: "postgres:incident_share_artifacts", disposition: subjectTableDeleteMatches,
		exact:    []string{"created_by"},
		contains: []string{"payload"},
	},
	"incident_signals": {
		plane: "postgres:incident_signals", disposition: subjectTableDeleteMatches,
		exact:    []string{"target"},
		contains: []string{"title", "summary", "attributes"},
	},
	"ir_attribution_records": {
		plane:       "audit:ir_attribution_encrypted",
		disposition: subjectTableRetainEncryptedEvidence,
	},
	"incidents": {
		plane: "postgres:incidents", disposition: subjectTableDeleteMatches,
		exact:    []string{"target", "prefix"},
		contains: []string{"title"},
	},
	"mcp_tokens": {
		plane: "postgres:mcp_tokens", disposition: subjectTableDeleteMatches,
		exact: []string{"id", "user_id"},
	},
	"organizations": {plane: "postgres:organizations", disposition: subjectTableNoSubject},
	"otlp_tokens":   {plane: "postgres:otlp_tokens", disposition: subjectTableNoSubject},
	"projects":      {plane: "postgres:projects", disposition: subjectTableNoSubject},
	"remediation_proposals": {
		plane: "postgres:remediation_proposals", disposition: subjectTableDeleteMatches,
		exact:    []string{"proposed_by", "decided_by", "target"},
		contains: []string{"rationale", "decision_note", "dry_run"},
	},
	"results": {plane: "postgres:results", disposition: subjectTableNoSubject},
	"role_bindings": {
		plane: "postgres:role_bindings", disposition: subjectTableDeleteMatches,
		exact: []string{"subject_id"},
	},
	"role_permissions": {plane: "postgres:role_permissions", disposition: subjectTableNoSubject},
	"roles":            {plane: "postgres:roles", disposition: subjectTableNoSubject},
	"rollout_events":   {plane: "postgres:rollout_events", disposition: subjectTableNoSubject},
	"rollout_plans":    {plane: "postgres:rollout_plans", disposition: subjectTableNoSubject},
	"scim_tokens":      {plane: "postgres:scim_tokens", disposition: subjectTableNoSubject},
	"service_accounts": {
		plane: "postgres:service_accounts", disposition: subjectTableDeleteMatches,
		exact: []string{"id", "name"},
	},
	"sessions": {
		plane: "postgres:sessions", disposition: subjectTableDeleteMatches,
		exact: []string{"id", "user_id", "email"},
	},
	"siem_delivery": {plane: "postgres:siem_delivery", disposition: subjectTableNoSubject},
	"teams":         {plane: "postgres:teams", disposition: subjectTableNoSubject},
	"tenant_idp":    {plane: "postgres:tenant_idp", disposition: subjectTableNoSubject},
	"tests":         {plane: "postgres:tests", disposition: subjectTableNoSubject},
	"users": {
		plane: "identity", disposition: subjectTableDeleteMatches,
		exact: []string{"id", "email", "user_name", "external_id"},
	},
	"webhook_deliveries": {plane: "postgres:webhook_deliveries", disposition: subjectTableNoSubject},
}

// ExportSubject writes a subject-scoped portability bundle. Reads are tenant
// scoped first; the subject filter is applied only inside the caller's tenant.
func (e *Engine) ExportSubject(ctx context.Context, tenantID, subject string, w io.Writer, redact bool) (SubjectManifest, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return SubjectManifest{}, fmt.Errorf("tenantlife: subject export requires a non-empty subject")
	}
	pol := govern.PolicyFor(ctx, tenantID)
	redact = redact || pol.RedactExport
	if redact && pol.RedactFrom == govern.ClassUnset {
		pol = govern.DefaultPIIPolicy()
	}
	man := SubjectManifest{
		FormatVersion: 1,
		TenantID:      tenantID,
		SubjectHash:   audit.SubjectErasureHash(tenantID, subject),
		ExportedAt:    e.now().UTC(),
		Redacted:      redact,
		Notes: []string{
			"Subject export filters only rows inside this tenant; it is not a cross-tenant search.",
			"Immutable audit rows keep their chain fields but are serialized through the canonical privacy projection; the matching hash-only erasure marker remains portable evidence.",
		},
	}
	if redact {
		man.Notes = append(man.Notes, "This subject export is redacted with the tenant governance policy.")
	}

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	x := subjectExportContext{ctx: ctx, tenantID: tenantID, subject: subject, tw: tw, man: &man, pol: pol, redact: redact}
	for _, step := range []func(*subjectExportContext) error{
		e.exportSubjectPostgres,
		e.exportSubjectFlows,
		e.exportSubjectOtel,
		e.exportSubjectTSDB,
		e.exportSubjectTopology,
		e.exportSubjectEBPF,
		e.exportSubjectEndpoint,
	} {
		if err := step(&x); err != nil {
			return man, err
		}
	}

	mb, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return man, err
	}
	if err := writeTarFile(tw, "manifest.json", mb, man.ExportedAt); err != nil {
		return man, err
	}
	if err := tw.Close(); err != nil {
		return man, err
	}
	if err := gz.Close(); err != nil {
		return man, err
	}
	if e.audit != nil {
		var rows int64
		for _, p := range man.Planes {
			rows += p.Rows
		}
		if err := e.audit(ctx, tenantID, "privacy.subject_export", tenantID, map[string]any{
			"subject_hash": man.SubjectHash, "planes": len(man.Planes), "rows": rows, "redacted": man.Redacted,
		}); err != nil {
			return man, fmt.Errorf("tenantlife: subject export audit append failed: %w", err)
		}
	}
	return man, nil
}

type subjectExportContext struct {
	ctx      context.Context
	tenantID string
	subject  string
	tw       *tar.Writer
	man      *SubjectManifest
	pol      govern.Policy
	redact   bool
}

func (x *subjectExportContext) writeJSONL(path string, buf *bytes.Buffer, rows int64) error {
	if rows == 0 {
		return nil
	}
	out := buf.Bytes()
	if x.redact {
		out = govern.RedactJSONL(x.pol, out)
	}
	return writeTarFile(x.tw, path, out, x.man.ExportedAt)
}

func (e *Engine) exportSubjectPostgres(x *subjectExportContext) error {
	if e.pool == nil {
		return nil
	}
	tables, err := e.tenantOwnedTables(x.ctx)
	if err != nil {
		return err
	}
	classified, err := classifySubjectPostgresTables(tables)
	if err != nil {
		return err
	}
	policies := make(map[string]subjectTablePolicy, len(classified))
	for _, table := range classified {
		policies[table.name] = table.policy
	}
	tctx := tenancy.WithTenant(x.ctx, tenancy.ID(x.tenantID))
	subject := []byte(strings.ToLower(x.subject))
	subjectHash := audit.SubjectErasureHash(x.tenantID, x.subject)
	for _, table := range tables {
		policy := policies[table]
		if policy.disposition == subjectTableRetainEncryptedEvidence {
			x.man.Planes = append(x.man.Planes, SubjectPlaneResult{
				Plane:  policy.plane,
				Status: SubjectStatusRetainedIR,
				Notes:  "excluded from ordinary subject export; retained ciphertext is revealable only through audited IR separation of duty",
			})
			continue
		}
		var buf bytes.Buffer
		var count int64
		err := tenancy.InTenant(tctx, e.pool, func(ctx context.Context, sc tenancy.Scope) error {
			if table == "audit_events" {
				var err error
				count, err = appendProjectedAuditJSONL(
					ctx,
					sc,
					&buf,
					func(event audit.Event, projected []byte) bool {
						if bytes.Contains(
							bytes.ToLower(projected),
							subject,
						) {
							return true
						}
						hash, _ := event.Data["subject_hash"].(string)
						return event.Action == audit.SubjectErasureAction &&
							hash == subjectHash
					},
				)
				return err
			}
			query := `SELECT row_to_json(t) FROM ` + pgIdent(table) + ` t`
			var args []any
			if table == "audit_subject_erasures" {
				// Projection rows intentionally contain no plaintext subject,
				// so generic JSON substring matching can never find them.
				// Match the same tenant-bound one-way hash used at write time;
				// RLS still provides the outer tenant boundary.
				query += ` WHERE subject_hash = $1`
				args = append(args, subjectHash)
			}
			rows, err := sc.Q.Query(ctx, query, args...)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var raw []byte
				if err := rows.Scan(&raw); err != nil {
					return err
				}
				if table != "audit_subject_erasures" &&
					!bytes.Contains(bytes.ToLower(raw), subject) {
					continue
				}
				buf.Write(raw)
				buf.WriteByte('\n')
				count++
			}
			return rows.Err()
		})
		if err != nil {
			return fmt.Errorf("tenantlife: subject export %s: %w", table, err)
		}
		if err := x.writeJSONL("postgres/"+table+".jsonl", &buf, count); err != nil {
			return err
		}
		if count > 0 {
			x.man.Planes = append(x.man.Planes, SubjectPlaneResult{Plane: "postgres:" + table, Status: SubjectStatusExported, Rows: count})
		}
	}
	return nil
}

func (e *Engine) exportSubjectFlows(x *subjectExportContext) error {
	if e.flows == nil {
		x.man.Planes = append(x.man.Planes, SubjectPlaneResult{Plane: "flows", Status: SubjectStatusNotDeployed, Notes: "store not deployed"})
		return nil
	}
	var all, filtered bytes.Buffer
	if _, err := e.flows.ExportTenant(x.ctx, x.tenantID, &all); err != nil {
		return fmt.Errorf("tenantlife: subject export flows: %w", err)
	}
	n := filterJSONLLines(&filtered, all.Bytes(), x.subject)
	if err := x.writeJSONL("flows.jsonl", &filtered, n); err != nil {
		return err
	}
	x.man.Planes = append(x.man.Planes, SubjectPlaneResult{Plane: "flows", Status: SubjectStatusExported, Rows: n})
	return nil
}

func (e *Engine) exportSubjectOtel(x *subjectExportContext) error {
	ox, ok := e.otel.(otelSubjectExporter)
	if e.otel == nil {
		x.man.Planes = append(x.man.Planes, SubjectPlaneResult{Plane: "otel", Status: SubjectStatusNotDeployed, Notes: "store not deployed"})
		return nil
	}
	if !ok {
		x.man.Planes = append(x.man.Planes, SubjectPlaneResult{Plane: "otel", Status: SubjectStatusNotCapable, Notes: "store is deployed but not subject-export capable"})
		return nil
	}
	var spans, logs bytes.Buffer
	sn, ln, err := ox.ExportSubject(x.ctx, x.tenantID, x.subject, &spans, &logs)
	if err != nil {
		return fmt.Errorf("tenantlife: subject export otel: %w", err)
	}
	if err := x.writeJSONL("otel_spans.jsonl", &spans, sn); err != nil {
		return err
	}
	if err := x.writeJSONL("otel_logs.jsonl", &logs, ln); err != nil {
		return err
	}
	x.man.Planes = append(x.man.Planes,
		SubjectPlaneResult{Plane: "otel_spans", Status: SubjectStatusExported, Rows: sn},
		SubjectPlaneResult{Plane: "otel_logs", Status: SubjectStatusExported, Rows: ln})
	return nil
}

func (e *Engine) exportSubjectTSDB(x *subjectExportContext) error {
	tx, ok := e.tsdbW.(tsdbSubjectExporter)
	switch {
	case e.tsdbW == nil:
		x.man.Planes = append(x.man.Planes,
			SubjectPlaneResult{Plane: "tsdb_metrics", Status: SubjectStatusNotDeployed, Notes: "store not deployed"},
			SubjectPlaneResult{Plane: "rum", Status: SubjectStatusNotDeployed, Notes: "RUM metrics store not deployed"},
		)
		return nil
	case !ok:
		x.man.Planes = append(x.man.Planes,
			SubjectPlaneResult{Plane: "tsdb_metrics", Status: SubjectStatusNotCapable, Notes: "remote TSDB exports are aggregate label-set/federation owned; age-out follows the external TSDB retention clock"},
			SubjectPlaneResult{Plane: "rum", Status: SubjectStatusNotCapable, Notes: "RUM is stored as TSDB aggregates; remote TSDB subject export requires operator Prometheus/VictoriaMetrics federation"},
		)
		return nil
	}
	var tsdb bytes.Buffer
	n, err := tx.ExportSubject(x.ctx, x.tenantID, x.subject, &tsdb)
	if err != nil {
		return fmt.Errorf("tenantlife: subject export tsdb: %w", err)
	}
	if err := x.writeJSONL("tsdb_metrics.jsonl", &tsdb, n); err != nil {
		return err
	}
	x.man.Planes = append(x.man.Planes,
		SubjectPlaneResult{Plane: "tsdb_metrics", Status: SubjectStatusExported, Rows: n, Notes: "metric names and label values are subject-filtered inside the tenant"},
		SubjectPlaneResult{Plane: "rum", Status: SubjectStatusCoveredByPlane, Rows: n, Notes: "RUM host/path metrics are covered by tsdb_metrics when their labels match; client IP and user-agent are never stored"},
	)
	return nil
}

func (e *Engine) exportSubjectTopology(x *subjectExportContext) error {
	tx, ok := e.topo.(topologySubjectExporter)
	switch {
	case e.topo == nil:
		x.man.Planes = append(x.man.Planes,
			SubjectPlaneResult{Plane: "topology", Status: SubjectStatusNotDeployed, Notes: "store not deployed"},
			SubjectPlaneResult{Plane: "device", Status: SubjectStatusNotDeployed, Notes: "topology/device graph not deployed"},
		)
		return nil
	case !ok:
		x.man.Planes = append(x.man.Planes,
			SubjectPlaneResult{Plane: "topology", Status: SubjectStatusNotCapable, Notes: "topology store is deployed but not subject-export capable; derived labels age out by retention"},
			SubjectPlaneResult{Plane: "device", Status: SubjectStatusNotCapable, Notes: "device-derived labels are in a topology backend without subject export; age out by retention"},
		)
		return nil
	}
	var topo bytes.Buffer
	nodes, edges, deviceNodes, err := tx.ExportSubject(x.tenantID, x.subject, &topo)
	if err != nil {
		return fmt.Errorf("tenantlife: subject export topology: %w", err)
	}
	if err := x.writeJSONL("topology_subject.jsonl", &topo, nodes+edges); err != nil {
		return err
	}
	x.man.Planes = append(x.man.Planes,
		SubjectPlaneResult{Plane: "topology", Status: SubjectStatusExported, Rows: nodes + edges, Notes: "bounded derived graph labels are subject-filtered inside the tenant"},
		SubjectPlaneResult{Plane: "device", Status: SubjectStatusExported, Rows: deviceNodes, Notes: "device-derived identity labels live in topology device nodes and are counted separately"},
	)
	return nil
}

func (e *Engine) exportSubjectEBPF(x *subjectExportContext) error {
	ex, ok := e.ebpf.(ebpfSubjectExporter)
	switch {
	case e.ebpf == nil:
		x.man.Planes = append(x.man.Planes, SubjectPlaneResult{Plane: "ebpf", Status: SubjectStatusNotDeployed, Notes: "store not deployed"})
		return nil
	case !ok:
		x.man.Planes = append(x.man.Planes, SubjectPlaneResult{Plane: "ebpf", Status: SubjectStatusNotCapable, Notes: "eBPF aggregate backend is deployed but not subject-export capable; age-out follows eBPF retention"})
		return nil
	}
	var ebpf bytes.Buffer
	n, err := ex.ExportSubject(x.ctx, x.tenantID, x.subject, &ebpf)
	if err != nil {
		return fmt.Errorf("tenantlife: subject export ebpf: %w", err)
	}
	if err := x.writeJSONL("ebpf_edges.jsonl", &ebpf, n); err != nil {
		return err
	}
	x.man.Planes = append(x.man.Planes, SubjectPlaneResult{Plane: "ebpf", Status: SubjectStatusExported, Rows: n, Notes: "workload aggregate labels are subject-filtered inside the tenant"})
	return nil
}

func (e *Engine) exportSubjectEndpoint(x *subjectExportContext) error {
	ex, ok := e.endpointRetention.(endpointSubjectExporter)
	switch {
	case e.endpointRetention == nil:
		x.man.Planes = append(x.man.Planes, SubjectPlaneResult{Plane: "endpoint", Status: SubjectStatusNotDeployed, Notes: "store not deployed"})
		return nil
	case !ok:
		x.man.Planes = append(x.man.Planes, SubjectPlaneResult{Plane: "endpoint", Status: SubjectStatusNotCapable, Notes: "endpoint latest-view backend is deployed but not subject-export capable; age-out follows derived identity retention"})
		return nil
	}
	var endpoints bytes.Buffer
	n, err := ex.ExportSubject(x.tenantID, x.subject, &endpoints)
	if err != nil {
		return fmt.Errorf("tenantlife: subject export endpoint: %w", err)
	}
	if err := x.writeJSONL("endpoint_subject.jsonl", &endpoints, n); err != nil {
		return err
	}
	x.man.Planes = append(x.man.Planes, SubjectPlaneResult{Plane: "endpoint", Status: SubjectStatusExported, Rows: n, Notes: "bounded endpoint latest-view labels are subject-filtered inside the tenant"})
	return nil
}

// EraseSubject runs the subject erasure workflow across every classified
// tenant-owned PostgreSQL table plus the attached telemetry planes. It never
// rewrites audit history; append-only markers make future audit reads/exports
// project the subject and its stable aliases while preserving prev_hash/hash.
func (e *Engine) EraseSubject(ctx context.Context, tenantID, subject, actor, reason string) (SubjectErasureReport, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return SubjectErasureReport{}, fmt.Errorf("tenantlife: subject erasure requires a non-empty subject")
	}
	if actor == "" {
		actor = "system"
	}
	rep := SubjectErasureReport{
		FormatVersion: 1,
		TenantID:      tenantID,
		SubjectHash:   audit.SubjectErasureHash(tenantID, subject),
		Actor:         actor,
		Reason:        strings.TrimSpace(reason),
		StartedAt:     e.now().UTC(),
		Complete:      true,
	}
	fail := func(plane, note string) {
		rep.Planes = append(rep.Planes, SubjectPlaneResult{Plane: plane, Status: SubjectStatusFailed, Remaining: -1, Notes: note})
		rep.Complete = false
	}

	destructiveSubjectValidated := false
	if e.pool != nil {
		deleted, aliases, err := e.eraseSubjectPostgres(
			ctx,
			tenantID,
			subject,
			actor,
			reason,
		)
		if err != nil {
			fail("postgres", err.Error())
		} else {
			rep.Planes = append(rep.Planes, deleted...)
			destructiveSubjectValidated = true
			rep.Planes = append(rep.Planes, SubjectPlaneResult{
				Plane: "audit", Status: SubjectStatusProjected, Projected: true,
				Notes: fmt.Sprintf("append-only privacy.subject_erase markers recorded atomically for %d stable subject aliases", len(aliases)),
			})
		}
	} else {
		rep.Planes = append(rep.Planes, SubjectPlaneResult{Plane: "postgres", Status: SubjectStatusNotDeployed, Notes: "store not deployed"})
		if isSafeContainsIdentifier(subject) {
			destructiveSubjectValidated = true
		} else {
			fail(
				"subject_validation",
				"subject does not resolve through a deployed directory and is not an unambiguous email, UUID, IP address, or URI",
			)
		}
	}

	// A failed directory/schema validation is an authorization failure for the
	// destructive selector, not permission to try the same unsafe substring in
	// less-structured telemetry stores. Preserve the failed request on the
	// provider audit stream, but do not mutate any downstream plane.
	if !destructiveSubjectValidated {
		return e.finalizeSubjectErasureReport(ctx, actor, rep)
	}

	if fd, ok := e.flows.(flowSubjectDeleter); ok {
		deleted, remaining, err := fd.DeleteSubject(ctx, tenantID, subject)
		if err != nil {
			fail("flows", err.Error())
		} else {
			rep.Planes = append(rep.Planes, SubjectPlaneResult{Plane: "flows", Status: SubjectStatusDeleted, Deleted: deleted, Remaining: remaining})
			if remaining != 0 {
				rep.Complete = false
			}
		}
	} else if e.flows == nil {
		rep.Planes = append(rep.Planes, SubjectPlaneResult{Plane: "flows", Status: SubjectStatusNotDeployed, Notes: "store not deployed"})
	} else {
		fail("flows", "store is deployed but not subject-erase capable")
	}

	if od, ok := e.otel.(otelSubjectDeleter); ok {
		deleted, remaining, err := od.EraseSubject(ctx, tenantID, subject)
		if err != nil {
			fail("otel", err.Error())
		} else {
			rep.Planes = append(rep.Planes, SubjectPlaneResult{Plane: "otel", Status: SubjectStatusDeleted, Deleted: int64(deleted), Remaining: int64(remaining)})
			if remaining != 0 {
				rep.Complete = false
			}
		}
	} else if e.otel == nil {
		rep.Planes = append(rep.Planes, SubjectPlaneResult{Plane: "otel", Status: SubjectStatusNotDeployed, Notes: "store not deployed"})
	} else {
		fail("otel", "store is deployed but not subject-erase capable")
	}
	if td, ok := e.tsdbW.(tsdbSubjectDeleter); ok {
		deleted, remaining, err := td.DeleteSubject(ctx, tenantID, subject)
		if err != nil {
			fail("tsdb_metrics", err.Error())
		} else {
			rep.Planes = append(rep.Planes,
				SubjectPlaneResult{Plane: "tsdb_metrics", Status: SubjectStatusDeleted, Deleted: deleted, Remaining: remaining, Notes: "metric names and label values are subject-filtered inside the tenant"},
				SubjectPlaneResult{Plane: "rum", Status: SubjectStatusCoveredByPlane, Deleted: deleted, Remaining: remaining, Notes: "RUM host/path metrics are covered by tsdb_metrics; raw browser IP and user-agent are never stored"},
			)
			if remaining != 0 {
				rep.Complete = false
			}
		}
	} else if e.tsdbW == nil {
		rep.Planes = append(rep.Planes,
			SubjectPlaneResult{Plane: "tsdb_metrics", Status: SubjectStatusNotDeployed, Notes: "store not deployed"},
			SubjectPlaneResult{Plane: "rum", Status: SubjectStatusNotDeployed, Notes: "RUM metrics store not deployed"},
		)
	} else {
		rep.Planes = append(rep.Planes,
			SubjectPlaneResult{Plane: "tsdb_metrics", Status: SubjectStatusNotCapable, Notes: "remote TSDB subject deletion requires operator delete_series by exported label-set or retention age-out"},
			SubjectPlaneResult{Plane: "rum", Status: SubjectStatusNotCapable, Notes: "RUM is stored as TSDB aggregates; remote TSDB deletion follows TSDB delete_series/retention"},
		)
	}
	if td, ok := e.topo.(topologySubjectDeleter); ok {
		deleted, remaining, deviceDeleted, deviceRemaining := td.DeleteSubject(tenantID, subject)
		rep.Planes = append(rep.Planes,
			SubjectPlaneResult{Plane: "topology", Status: SubjectStatusDeleted, Deleted: deleted, Remaining: remaining, Notes: "bounded derived graph labels are subject-filtered inside the tenant"},
			SubjectPlaneResult{Plane: "device", Status: SubjectStatusDeleted, Deleted: deviceDeleted, Remaining: deviceRemaining, Notes: "device-derived identity labels live in topology device nodes and are counted separately"},
		)
		if remaining != 0 || deviceRemaining != 0 {
			rep.Complete = false
		}
	} else if e.topo == nil {
		rep.Planes = append(rep.Planes,
			SubjectPlaneResult{Plane: "topology", Status: SubjectStatusNotDeployed, Notes: "store not deployed"},
			SubjectPlaneResult{Plane: "device", Status: SubjectStatusNotDeployed, Notes: "topology/device graph not deployed"},
		)
	} else {
		rep.Planes = append(rep.Planes,
			SubjectPlaneResult{Plane: "topology", Status: SubjectStatusNotCapable, Notes: "topology store is deployed but not subject-erase capable; derived labels age out by retention"},
			SubjectPlaneResult{Plane: "device", Status: SubjectStatusNotCapable, Notes: "device-derived labels are in a topology backend without subject erase; age out by retention"},
		)
	}
	if ed, ok := e.ebpf.(ebpfSubjectDeleter); ok {
		deleted, remaining, err := ed.DeleteSubject(ctx, tenantID, subject)
		if err != nil {
			fail("ebpf", err.Error())
		} else {
			rep.Planes = append(rep.Planes, SubjectPlaneResult{Plane: "ebpf", Status: SubjectStatusDeleted, Deleted: deleted, Remaining: remaining, Notes: "workload aggregate labels are subject-filtered inside the tenant"})
			if remaining != 0 {
				rep.Complete = false
			}
		}
	} else if e.ebpf == nil {
		rep.Planes = append(rep.Planes, SubjectPlaneResult{Plane: "ebpf", Status: SubjectStatusNotDeployed, Notes: "store not deployed"})
	} else {
		rep.Planes = append(rep.Planes, SubjectPlaneResult{Plane: "ebpf", Status: SubjectStatusNotCapable, Notes: "eBPF aggregate backend is deployed but not subject-erase capable; age-out follows eBPF retention"})
	}
	if ed, ok := e.endpointRetention.(endpointSubjectDeleter); ok {
		deleted, remaining := ed.DeleteSubject(tenantID, subject)
		rep.Planes = append(rep.Planes, SubjectPlaneResult{Plane: "endpoint", Status: SubjectStatusDeleted, Deleted: deleted, Remaining: remaining, Notes: "bounded endpoint latest-view labels are subject-filtered inside the tenant"})
		if remaining != 0 {
			rep.Complete = false
		}
	} else if e.endpointRetention == nil {
		rep.Planes = append(rep.Planes, SubjectPlaneResult{Plane: "endpoint", Status: SubjectStatusNotDeployed, Notes: "store not deployed"})
	} else {
		rep.Planes = append(rep.Planes, SubjectPlaneResult{Plane: "endpoint", Status: SubjectStatusNotCapable, Notes: "endpoint latest-view backend is deployed but not subject-erase capable; age-out follows derived identity retention"})
	}

	// Derive completeness from the final plane receipts instead of relying on
	// every branch to remember a side effect. This is fail closed for deployed
	// backends that honestly report not_capable and for any future unknown
	// erasure status.
	return e.finalizeSubjectErasureReport(ctx, actor, rep)
}

func (e *Engine) finalizeSubjectErasureReport(
	ctx context.Context,
	actor string,
	rep SubjectErasureReport,
) (SubjectErasureReport, error) {
	rep.Complete = subjectErasurePlanesComplete(rep.Planes)
	rep.FinishedAt = e.now().UTC()
	rep.ReportSHA256 = rep.hash()
	if e.audit != nil {
		if err := e.audit(ctx, actor, "privacy.subject_erase", rep.TenantID, map[string]any{
			"subject_hash": rep.SubjectHash, "complete": rep.Complete, "report_sha256": rep.ReportSHA256,
			"planes": len(rep.Planes),
		}); err != nil {
			return rep, fmt.Errorf("tenantlife: subject erasure audit append failed: %w", err)
		}
	}
	return rep, nil
}

func subjectErasurePlanesComplete(planes []SubjectPlaneResult) bool {
	if len(planes) == 0 {
		return false
	}
	for _, plane := range planes {
		if plane.Remaining != 0 {
			return false
		}
		switch plane.Status {
		case SubjectStatusDeleted,
			SubjectStatusCoveredByPlane,
			SubjectStatusRetainedIR,
			SubjectStatusProjected,
			SubjectStatusNotDeployed:
			// These statuses either prove the subject is gone from a deployed
			// plane, explicitly preserve separately encrypted evidence, or
			// state that no such plane exists in this deployment.
		default:
			return false
		}
	}
	return true
}

func (e *Engine) eraseSubjectPostgres(
	ctx context.Context,
	tenantID, subject, actor, reason string,
) ([]SubjectPlaneResult, []string, error) {
	tctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	var (
		out     []SubjectPlaneResult
		aliases = newSubjectAliasSet(subject)
	)
	err := tenancy.InTenant(tctx, e.pool, func(ctx context.Context, sc tenancy.Scope) error {
		// Ordinary audited mutations lock the tenant audit stream before their
		// subject-bearing rows. Taking that same lock before catalog discovery
		// and deletion prevents the inverse row-lock → audit-lock order.
		if err := audit.LockTenantStream(ctx, sc.Q, tenantID); err != nil {
			return fmt.Errorf("lock tenant audit stream before subject erasure: %w", err)
		}
		liveTables, err := subjectTenantOwnedTables(ctx, sc)
		if err != nil {
			return fmt.Errorf("discover tenant-owned tables: %w", err)
		}
		classified, err := classifySubjectPostgresTables(liveTables)
		if err != nil {
			return err
		}

		captured, err := e.captureSubjectAliases(ctx, sc, subject)
		if err != nil {
			return err
		}
		aliases = captured.aliases
		exactAliases := aliases.normalizedValues()
		containsPatterns := aliases.safeContainsPatterns()

		locatorsDeleted, err := store.DeleteSubjectCredentialLocatorsScoped(
			ctx, sc, captured.sessionIDs, captured.mcpTokenIDs,
		)
		if err != nil {
			return fmt.Errorf("erase subject credential locators: %w", err)
		}
		out = append(out, SubjectPlaneResult{
			Plane: "postgres:credential_locators", Status: SubjectStatusDeleted,
			Deleted: locatorsDeleted, Remaining: 0,
			Notes: "tenant-GUC-checked global session/MCP locators removed by captured credential UUID",
		})

		for _, table := range classified {
			switch table.policy.disposition {
			case subjectTableProjectMatches:
				continue
			case subjectTableNoSubject:
				out = append(out, SubjectPlaneResult{
					Plane: table.policy.plane, Status: SubjectStatusCoveredByPlane,
					Notes: "live-schema policy declares no first-class data-subject field",
				})
				continue
			case subjectTableRetainEncryptedEvidence:
				out = append(out, SubjectPlaneResult{
					Plane: table.policy.plane, Status: SubjectStatusRetainedIR,
					Notes: "encrypted incident-response evidence retained; ordinary subject lifecycle cannot read, decrypt, or delete it",
				})
				continue
			}
			ident := pgIdent(table.name)
			predicate := subjectTableMatchPredicate(table.policy)
			tag, err := sc.Q.Exec(ctx,
				`DELETE FROM `+ident+` AS subject_row
				  WHERE subject_row.tenant_id = $1
				    AND `+predicate,
				tenantID, exactAliases, containsPatterns)
			if err != nil {
				return fmt.Errorf("erase classified subject rows from %s: %w", table.name, err)
			}
			var remaining int64
			if err := sc.Q.QueryRow(ctx,
				`SELECT count(*) FROM `+ident+` AS subject_row
				  WHERE subject_row.tenant_id = $1
				    AND `+predicate,
				tenantID, exactAliases, containsPatterns).Scan(&remaining); err != nil {
				return fmt.Errorf("verify classified subject rows in %s: %w", table.name, err)
			}
			out = append(out, SubjectPlaneResult{
				Plane: table.policy.plane, Status: SubjectStatusDeleted,
				Deleted: tag.RowsAffected(), Remaining: remaining,
				Notes: "explicit subject columns count-verified after deletion",
			})
			if remaining != 0 {
				return fmt.Errorf("verify classified subject rows in %s: %d remain", table.name, remaining)
			}
		}

		// Re-read the catalog before commit. PostgreSQL READ COMMITTED sees a
		// table added by a concurrent migration; returning an error rolls every
		// deletion back rather than certifying a stale schema snapshot.
		afterTables, err := subjectTenantOwnedTables(ctx, sc)
		if err != nil {
			return fmt.Errorf("recheck tenant-owned tables: %w", err)
		}
		if !equalStringSets(liveTables, afterTables) {
			return fmt.Errorf("tenantlife: tenant-owned table set changed during subject erasure")
		}
		if e.appendSubjectErasure == nil {
			return fmt.Errorf("tenantlife: subject erasure audit appender is unavailable")
		}
		for _, alias := range aliases.values() {
			if _, err := e.appendSubjectErasure(
				ctx,
				sc,
				actor,
				alias,
				reason,
			); err != nil {
				return fmt.Errorf(
					"record subject erasure for stable alias: %w",
					err,
				)
			}
		}
		return nil
	})
	return out, aliases.values(), err
}

type classifiedSubjectTable struct {
	name   string
	policy subjectTablePolicy
}

func classifySubjectPostgresTables(tables []string) ([]classifiedSubjectTable, error) {
	classified := make([]classifiedSubjectTable, 0, len(tables))
	var unknown []string
	for _, table := range tables {
		policy, ok := subjectPostgresTablePolicies[table]
		if !ok {
			unknown = append(unknown, table)
			continue
		}
		var valid bool
		switch policy.disposition {
		case subjectTableDeleteMatches:
			valid = len(policy.exact)+len(policy.contains) > 0
		case subjectTableProjectMatches,
			subjectTableNoSubject,
			subjectTableRetainEncryptedEvidence:
			valid = len(policy.exact) == 0 && len(policy.contains) == 0
		default:
			valid = false
		}
		if !valid || strings.TrimSpace(policy.plane) == "" {
			unknown = append(unknown, table)
			continue
		}
		classified = append(classified, classifiedSubjectTable{name: table, policy: policy})
	}
	if len(unknown) != 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf(
			"tenantlife: subject erasure refuses unclassified tenant-owned tables: %s",
			strings.Join(unknown, ", "),
		)
	}
	sort.Slice(classified, func(i, j int) bool {
		return subjectTableSortKey(classified[i].name) < subjectTableSortKey(classified[j].name)
	})
	return classified, nil
}

func subjectTableSortKey(table string) string {
	// Delete a subject-owned dashboard view first so its CASCADE removes
	// schedules/artifacts without tripping the artifact->schedule RESTRICT edge.
	switch table {
	case "dashboard_views":
		return "dashboard_0_views"
	case "dashboard_report_artifacts":
		return "dashboard_1_report_artifacts"
	case "dashboard_report_schedules":
		return "dashboard_2_report_schedules"
	default:
		return table
	}
}

func subjectTableMatchPredicate(policy subjectTablePolicy) string {
	// Reference both arrays for every policy so the prepared statement has a
	// stable three-argument shape even when this table uses only one match mode.
	var parts []string
	if len(policy.exact) == 0 {
		parts = append(parts, `($2::text[] IS NULL AND FALSE)`)
	}
	if len(policy.contains) == 0 {
		parts = append(parts, `($3::text[] IS NULL AND FALSE)`)
	}
	for _, column := range policy.exact {
		parts = append(parts,
			`lower(COALESCE(subject_row.`+pgIdent(column)+`::text, '')) = ANY($2::text[])`)
	}
	for _, column := range policy.contains {
		parts = append(parts, `EXISTS (
	SELECT 1
	  FROM unnest($3::text[]) AS subject_pattern(value)
	 WHERE COALESCE(subject_row.`+pgIdent(column)+`::text, '') ILIKE subject_pattern.value ESCAPE '!'
)`)
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

// subjectTenantOwnedTables uses pg_catalog rather than information_schema so
// tables remain visible even when a migration accidentally omitted an app-role
// grant. A silo must have the same filtered tenant-table set as the public
// template: otherwise search_path could fall through to a pooled table while a
// silo-only table escaped the inventory. Drift fails before any deletion.
func subjectTenantOwnedTables(ctx context.Context, sc tenancy.Scope) ([]string, error) {
	var activeSchema string
	if err := sc.Q.QueryRow(ctx, `SELECT current_schema()`).Scan(&activeSchema); err != nil {
		return nil, fmt.Errorf("resolve active tenant schema: %w", err)
	}
	if strings.TrimSpace(activeSchema) == "" {
		return nil, fmt.Errorf("tenantlife: active tenant schema is empty")
	}

	active, err := subjectTenantOwnedTablesInSchema(ctx, sc, activeSchema)
	if err != nil {
		return nil, fmt.Errorf("inventory active tenant schema %q: %w", activeSchema, err)
	}
	if activeSchema == "public" {
		return active, nil
	}
	publicTemplate, err := subjectTenantOwnedTablesInSchema(ctx, sc, "public")
	if err != nil {
		return nil, fmt.Errorf("inventory public tenant-table template: %w", err)
	}
	if !equalStringSets(active, publicTemplate) {
		return nil, fmt.Errorf(
			"tenantlife: active tenant schema %q drifts from public tenant-table template (missing=%s extra=%s)",
			activeSchema,
			strings.Join(stringSetDifference(publicTemplate, active), ","),
			strings.Join(stringSetDifference(active, publicTemplate), ","),
		)
	}
	return active, nil
}

func subjectTenantOwnedTablesInSchema(
	ctx context.Context,
	sc tenancy.Scope,
	schema string,
) ([]string, error) {
	rows, err := sc.Q.Query(ctx, `
		SELECT DISTINCT c.relname
		  FROM pg_catalog.pg_class AS c
		  JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
		  JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid
		 WHERE n.nspname = $1
		   AND c.relkind IN ('r', 'p')
		   AND a.attname = 'tenant_id'
		   AND NOT a.attisdropped
		 ORDER BY c.relname`,
		schema)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			return nil, err
		}
		tables = append(tables, table)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tenancy.FilterTenantOwned(tables), nil
}

func stringSetDifference(left, right []string) []string {
	present := make(map[string]struct{}, len(right))
	for _, value := range right {
		present[value] = struct{}{}
	}
	var difference []string
	for _, value := range left {
		if _, ok := present[value]; !ok {
			difference = append(difference, value)
		}
	}
	sort.Strings(difference)
	return difference
}

type subjectAliasSet struct {
	valuesByNormalized map[string]string
}

func newSubjectAliasSet(subject string) subjectAliasSet {
	aliases := subjectAliasSet{valuesByNormalized: map[string]string{}}
	aliases.add(subject)
	return aliases
}

func (a *subjectAliasSet) add(value string) {
	value = strings.TrimSpace(value)
	normalized := strings.ToLower(value)
	if normalized == "" {
		return
	}
	if _, exists := a.valuesByNormalized[normalized]; !exists {
		a.valuesByNormalized[normalized] = value
	}
}

func (a subjectAliasSet) values() []string {
	normalized := make([]string, 0, len(a.valuesByNormalized))
	for value := range a.valuesByNormalized {
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	out := make([]string, 0, len(normalized))
	for _, value := range normalized {
		out = append(out, a.valuesByNormalized[value])
	}
	return out
}

func (a subjectAliasSet) normalizedValues() []string {
	out := make([]string, 0, len(a.valuesByNormalized))
	for value := range a.valuesByNormalized {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func (a subjectAliasSet) safeContainsPatterns() []string {
	values := a.values()
	out := make([]string, 0, len(values))
	for _, value := range values {
		if isSafeContainsIdentifier(value) {
			out = append(out, literalILikeContainsPattern(value))
		}
	}
	return out
}

type capturedSubjectAliases struct {
	aliases     subjectAliasSet
	sessionIDs  []string
	mcpTokenIDs []string
}

type subjectIdentity struct {
	kind       string
	id         string
	email      string
	userName   string
	externalID string
	name       string
}

// captureSubjectAliases resolves a caller-supplied subject to stable directory
// aliases before deleting the primary identity row. This is what lets feedback,
// dashboards, shares, RBAC bindings, and other tables that store only the user
// UUID get erased when the request was made with an email (and vice versa).
func (e *Engine) captureSubjectAliases(
	ctx context.Context,
	sc tenancy.Scope,
	subject string,
) (capturedSubjectAliases, error) {
	aliases := newSubjectAliasSet(subject)
	captured := capturedSubjectAliases{aliases: aliases}
	normalizedSubject := strings.ToLower(strings.TrimSpace(subject))
	var identities []subjectIdentity

	exists, err := e.subjectTableExists(ctx, sc, "users")
	if err != nil {
		return captured, fmt.Errorf("discover users table: %w", err)
	}
	if !exists {
		return captured, fmt.Errorf("tenantlife: users table is missing from tenant schema")
	}
	rows, err := sc.Q.Query(ctx, `
		SELECT id::text, email, COALESCE(user_name, ''), COALESCE(external_id, '')
		  FROM users
		 WHERE lower(id::text) = $1
		    OR lower(email) = $1
		    OR lower(COALESCE(user_name, '')) = $1
		    OR lower(COALESCE(external_id, '')) = $1`,
		normalizedSubject)
	if err != nil {
		return captured, fmt.Errorf("capture user subject aliases: %w", err)
	}
	for rows.Next() {
		var id, email, userName, externalID string
		if err := rows.Scan(&id, &email, &userName, &externalID); err != nil {
			rows.Close()
			return captured, err
		}
		identities = append(identities, subjectIdentity{
			kind: "user", id: id, email: email, userName: userName, externalID: externalID,
		})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return captured, err
	}
	rows.Close()

	exists, err = e.subjectTableExists(ctx, sc, "service_accounts")
	if err != nil {
		return captured, fmt.Errorf("discover service_accounts table: %w", err)
	}
	if !exists {
		return captured, fmt.Errorf("tenantlife: service_accounts table is missing from tenant schema")
	}
	rows, err = sc.Q.Query(ctx, `
		SELECT id::text, name
		  FROM service_accounts
		 WHERE lower(id::text) = $1 OR lower(name) = $1`,
		normalizedSubject)
	if err != nil {
		return captured, fmt.Errorf("capture service-account subject aliases: %w", err)
	}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			return captured, err
		}
		identities = append(identities, subjectIdentity{kind: "service_account", id: id, name: name})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return captured, err
	}
	rows.Close()

	if len(identities) > 1 {
		return captured, fmt.Errorf(
			"tenantlife: subject identifier is ambiguous across %d directory identities; use an exact UUID",
			len(identities),
		)
	}
	if len(identities) == 0 && !isSafeContainsIdentifier(subject) {
		return captured, fmt.Errorf(
			"tenantlife: subject does not resolve to one exact identity and is not an unambiguous email, UUID, IP address, or URI",
		)
	}
	if len(identities) == 1 {
		identity := identities[0]
		aliases.add(identity.id)
		if identity.kind == "user" {
			aliases.add(identity.email)
			aliases.add(identity.userName)
			aliases.add(identity.externalID)
		} else {
			aliases.add(identity.name)
		}
	}

	// Locator rows added for silo-safe pre-tenant authentication reference a
	// credential UUID, not the owning user UUID. Capture those credential IDs
	// while the detailed session/token rows still exist.
	for _, credentialTable := range []struct {
		name string
		sql  string
		dst  *[]string
	}{
		{
			name: "sessions",
			sql: `SELECT id::text FROM sessions
			       WHERE lower(id::text) = ANY($1::text[])
			          OR lower(user_id::text) = ANY($1::text[])
			          OR lower(email) = ANY($1::text[])`,
			dst: &captured.sessionIDs,
		},
		{
			name: "mcp_tokens",
			sql: `SELECT id::text FROM mcp_tokens
			       WHERE lower(id::text) = ANY($1::text[])
			          OR lower(user_id::text) = ANY($1::text[])`,
			dst: &captured.mcpTokenIDs,
		},
	} {
		exists, err = e.subjectTableExists(ctx, sc, credentialTable.name)
		if err != nil {
			return captured, fmt.Errorf("discover %s table: %w", credentialTable.name, err)
		}
		if !exists {
			return captured, fmt.Errorf("tenantlife: %s table is missing from tenant schema", credentialTable.name)
		}
		rows, err = sc.Q.Query(ctx, credentialTable.sql, aliases.normalizedValues())
		if err != nil {
			return captured, fmt.Errorf("capture %s subject aliases: %w", credentialTable.name, err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return captured, err
			}
			*credentialTable.dst = append(*credentialTable.dst, id)
			aliases.add(id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return captured, err
		}
		rows.Close()
	}
	sort.Strings(captured.sessionIDs)
	sort.Strings(captured.mcpTokenIDs)
	captured.aliases = aliases
	return captured, nil
}

func isSafeContainsIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 8 || strings.IndexFunc(value, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) >= 0 {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return true
	}
	if isUUIDString(value) {
		return true
	}
	if strings.Contains(value, "@") {
		return true
	}
	return strings.Contains(value, "://")
}

func isUUIDString(value string) bool {
	if len(value) != 36 ||
		value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	left := append([]string(nil), a...)
	right := append([]string(nil), b...)
	sort.Strings(left)
	sort.Strings(right)
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// literalILikeContainsPattern builds a case-insensitive substring pattern while
// keeping caller-controlled LIKE metacharacters literal. The SQL comparisons
// declare "!" as their ESCAPE character, so escape it before "%" and "_".
func literalILikeContainsPattern(value string) string {
	escaped := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(value)
	return "%" + escaped + "%"
}

func tableExists(ctx context.Context, sc tenancy.Scope, table string) (bool, error) {
	var ok bool
	if err := sc.Q.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&ok); err != nil {
		return false, err
	}
	return ok, nil
}

func (r SubjectErasureReport) hash() string {
	cp := r
	cp.ReportSHA256 = ""
	b, _ := json.Marshal(cp)
	return hex.EncodeToString(crypto.Hash(b))
}

func filterJSONLLines(w io.Writer, b []byte, subject string) int64 {
	subject = strings.ToLower(strings.TrimSpace(subject))
	var n int64
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if !bytes.Contains(bytes.ToLower(line), []byte(subject)) {
			continue
		}
		_, _ = w.Write(line)
		_, _ = w.Write([]byte{'\n'})
		n++
	}
	return n
}
