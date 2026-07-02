// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/govern"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
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
// copies age out under the tenant backup policy. The report is still hashed and
// audited so the request has a durable proof.
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
			"Immutable audit rows are exported as evidence; subject erasure uses an append-only projection marker instead of rewriting the hash chain.",
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
	tctx := tenancy.WithTenant(x.ctx, tenancy.ID(x.tenantID))
	subject := []byte(strings.ToLower(x.subject))
	for _, table := range tables {
		var buf bytes.Buffer
		var count int64
		err := tenancy.InTenant(tctx, e.pool, func(ctx context.Context, sc tenancy.Scope) error {
			rows, err := sc.Q.Query(ctx, `SELECT row_to_json(t) FROM `+pgIdent(table)+` t`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var raw []byte
				if err := rows.Scan(&raw); err != nil {
					return err
				}
				if !bytes.Contains(bytes.ToLower(raw), subject) {
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

// EraseSubject runs the subject erasure workflow across identity, persisted AI,
// audit projection, flow telemetry, and OTLP telemetry. It never rewrites audit
// history; the append-only marker makes future audit reads/exports project the
// subject while preserving prev_hash/hash.
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

	if e.pool != nil {
		deleted, err := e.eraseSubjectPostgres(ctx, tenantID, subject)
		if err != nil {
			fail("postgres", err.Error())
		} else {
			rep.Planes = append(rep.Planes, deleted...)
		}
		tctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
		if err := tenancy.InTenant(tctx, e.pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := audit.RecordSubjectErasure(ctx, sc, actor, subject, reason)
			return err
		}); err != nil {
			fail("audit", "subject marker failed: "+err.Error())
		} else {
			rep.Planes = append(rep.Planes, SubjectPlaneResult{Plane: "audit", Status: SubjectStatusProjected, Projected: true, Notes: "append-only privacy.subject_erase marker recorded"})
		}
	} else {
		rep.Planes = append(rep.Planes, SubjectPlaneResult{Plane: "postgres", Status: SubjectStatusNotDeployed, Notes: "store not deployed"})
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

	rep.FinishedAt = e.now().UTC()
	rep.ReportSHA256 = rep.hash()
	if e.audit != nil {
		if err := e.audit(ctx, actor, "privacy.subject_erase", tenantID, map[string]any{
			"subject_hash": rep.SubjectHash, "complete": rep.Complete, "report_sha256": rep.ReportSHA256,
			"planes": len(rep.Planes),
		}); err != nil {
			return rep, fmt.Errorf("tenantlife: subject erasure audit append failed: %w", err)
		}
	}
	return rep, nil
}

func (e *Engine) eraseSubjectPostgres(ctx context.Context, tenantID, subject string) ([]SubjectPlaneResult, error) {
	tctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	var out []SubjectPlaneResult
	like := "%" + subject + "%"
	err := tenancy.InTenant(tctx, e.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if tableExists(ctx, sc, "users") {
			tag, err := sc.Q.Exec(ctx, `
DELETE FROM users
 WHERE email ILIKE $1 OR display_name ILIKE $1 OR user_name ILIKE $1
    OR external_id ILIKE $1 OR attributes::text ILIKE $1`, like)
			if err != nil {
				return err
			}
			out = append(out, SubjectPlaneResult{Plane: "identity", Status: SubjectStatusDeleted, Deleted: tag.RowsAffected()})
		}
		if tableExists(ctx, sc, "ai_answers") {
			tag, err := sc.Q.Exec(ctx, `
DELETE FROM ai_answers
 WHERE question ILIKE $1 OR root_cause ILIKE $1 OR payload::text ILIKE $1`, like)
			if err != nil {
				return err
			}
			out = append(out, SubjectPlaneResult{Plane: "ai_answers", Status: SubjectStatusDeleted, Deleted: tag.RowsAffected()})
		}
		return nil
	})
	return out, err
}

func tableExists(ctx context.Context, sc tenancy.Scope, table string) bool {
	var ok bool
	_ = sc.Q.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&ok)
	return ok
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
