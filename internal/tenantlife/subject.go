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

	if e.pool != nil {
		tables, err := e.tenantOwnedTables(ctx)
		if err != nil {
			return man, err
		}
		tctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
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
					if !bytes.Contains(bytes.ToLower(raw), []byte(strings.ToLower(subject))) {
						continue
					}
					buf.Write(raw)
					buf.WriteByte('\n')
					count++
				}
				return rows.Err()
			})
			if err != nil {
				return man, fmt.Errorf("tenantlife: subject export %s: %w", table, err)
			}
			if count == 0 {
				continue
			}
			out := buf.Bytes()
			if redact {
				out = govern.RedactJSONL(pol, out)
			}
			if err := writeTarFile(tw, "postgres/"+table+".jsonl", out, man.ExportedAt); err != nil {
				return man, err
			}
			man.Planes = append(man.Planes, SubjectPlaneResult{Plane: "postgres:" + table, Status: SubjectStatusExported, Rows: count})
		}
	}

	if e.flows != nil {
		var all, filtered bytes.Buffer
		if _, err := e.flows.ExportTenant(ctx, tenantID, &all); err != nil {
			return man, fmt.Errorf("tenantlife: subject export flows: %w", err)
		}
		n := filterJSONLLines(&filtered, all.Bytes(), subject)
		out := filtered.Bytes()
		if redact {
			out = govern.RedactJSONL(pol, out)
		}
		if n > 0 {
			if err := writeTarFile(tw, "flows.jsonl", out, man.ExportedAt); err != nil {
				return man, err
			}
		}
		man.Planes = append(man.Planes, SubjectPlaneResult{Plane: "flows", Status: SubjectStatusExported, Rows: n})
	} else {
		man.Planes = append(man.Planes, SubjectPlaneResult{Plane: "flows", Status: SubjectStatusNotDeployed, Notes: "store not deployed"})
	}

	if ox, ok := e.otel.(otelSubjectExporter); ok {
		var spans, logs bytes.Buffer
		sn, ln, err := ox.ExportSubject(ctx, tenantID, subject, &spans, &logs)
		if err != nil {
			return man, fmt.Errorf("tenantlife: subject export otel: %w", err)
		}
		if sn > 0 {
			out := spans.Bytes()
			if redact {
				out = govern.RedactJSONL(pol, out)
			}
			if err := writeTarFile(tw, "otel_spans.jsonl", out, man.ExportedAt); err != nil {
				return man, err
			}
		}
		if ln > 0 {
			out := logs.Bytes()
			if redact {
				out = govern.RedactJSONL(pol, out)
			}
			if err := writeTarFile(tw, "otel_logs.jsonl", out, man.ExportedAt); err != nil {
				return man, err
			}
		}
		man.Planes = append(man.Planes,
			SubjectPlaneResult{Plane: "otel_spans", Status: SubjectStatusExported, Rows: sn},
			SubjectPlaneResult{Plane: "otel_logs", Status: SubjectStatusExported, Rows: ln})
	} else if e.otel == nil {
		man.Planes = append(man.Planes, SubjectPlaneResult{Plane: "otel", Status: SubjectStatusNotDeployed, Notes: "store not deployed"})
	} else {
		man.Planes = append(man.Planes, SubjectPlaneResult{Plane: "otel", Status: SubjectStatusNotCapable, Notes: "store is deployed but not subject-export capable"})
	}
	man.Planes = append(man.Planes, e.subjectNonAddressablePlanes()...)

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
	rep.Planes = append(rep.Planes, e.subjectNonAddressablePlanes()...)

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

func (e *Engine) subjectNonAddressablePlanes() []SubjectPlaneResult {
	return []SubjectPlaneResult{
		e.subjectDerivedPlane("topology", e.topo != nil,
			"derived graph labels are not a subject-indexed store; source telemetry and tenant erasure own deletion"),
		e.subjectDerivedPlane("ebpf", e.ebpf != nil,
			"eBPF service-edge aggregates are workload aggregates, not subject-indexed personal records"),
		{Plane: "rum", Status: SubjectStatusNotAddressable,
			Notes: "RUM host/path samples are privacy-redacted result signals and are not subject-indexed by lifecycle"},
		{Plane: "device", Status: SubjectStatusNotAddressable,
			Notes: "device sysName/interface labels are operational inventory labels and are not subject-indexed by lifecycle"},
		e.subjectDerivedPlane("endpoint", e.endpointRetention != nil,
			"endpoint latest-view labels are derived DEM cache entries and are not subject-indexed by lifecycle"),
	}
}

func (e *Engine) subjectDerivedPlane(plane string, deployed bool, notes string) SubjectPlaneResult {
	if !deployed {
		return SubjectPlaneResult{Plane: plane, Status: SubjectStatusNotDeployed, Notes: "store not deployed"}
	}
	return SubjectPlaneResult{Plane: plane, Status: SubjectStatusNotAddressable, Notes: notes}
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
