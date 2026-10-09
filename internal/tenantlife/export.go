// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The export bundle (the portability contract, format_version 1): a tar.gz of
//
//	manifest.json            counts, object inventory, format notes
//	postgres/<table>.jsonl   ordinary tenant-owned rows, one JSON object per line
//	flows.jsonl              every flow record (streamed from the flow store)
//	endpoint_events.jsonl    every endpoint/DEM event
//	otel_spans.jsonl         every OTLP span, and every OTLP log record
//	otel_logs.jsonl
//	ebpf_edges.jsonl         every eBPF workload aggregate
//	path_hops.jsonl          every path discovery round's hop and link rows
//	path_links.jsonl
//	topology.jsonl           the topology graph's nodes and edges
//
// Every store the erasure clears is either bundled here or named in the notes.
//
// Provider-only encrypted incident-response attribution is deliberately absent
// from ordinary portability bundles. Investigation access uses its dedicated,
// audited separation-of-duty path.
//
// TSDB series are NOT bundled (metrics export rides PromQL/federation — the
// manifest says so); object-store BLOBS are inventoried in the manifest
// (key + size) rather than bundled in v1. Additive changes only.

const ordinaryPortabilityIRPolicyNote = "Ordinary portability exports never include encrypted incident-response attribution. Investigation access, where applicable, is only through the audited IR-investigator path. This policy statement does not indicate whether any records exist."

// Manifest describes one export bundle.
type Manifest struct {
	FormatVersion  int              `json:"format_version"`
	TenantID       string           `json:"tenant_id"`
	ExportedAt     time.Time        `json:"exported_at"`
	Tables         map[string]int64 `json:"tables"` // table -> row count
	Flows          int64            `json:"flows"`
	EndpointEvents int64            `json:"endpoint_events"`
	OtelSpans      int64            `json:"otel_spans"`
	OtelLogs       int64            `json:"otel_logs"`
	EBPFEdges      int64            `json:"ebpf_edges"`
	PathHops       int64            `json:"path_hops"`
	PathLinks      int64            `json:"path_links"`
	Topology       int64            `json:"topology"` // graph nodes + edges
	Objects        []ObjectRef      `json:"objects"`
	Notes          []string         `json:"notes"`
	Redacted       bool             `json:"redacted"` // S-EE3: PII masked per the governance policy
}

// ObjectRef inventories one stored artifact.
type ObjectRef struct {
	Key  string `json:"key"`
	Size int64  `json:"size"`
}

// Export writes the tenant's portability bundle to w. Everything is read
// inside the tenant's own scope (RLS + silo routing) — the export path
// cannot see another tenant's rows by construction.
func (e *Engine) Export(ctx context.Context, tenantID string, w io.Writer) (Manifest, error) {
	return e.export(ctx, tenantID, w, false)
}

// ExportRedacted is Export with optional data-governance redaction (S-EE3):
// when redact is requested OR the tenant's governance policy forces it,
// PII-class columns (IPs-as-PII, emails, geo, …) and flow records are masked
// per the tenant's classification before they leave the deployment.
func (e *Engine) ExportRedacted(ctx context.Context, tenantID string, w io.Writer, redact bool) (Manifest, error) {
	return e.export(ctx, tenantID, w, redact)
}

func (e *Engine) export(ctx context.Context, tenantID string, w io.Writer, redact bool) (Manifest, error) {
	// Resolve the effective redaction policy. A request for redaction (or a
	// policy that forces it) uses the tenant's governance policy, defaulting to
	// PII-floor partial masking when nothing is configured — the redaction
	// MECHANISM is core, the per-tenant POLICY is the governance feature.
	pol, perr := govern.PolicyForStrict(ctx, tenantID)
	if perr != nil {
		// AUTHZ-29: the tenant's redaction policy cannot be read. Fail CLOSED —
		// never ship an unredacted bundle during a transient governance-store
		// failure (a redact_export tenant would otherwise leak PII). Force
		// maximal (PII-floor) redaction regardless of what the request asked.
		pol = govern.DefaultPIIPolicy()
		redact = true
	}
	redact = redact || pol.RedactExport
	if redact && pol.RedactFrom == govern.ClassUnset {
		pol = govern.DefaultPIIPolicy()
	}
	man := Manifest{
		FormatVersion: 1, TenantID: tenantID, ExportedAt: e.now().UTC(),
		Tables: map[string]int64{},
		Notes: []string{
			"TSDB metric series are not bundled: export them via the Prometheus-compatible API (federation/PromQL).",
			"Object-store artifacts are inventoried under objects[]; fetch blobs individually via their API surfaces.",
			"Hourly flow and path rollups are derived aggregates and are not bundled; the raw rows they summarize are, for as long as those rows are retained.",
			"Immutable audit rows keep their tenant, sequence, timestamp, and chain fields; erased identities are emitted only through the canonical audit privacy projection.",
			ordinaryPortabilityIRPolicyNote,
		},
		Redacted: redact,
	}
	if redact {
		man.Notes = append(man.Notes,
			"This export is REDACTED (S-EE3): PII-class values (IP addresses, emails, geo, …) are masked per the tenant's data-classification policy.")
	}

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	// 1) Postgres: ordinary tenant-owned tables as JSONL, read under InTenant.
	// Retained encrypted IR evidence is classified and removed before entering
	// the app-role transaction; this path never probes, counts, or opens it.
	if e.pool != nil {
		tables, err := e.tenantOwnedTables(ctx)
		if err != nil {
			return man, err
		}
		tables = ordinaryPortabilityExportTables(tables)
		tctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
		for _, table := range tables {
			var buf bytes.Buffer
			var count int64
			err := tenancy.InTenant(tctx, e.pool, func(ctx context.Context, sc tenancy.Scope) error {
				if table == "audit_events" {
					var err error
					count, err = appendProjectedAuditJSONL(
						ctx,
						sc,
						&buf,
						nil,
					)
					return err
				}
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
					buf.Write(raw)
					buf.WriteByte('\n')
					count++
				}
				return rows.Err()
			})
			if err != nil {
				return man, fmt.Errorf("tenantlife: export %s: %w", table, err)
			}
			man.Tables[table] = count
			out := buf.Bytes()
			if redact {
				out = govern.RedactJSONL(pol, out)
			}
			if err := writeTarFile(tw, "postgres/"+table+".jsonl", out, man.ExportedAt); err != nil {
				return man, err
			}
		}
	}

	// 2) Flows: streamed JSONL from the routed flow store.
	if e.flows != nil {
		var buf bytes.Buffer
		n, err := e.flows.ExportTenant(ctx, tenantID, &buf)
		if err != nil {
			return man, fmt.Errorf("tenantlife: export flows: %w", err)
		}
		man.Flows = n
		flowsOut := buf.Bytes()
		if redact {
			flowsOut = govern.RedactJSONL(pol, flowsOut)
		}
		if err := writeTarFile(tw, "flows.jsonl", flowsOut, man.ExportedAt); err != nil {
			return man, err
		}
	}

	// 2b) Durable endpoint/DEM event history (tenant-scoped by the store).
	// The endpoint history is unbounded (GAP-05): the store streams it row by
	// row and we stage it through a temp file so neither the store read nor the
	// tar write buffers the whole plane in the shared control-plane heap. The
	// tar header needs the byte size up front, so the temp file both supplies
	// that size and holds the (optionally redacted, line-by-line) bytes.
	if e.endpointEvents != nil {
		n, err := streamPlaneToTar(tw, "endpoint_events.jsonl", man.ExportedAt, redact, pol,
			func(w io.Writer) (int64, error) {
				return e.endpointEvents.ExportTenant(ctx, tenantID, w)
			})
		if err != nil {
			return man, fmt.Errorf("tenantlife: export endpoint events: %w", err)
		}
		man.EndpointEvents = n
	}

	// 2c) The OTLP, eBPF, path and topology planes.
	if err := e.exportTelemetryPlanes(ctx, tw, tenantID, &man, redact, pol); err != nil {
		return man, err
	}

	// 3) Object inventory (both key namespaces).
	if e.objects != nil {
		tenantObjects, err := tenantObjectStores(e.objects, tenantID)
		if err != nil {
			return man, fmt.Errorf("tenantlife: bind object namespace: %w", err)
		}
		for _, objects := range tenantObjects {
			keys, err := objects.List(ctx, "")
			if err != nil {
				return man, fmt.Errorf("tenantlife: list objects: %w", err)
			}
			for _, k := range keys {
				size, _, _ := objects.Stat(ctx, k)
				man.Objects = append(man.Objects, ObjectRef{Key: objects.Key(k), Size: size})
			}
		}
	}

	// 4) The manifest itself, last (it summarizes everything above).
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
		if err := e.audit(ctx, tenantID, "lifecycle.export", tenantID, map[string]any{
			"tables": len(man.Tables), "flows": man.Flows, "objects": len(man.Objects),
		}); err != nil {
			return man, fmt.Errorf("tenantlife: export audit append failed: %w", err)
		}
	}
	return man, nil
}

// The planes a full export streams beside flows and endpoint events. Every
// shipped backend implements them; a deployed store that does not is named in
// the manifest notes rather than silently left out of the bundle.
type otelTenantExporter interface {
	ExportTenantSpans(ctx context.Context, tenantID string, w io.Writer) (int64, error)
	ExportTenantLogs(ctx context.Context, tenantID string, w io.Writer) (int64, error)
}

type ebpfTenantExporter interface {
	ExportTenant(ctx context.Context, tenantID string, w io.Writer) (int64, error)
}

type pathTenantExporter interface {
	ExportTenantHops(ctx context.Context, tenantID string, w io.Writer) (int64, error)
	ExportTenantLinks(ctx context.Context, tenantID string, w io.Writer) (int64, error)
}

type topologyTenantExporter interface {
	ExportTenant(tenantID string, w io.Writer) (nodes, edges int64, err error)
}

// exportTelemetryPlanes streams the OTLP, eBPF, path and topology planes into
// the bundle, each staged through a temp file like the endpoint history
// (GAP-05). Erasure clears every one of these stores, so the bundle that comes
// before it must carry them.
func (e *Engine) exportTelemetryPlanes(ctx context.Context, tw *tar.Writer, tenantID string, man *Manifest, redact bool, pol govern.Policy) error {
	type plane struct {
		file    string
		count   *int64
		produce func(io.Writer) (int64, error)
	}
	var planes []plane
	var incapable []string
	if e.otel != nil {
		if x, ok := e.otel.(otelTenantExporter); ok {
			planes = append(planes,
				plane{"otel_spans.jsonl", &man.OtelSpans, func(w io.Writer) (int64, error) { return x.ExportTenantSpans(ctx, tenantID, w) }},
				plane{"otel_logs.jsonl", &man.OtelLogs, func(w io.Writer) (int64, error) { return x.ExportTenantLogs(ctx, tenantID, w) }})
		} else {
			incapable = append(incapable, "otel")
		}
	}
	if e.ebpf != nil {
		if x, ok := e.ebpf.(ebpfTenantExporter); ok {
			planes = append(planes,
				plane{"ebpf_edges.jsonl", &man.EBPFEdges, func(w io.Writer) (int64, error) { return x.ExportTenant(ctx, tenantID, w) }})
		} else {
			incapable = append(incapable, "ebpf")
		}
	}
	if e.paths != nil {
		if x, ok := e.paths.(pathTenantExporter); ok {
			planes = append(planes,
				plane{"path_hops.jsonl", &man.PathHops, func(w io.Writer) (int64, error) { return x.ExportTenantHops(ctx, tenantID, w) }},
				plane{"path_links.jsonl", &man.PathLinks, func(w io.Writer) (int64, error) { return x.ExportTenantLinks(ctx, tenantID, w) }})
		} else {
			incapable = append(incapable, "paths")
		}
	}
	if e.topo != nil {
		if x, ok := e.topo.(topologyTenantExporter); ok {
			planes = append(planes, plane{"topology.jsonl", &man.Topology, func(w io.Writer) (int64, error) {
				nodes, edges, err := x.ExportTenant(tenantID, w)
				return nodes + edges, err
			}})
		} else {
			incapable = append(incapable, "topology")
		}
	}
	for _, p := range planes {
		n, err := streamPlaneToTar(tw, p.file, man.ExportedAt, redact, pol, p.produce)
		if err != nil {
			return fmt.Errorf("tenantlife: export %s: %w", strings.TrimSuffix(p.file, ".jsonl"), err)
		}
		*p.count = n
	}
	if len(incapable) > 0 {
		man.Notes = append(man.Notes, "These deployed stores cannot export, so their rows are not in this bundle: "+strings.Join(incapable, ", ")+".")
	}
	return nil
}

func ordinaryPortabilityExportTables(tables []string) []string {
	exportable := make([]string, 0, len(tables))
	for _, table := range tables {
		if retainedCryptoShreddedEvidenceTables[table] {
			continue
		}
		exportable = append(exportable, table)
	}
	return exportable
}

// appendProjectedAuditJSONL is the only tenant-lifecycle path that serializes
// audit_events. It deliberately consumes audit.ListExportRows instead of
// row_to_json so subject-erasure projection is identical in the audit API, SIEM
// drain, full portability bundle, and subject bundle. The audit export-row API
// preserves the format-version-1 id, tenant_id, and every stored chain field.
func appendProjectedAuditJSONL(
	ctx context.Context,
	scope tenancy.Scope,
	dst *bytes.Buffer,
	include func(audit.Event, []byte) bool,
) (int64, error) {
	// TenantVerify takes the same transaction-scoped advisory lock used by
	// append and retention, and proves the retained suffix reaches its durable
	// head. The lock remains held by this scope transaction across every page,
	// so a bundle cannot silently skip rows pruned between page reads.
	if err := audit.TenantVerify(ctx, scope); err != nil {
		return 0, fmt.Errorf("verify audit stream for portability export: %w", err)
	}

	var (
		after int64
		count int64
	)
	for {
		rows, err := audit.ListExportRows(
			ctx,
			scope,
			after,
			audit.MaxExportPageSize,
		)
		if err != nil {
			return 0, err
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			projected, err := json.Marshal(row.Event)
			if err != nil {
				return 0, fmt.Errorf(
					"encode projected audit event %d: %w",
					row.Seq,
					err,
				)
			}
			after = row.Seq
			if include != nil && !include(row.Event, projected) {
				continue
			}
			encoded, err := json.Marshal(row)
			if err != nil {
				return 0, fmt.Errorf(
					"encode tenant audit event %d: %w",
					row.Seq,
					err,
				)
			}
			dst.Write(encoded)
			dst.WriteByte('\n')
			count++
		}
	}
	return count, nil
}

// streamPlaneToTar stages a large, unbounded export plane through a temp file so
// it never lands whole in the control-plane heap (GAP-05). produce streams the
// plane's JSONL into the writer it is handed; when redact is set, each line is
// redacted on the way to disk via a one-line-at-a-time writer (so the temp file
// itself holds only redacted bytes). The temp file's size then feeds the tar
// header and its bytes are copied straight into the archive. It returns the row
// count produce reports, so the manifest count stays exact.
func streamPlaneToTar(tw *tar.Writer, name string, mod time.Time, redact bool, pol govern.Policy, produce func(io.Writer) (int64, error)) (int64, error) {
	tmp, err := os.CreateTemp("", "probectl-export-plane-*.jsonl")
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()

	var dst io.Writer = tmp
	var rw *redactingLineWriter
	if redact {
		rw = &redactingLineWriter{pol: pol, dst: tmp}
		dst = rw
	}
	n, err := produce(dst)
	if err != nil {
		return n, err
	}
	if rw != nil {
		if err := rw.Flush(); err != nil {
			return n, err
		}
	}

	size, err := tmp.Seek(0, io.SeekCurrent)
	if err != nil {
		return n, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return n, err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: size, ModTime: mod}); err != nil {
		return n, err
	}
	if _, err := io.Copy(tw, tmp); err != nil {
		return n, err
	}
	return n, nil
}

// redactingLineWriter applies govern.RedactJSONL to a JSONL stream one complete
// line at a time, buffering at most a single partial line — so a redacted export
// plane can be staged without holding the whole plane in memory (GAP-05). It is
// not safe for concurrent use; the export path writes to it from one goroutine.
type redactingLineWriter struct {
	pol govern.Policy
	dst io.Writer
	rem []byte // bytes after the last newline, not yet a complete line
}

func (r *redactingLineWriter) Write(p []byte) (int, error) {
	r.rem = append(r.rem, p...)
	for {
		idx := bytes.IndexByte(r.rem, '\n')
		if idx < 0 {
			break
		}
		if _, err := r.dst.Write(govern.RedactJSONL(r.pol, r.rem[:idx+1])); err != nil {
			return 0, err
		}
		r.rem = r.rem[idx+1:]
	}
	if len(r.rem) == 0 {
		r.rem = r.rem[:0]
	}
	return len(p), nil
}

// Flush redacts and writes any trailing line that did not end in a newline.
func (r *redactingLineWriter) Flush() error {
	if len(r.rem) == 0 {
		return nil
	}
	out := govern.RedactJSONL(r.pol, r.rem)
	r.rem = nil
	_, err := r.dst.Write(out)
	return err
}

func writeTarFile(tw *tar.Writer, name string, data []byte, mod time.Time) error {
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: mod,
	}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
