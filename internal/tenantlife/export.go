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
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/govern"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// The export bundle (the portability contract, format_version 1): a tar.gz of
//
//	manifest.json            counts, object inventory, format notes
//	postgres/<table>.jsonl   ordinary tenant-owned rows, one JSON object per line
//	flows.jsonl              every flow record (streamed from the flow store)
//	endpoint_events.jsonl    every endpoint/DEM event
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
	pol := govern.PolicyFor(ctx, tenantID)
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
	if e.endpointEvents != nil {
		var buf bytes.Buffer
		n, err := e.endpointEvents.ExportTenant(ctx, tenantID, &buf)
		if err != nil {
			return man, fmt.Errorf("tenantlife: export endpoint events: %w", err)
		}
		man.EndpointEvents = n
		out := buf.Bytes()
		if redact {
			out = govern.RedactJSONL(pol, out)
		}
		if err := writeTarFile(tw, "endpoint_events.jsonl", out, man.ExportedAt); err != nil {
			return man, err
		}
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

func writeTarFile(tw *tar.Writer, name string, data []byte, mod time.Time) error {
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: mod,
	}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
