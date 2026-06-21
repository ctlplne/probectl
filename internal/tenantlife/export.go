// SPDX-License-Identifier: LicenseRef-probectl-TBD

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

	"github.com/imfeelingtheagi/probectl/internal/govern"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// The export bundle (the portability contract, format_version 1): a tar.gz of
//
//	manifest.json            counts, object inventory, format notes
//	postgres/<table>.jsonl   every tenant-owned row, one JSON object per line
//	flows.jsonl              every flow record (streamed from the flow store)
//
// TSDB series are NOT bundled (metrics export rides PromQL/federation — the
// manifest says so); object-store BLOBS are inventoried in the manifest
// (key + size) rather than bundled in v1. Additive changes only.

// Manifest describes one export bundle.
type Manifest struct {
	FormatVersion int              `json:"format_version"`
	TenantID      string           `json:"tenant_id"`
	ExportedAt    time.Time        `json:"exported_at"`
	Tables        map[string]int64 `json:"tables"` // table -> row count
	Flows         int64            `json:"flows"`
	Objects       []ObjectRef      `json:"objects"`
	Notes         []string         `json:"notes"`
	Redacted      bool             `json:"redacted"` // S-EE3: PII masked per the governance policy
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
		},
		Redacted: redact,
	}
	if redact {
		man.Notes = append(man.Notes,
			"This export is REDACTED (S-EE3): PII-class values (IP addresses, emails, geo, …) are masked per the tenant's data-classification policy.")
	}

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	// 1) Postgres: every tenant-owned table as JSONL, read under InTenant.
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

func writeTarFile(tw *tar.Writer, name string, data []byte, mod time.Time) error {
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: mod,
	}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
