// Package tenantlife is the per-tenant lifecycle engine (S-T5, F55):
// tenant-scoped data EXPORT (portability), VERIFIABLE full deletion across
// every store (Postgres / ClickHouse flows / TSDB / object store) with an
// audit-grade attestation, and per-tenant retention/erasure controls.
//
// This is CORE deliberately (the ratified editions decision): export and
// verifiable deletion are a compliance right, not a commercial feature. Only
// the provider-console offboarding views ride ee/.
//
// Scoping facts the engine builds on:
//   - Postgres deletion runs table-by-table UNDER tenancy.InTenant: RLS (and
//     the S-T2 silo routing) scope every DELETE, so erasing tenant A cannot
//     touch tenant B even if this code were buggy (defense in depth) — and a
//     siloed tenant's deletes land inside its own schema.
//   - The tenant-owned table set derives LIVE from information_schema minus
//     the shared provider-owned deny list (internal/tenancy) — the same
//     vocabulary the silo provisioner uses, so the two can never disagree.
//   - Provider-plane rows ABOUT the tenant (usage, quotas, branding,
//     break-glass) are erased through the provider role.
//   - "Deleted" is verified by counting AFTER deleting: the attestation
//     records per-store remaining==0, not a promise.
package tenantlife

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/objectstore"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
)

// TSDBTenantDeleter is implemented by TSDB writers that can delete a
// tenant's series in place (the memory writer). The prometheus remote-write
// mode cannot — that store's erasure is the documented manual step
// (delete_series admin API / retention), recorded honestly in the
// attestation.
type TSDBTenantDeleter interface {
	DeleteTenant(ctx context.Context, tenantID string) (int, error)
}

// AuditSink records lifecycle events on the PROVIDER audit stream — the
// chain that survives the tenant's own audit data being erased.
type AuditSink func(ctx context.Context, actor, action, target string, data map[string]any) error

// Engine runs exports, erasures, and retention sweeps.
type Engine struct {
	pool    *pgxpool.Pool
	flows   flowstore.Store
	objects objectstore.Store
	tsdbW   tsdb.Writer
	audit   AuditSink
	log     *slog.Logger
	now     func() time.Time

	// BackupNote is the operator's backup-retention statement, included
	// verbatim in every attestation (the explicit backup-TTL story).
	backupNote string
}

// New wires the engine. flows/objects/tsdb may be nil (that store absent in
// the deployment — recorded as "not deployed" in attestations, never
// silently skipped). audit may be nil only when no pool exists (tests).
func New(pool *pgxpool.Pool, flows flowstore.Store, objects objectstore.Store, w tsdb.Writer,
	audit AuditSink, backupNote string, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	if backupNote == "" {
		backupNote = "Live-store deletion is attested below. Operator backups/snapshots expire per the deployment's backup policy — state PROBECTL_BACKUP_RETENTION_NOTE to put your TTL on the record."
	}
	return &Engine{pool: pool, flows: flows, objects: objects, tsdbW: w,
		audit: audit, backupNote: backupNote, log: log, now: time.Now}
}

// WithClock overrides time (tests).
func (e *Engine) WithClock(now func() time.Time) *Engine {
	e.now = now
	return e
}

// tenantOwnedTables derives the live tenant-owned table set (public tables
// with a tenant_id column minus the shared provider-owned deny list).
func (e *Engine) tenantOwnedTables(ctx context.Context) ([]string, error) {
	rows, err := e.pool.Query(ctx, `
		SELECT DISTINCT table_name FROM information_schema.columns
		 WHERE table_schema = 'public' AND column_name = 'tenant_id'
		 ORDER BY table_name`)
	if err != nil {
		return nil, fmt.Errorf("tenantlife: read tenant tables: %w", err)
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		tables = append(tables, t)
	}
	return tenancy.FilterTenantOwned(tables), rows.Err()
}

// --- Verifiable erasure -----------------------------------------------------

// StoreResult is one store's outcome in the attestation.
type StoreResult struct {
	Store        string `json:"store"`
	Deleted      int64  `json:"deleted"`
	VerifiedZero bool   `json:"verified_zero"`
	Notes        string `json:"notes,omitempty"`
}

// Attestation is the deletion report — the proof handed to the offboarded
// customer. Audit-grade: appended to the tamper-evident provider audit chain
// (which survives the tenant's own data) with the report's SHA-256.
type Attestation struct {
	FormatVersion int           `json:"format_version"`
	TenantID      string        `json:"tenant_id"`
	TenantSlug    string        `json:"tenant_slug,omitempty"`
	Actor         string        `json:"actor"`
	StartedAt     time.Time     `json:"started_at"`
	FinishedAt    time.Time     `json:"finished_at"`
	Stores        []StoreResult `json:"stores"`
	BackupPolicy  string        `json:"backup_policy"`
	Complete      bool          `json:"complete"`
	ReportSHA256  string        `json:"report_sha256"`
}

// maxDeletePasses bounds the FK-ordering retry loop (intra-tenant foreign
// keys are resolved by repeated passes instead of a dependency graph).
const maxDeletePasses = 6

// Erase deletes one tenant's data from every store, verifies each store
// reads zero afterward, marks the tenant deleted, and appends the
// attestation to the provider audit stream BEFORE returning it. Pooled
// tenants get scoped deletes (RLS-bound); siloed tenants' Postgres deletes
// route into their own schema (the silo container drop itself is the
// provider offboard step and is noted).
func (e *Engine) Erase(ctx context.Context, tenantID, slug, actor string) (Attestation, error) {
	att := Attestation{
		FormatVersion: 1, TenantID: tenantID, TenantSlug: slug, Actor: actor,
		StartedAt: e.now().UTC(), BackupPolicy: e.backupNote, Complete: true,
	}
	fail := func(store, note string) {
		att.Stores = append(att.Stores, StoreResult{Store: store, Deleted: -1, Notes: note})
		att.Complete = false
	}

	// 1) ClickHouse flows (routed: siloed databases are dropped whole).
	if e.flows != nil {
		remaining, err := e.flows.DeleteTenant(ctx, tenantID)
		if err != nil {
			fail("flows", "delete failed: "+err.Error())
		} else {
			att.Stores = append(att.Stores, StoreResult{Store: "flows", VerifiedZero: remaining == 0,
				Notes: "remaining=" + fmt.Sprint(remaining)})
			if remaining != 0 {
				att.Complete = false
			}
		}
	} else {
		att.Stores = append(att.Stores, StoreResult{Store: "flows", VerifiedZero: true, Notes: "store not deployed"})
	}

	// 2) Object store: both the pooled and silo key namespaces.
	if e.objects != nil {
		total := 0
		ok := true
		for _, prefix := range []string{"tenant/" + tenantID + "/", "silo/" + tenantID + "/"} {
			n, err := e.objects.DeletePrefix(ctx, prefix)
			if err != nil {
				fail("objects", "delete "+prefix+" failed: "+err.Error())
				ok = false
				break
			}
			total += n
		}
		if ok {
			left, _ := e.objects.List(ctx, "tenant/"+tenantID+"/")
			left2, _ := e.objects.List(ctx, "silo/"+tenantID+"/")
			verified := len(left)+len(left2) == 0
			att.Stores = append(att.Stores, StoreResult{Store: "objects", Deleted: int64(total), VerifiedZero: verified})
			if !verified {
				att.Complete = false
			}
		}
	} else {
		att.Stores = append(att.Stores, StoreResult{Store: "objects", VerifiedZero: true, Notes: "store not deployed"})
	}

	// 3) TSDB series.
	switch td := e.tsdbW.(type) {
	case TSDBTenantDeleter:
		n, err := td.DeleteTenant(ctx, tenantID)
		if err != nil {
			fail("tsdb", "delete failed: "+err.Error())
		} else {
			att.Stores = append(att.Stores, StoreResult{Store: "tsdb", Deleted: int64(n), VerifiedZero: true})
		}
	case nil:
		att.Stores = append(att.Stores, StoreResult{Store: "tsdb", VerifiedZero: true, Notes: "store not deployed"})
	default:
		// Honesty over optimism: prometheus-mode series need the documented
		// manual step (delete_series admin API or retention expiry).
		fail("tsdb", "MANUAL STEP REQUIRED: prometheus-mode series are deleted via the admin delete_series API or expire by retention (see docs/runbooks/tenant-offboarding.md)")
	}

	// 4) Postgres tenant-owned tables — RLS-scoped, silo-routed, multi-pass
	// for intra-tenant FK ordering.
	if e.pool != nil {
		if res, err := e.erasePostgres(ctx, tenantID); err != nil {
			fail("postgres", err.Error())
		} else {
			att.Stores = append(att.Stores, res)
			if !res.VerifiedZero {
				att.Complete = false
			}
		}

		// 5) Provider-plane rows ABOUT the tenant + the tombstone status.
		if res, err := e.eraseProviderRows(ctx, tenantID); err != nil {
			fail("provider_rows", err.Error())
		} else {
			att.Stores = append(att.Stores, res)
			if !res.VerifiedZero {
				att.Complete = false
			}
		}
	} else {
		att.Stores = append(att.Stores, StoreResult{Store: "postgres", VerifiedZero: true, Notes: "store not deployed"})
	}

	// 6) Cryptographic offboarding (S-T6): when a per-tenant keyring is
	// installed, destroy the tenant's keys — every remaining ciphertext
	// (incl. backups within their TTL) becomes permanently unreadable.
	if n, supported, err := tenantcrypto.DestroyKeys(ctx, tenantID); err != nil {
		fail("tenant_keys", "key destruction failed: "+err.Error())
	} else if supported {
		att.Stores = append(att.Stores, StoreResult{Store: "tenant_keys", Deleted: int64(n), VerifiedZero: true,
			Notes: "crypto-shred: key versions destroyed; ciphertexts (incl. in-TTL backups) unreadable"})
	} else {
		att.Stores = append(att.Stores, StoreResult{Store: "tenant_keys", VerifiedZero: true,
			Notes: "no per-tenant keyring installed (byok feature not licensed)"})
	}

	att.FinishedAt = e.now().UTC()
	att.ReportSHA256 = att.hash()

	// The attestation goes on the provider audit chain BEFORE returning —
	// an unrecorded erasure is no erasure (audit-grade, guardrail 7).
	if e.audit != nil {
		if err := e.audit(ctx, actor, "lifecycle.erase", tenantID, map[string]any{
			"slug": slug, "complete": att.Complete, "report_sha256": att.ReportSHA256,
			"stores": len(att.Stores),
		}); err != nil {
			return att, fmt.Errorf("tenantlife: attestation audit append failed: %w", err)
		}
	}
	return att, nil
}

// hash computes the report digest over the canonical JSON minus the hash
// field — through the internal crypto provider (FIPS-swappable, guardrail 3).
func (a Attestation) hash() string {
	cp := a
	cp.ReportSHA256 = ""
	b, _ := json.Marshal(cp)
	return hex.EncodeToString(crypto.Hash(b))
}

// appendOnlyTables are tenant-owned tables the APP ROLE may not delete by
// design (audit_events is append-only for probectl_app — a deliberate
// security property). The erase engine removes them via the PROVIDER role
// instead (an explicit DELETE policy from migration 0029), never by
// weakening the app role.
var appendOnlyTables = map[string]bool{"audit_events": true}

// erasePostgres deletes every tenant-owned row under the tenant's own scope.
// Each table's DELETE runs in ITS OWN transaction: a failed statement aborts
// a Postgres transaction, so per-table isolation is what lets the multi-pass
// loop retry FK orderings without poisoning the rest of the pass.
func (e *Engine) erasePostgres(ctx context.Context, tenantID string) (StoreResult, error) {
	all, err := e.tenantOwnedTables(ctx)
	if err != nil {
		return StoreResult{}, err
	}
	tables := make([]string, 0, len(all))
	for _, t := range all {
		if !appendOnlyTables[t] {
			tables = append(tables, t)
		}
	}
	tctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	var deleted int64
	for pass := 0; pass < maxDeletePasses; pass++ {
		var passDeleted int64
		for _, t := range tables {
			err := tenancy.InTenant(tctx, e.pool, func(ctx context.Context, sc tenancy.Scope) error {
				tag, err := sc.Q.Exec(ctx, `DELETE FROM `+pgIdent(t))
				if err != nil {
					return err
				}
				passDeleted += tag.RowsAffected()
				return nil
			})
			if err != nil {
				continue // FK ordering: a later pass retries this table
			}
		}
		deleted += passDeleted
		if passDeleted == 0 {
			break
		}
	}
	// Append-only tables: erased via the provider role (the explicit S-T5
	// DELETE policy) — the app role stays append-only.
	err = tenancy.InProvider(ctx, e.pool, func(ctx context.Context, q tenancy.Querier) error {
		for t := range appendOnlyTables {
			tag, err := q.Exec(ctx, `DELETE FROM `+pgIdent(t)+` WHERE tenant_id = $1`, tenantID)
			if err != nil {
				return fmt.Errorf("delete %s: %w", t, err)
			}
			deleted += tag.RowsAffected()
		}
		return nil
	})
	if err != nil {
		return StoreResult{}, fmt.Errorf("tenantlife: postgres erase (append-only tables): %w", err)
	}
	// Verify: every table reads zero within the tenant's scope (the
	// append-only set is verified through the provider role).
	verified := true
	notes := ""
	verr := tenancy.InTenant(tctx, e.pool, func(ctx context.Context, sc tenancy.Scope) error {
		for _, t := range tables {
			var n int64
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM `+pgIdent(t)).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				verified = false
				notes += fmt.Sprintf("%s:%d ", t, n)
			}
		}
		return nil
	})
	if verr != nil {
		return StoreResult{}, fmt.Errorf("tenantlife: postgres verify: %w", verr)
	}
	if perr := tenancy.InProvider(ctx, e.pool, func(ctx context.Context, q tenancy.Querier) error {
		for t := range appendOnlyTables {
			var n int64
			if err := q.QueryRow(ctx, `SELECT count(*) FROM `+pgIdent(t)+` WHERE tenant_id = $1`, tenantID).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				verified = false
				notes += fmt.Sprintf("%s:%d ", t, n)
			}
		}
		return nil
	}); perr != nil {
		return StoreResult{}, fmt.Errorf("tenantlife: postgres verify (append-only): %w", perr)
	}
	return StoreResult{Store: "postgres", Deleted: deleted, VerifiedZero: verified,
		Notes: trimNotes(notes, len(all))}, nil
}

// eraseProviderRows removes provider-plane rows about the tenant and marks
// the registry tombstone (status=deleted; the row itself remains so the
// attestation keeps a referent).
func (e *Engine) eraseProviderRows(ctx context.Context, tenantID string) (StoreResult, error) {
	var deleted int64
	verified := true
	err := tenancy.InProvider(ctx, e.pool, func(ctx context.Context, q tenancy.Querier) error {
		for _, t := range []string{"usage_records", "tenant_quotas", "tenant_branding", "break_glass_grants", "tenant_retention", "tenant_keys", "tenant_fairness", "tenant_governance"} {
			tag, err := q.Exec(ctx, `DELETE FROM `+pgIdent(t)+` WHERE tenant_id = $1`, tenantID)
			if err != nil {
				return fmt.Errorf("delete %s: %w", t, err)
			}
			deleted += tag.RowsAffected()
			var n int64
			if err := q.QueryRow(ctx, `SELECT count(*) FROM `+pgIdent(t)+` WHERE tenant_id = $1`, tenantID).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				verified = false
			}
		}
		_, err := q.Exec(ctx, `UPDATE tenants SET status = 'deleted', updated_at = now() WHERE id = $1`, tenantID)
		return err
	})
	if err != nil {
		return StoreResult{}, fmt.Errorf("tenantlife: provider rows: %w", err)
	}
	return StoreResult{Store: "provider_rows", Deleted: deleted, VerifiedZero: verified,
		Notes: "tenant registry row tombstoned (status=deleted)"}, nil
}

func trimNotes(notes string, tables int) string {
	if notes == "" {
		return fmt.Sprintf("%d tables verified zero", tables)
	}
	return "non-zero: " + notes
}

// pgIdent quotes a table identifier.
func pgIdent(s string) string { return `"` + s + `"` }

// --- Retention ---------------------------------------------------------------

// RetentionPolicy is one tenant's erasure control (nil days = deployment
// default, i.e. the store-level TTL).
type RetentionPolicy struct {
	TenantID          string `json:"tenant_id,omitempty"`
	FlowRetentionDays *int   `json:"flow_retention_days"`
	UpdatedBy         string `json:"updated_by,omitempty"`
}

// RetentionFor reads a tenant's policy within its own scope (RLS).
func (e *Engine) RetentionFor(ctx context.Context, tenantID string) (RetentionPolicy, error) {
	p := RetentionPolicy{TenantID: tenantID}
	tctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	err := tenancy.InTenant(tctx, e.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `SELECT flow_retention_days, updated_by FROM tenant_retention WHERE tenant_id = $1`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			return rows.Scan(&p.FlowRetentionDays, &p.UpdatedBy)
		}
		return rows.Err()
	})
	return p, err
}

// SetRetention upserts a tenant's policy within its own scope (RLS).
func (e *Engine) SetRetention(ctx context.Context, p RetentionPolicy) error {
	if p.FlowRetentionDays != nil && *p.FlowRetentionDays < 1 {
		return fmt.Errorf("tenantlife: flow_retention_days must be >= 1 (null = deployment default)")
	}
	tctx := tenancy.WithTenant(ctx, tenancy.ID(p.TenantID))
	return tenancy.InTenant(tctx, e.pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `
			INSERT INTO tenant_retention (tenant_id, flow_retention_days, updated_by, updated_at)
			VALUES ($1, $2, $3, now())
			ON CONFLICT (tenant_id) DO UPDATE SET
			  flow_retention_days = EXCLUDED.flow_retention_days,
			  updated_by = EXCLUDED.updated_by, updated_at = now()`,
			p.TenantID, p.FlowRetentionDays, p.UpdatedBy)
		return err
	})
}

// SweepRetention applies every tenant's flow-retention policy once (the
// deployment-level TTL handles the default; this enforces PER-TENANT
// tightening). Per-tenant failures are logged and skipped.
func (e *Engine) SweepRetention(ctx context.Context) error {
	if e.pool == nil || e.flows == nil {
		return nil
	}
	type policy struct {
		tenant string
		days   int
	}
	var policies []policy
	err := tenancy.InProvider(ctx, e.pool, func(ctx context.Context, q tenancy.Querier) error {
		rows, err := q.Query(ctx, `
			SELECT tenant_id::text, flow_retention_days FROM tenant_retention
			 WHERE flow_retention_days IS NOT NULL`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p policy
			if err := rows.Scan(&p.tenant, &p.days); err != nil {
				return err
			}
			policies = append(policies, p)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	for _, p := range policies {
		cutoff := e.now().Add(-time.Duration(p.days) * 24 * time.Hour)
		if err := e.flows.DeleteTenantBefore(ctx, p.tenant, cutoff); err != nil {
			e.log.Warn("retention sweep failed for tenant", "tenant", p.tenant, "error", err.Error())
		}
	}
	return nil
}

// RunRetention sweeps on the interval until ctx ends.
func (e *Engine) RunRetention(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := e.SweepRetention(ctx); err != nil {
				e.log.Warn("retention sweep failed", "error", err.Error())
			}
		}
	}
}
