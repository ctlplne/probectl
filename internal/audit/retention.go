// SPDX-License-Identifier: LicenseRef-probectl-TBD

package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// Audit-log retention (EXC-ORG-01). The chains are append-only for the
// application role (no UPDATE/DELETE RLS policy) and tamper-evident (hash chained
// + WORM-exported, see worm.go). Retention is the controlled, F500-required
// counterpart: an operator keeps audit history for a configurable window — long
// enough to satisfy SOC2 CC7 / ISO A.12.4 evidence retention, then prunes — but
// pruning must NEVER (a) delete an event the WORM/SIEM export has not durably
// captured, or (b) leave a gap that breaks the in-DB hash chain a verifier walks.
//
// The design that makes this safe: prune ONLY a contiguous prefix [oldest .. N]
// where every pruned event is BOTH older than the retention window AND already
// exported (seq <= exportedWatermark). The kept rows still form an unbroken chain
// from the new head onward; the pruned history lives on in the signed WORM
// segments. Pruning runs as the table owner (this is a maintenance path, not the
// app role) so RLS append-only still blocks the application from deleting.

// RetentionPolicy configures how long audit events are kept before pruning.
type RetentionPolicy struct {
	// Window is the minimum age an event must reach before it is eligible to
	// prune (e.g. 365*24h). A non-positive window disables pruning entirely
	// (keep forever — the safe default).
	Window time.Duration
}

// Enabled reports whether pruning is active.
func (p RetentionPolicy) Enabled() bool { return p.Window > 0 }

// cutoff is the timestamp before which events are age-eligible to prune.
func (p RetentionPolicy) cutoff(now time.Time) time.Time { return now.Add(-p.Window) }

// RetentionPruneAction is the receipt event emitted after a production prune.
// The receipt is append-only and deliberately contains counts/cursors, not
// deleted payload data.
const RetentionPruneAction = "audit.retention_prune"

// ProviderWatermarkFunc returns the highest provider-audit seq proven durably
// exported. Returning 0 makes provider pruning fail closed.
type ProviderWatermarkFunc func(context.Context) (int64, error)

// TenantWatermarkFunc returns the highest tenant-audit seq proven durably
// exported for one tenant. Returning 0 makes tenant pruning fail closed.
type TenantWatermarkFunc func(context.Context, string) (int64, error)

// TenantIDsFunc returns tenants whose audit streams should be considered.
type TenantIDsFunc func(context.Context) ([]string, error)

// RetentionSummary is the aggregate receipt for one runner tick.
type RetentionSummary struct {
	ProviderPruned int64
	TenantPruned   int64
	TenantsChecked int
}

// RetentionRunner is the production clock for audit retention. It reads durable
// export watermarks, prunes only eligible contiguous prefixes, and appends prune
// receipts so the next auditor can see exactly what local history moved to the
// exported evidence system.
type RetentionRunner struct {
	pool              *pgxpool.Pool
	policy            RetentionPolicy
	providerWatermark ProviderWatermarkFunc
	tenantWatermark   TenantWatermarkFunc
	tenantIDs         TenantIDsFunc
	log               *slog.Logger
	now               func() time.Time
}

// NewRetentionRunnerPG wires the production runner over Postgres. The provider
// watermark usually comes from the signed WORM segment ledger; tenant
// watermarks come from the RLS-scoped siem_delivery cursor table.
func NewRetentionRunnerPG(pool *pgxpool.Pool, policy RetentionPolicy, providerWatermark ProviderWatermarkFunc, log *slog.Logger) *RetentionRunner {
	if log == nil {
		log = slog.Default()
	}
	r := &RetentionRunner{
		pool:              pool,
		policy:            policy,
		providerWatermark: providerWatermark,
		log:               log,
		now:               time.Now,
	}
	r.tenantWatermark = func(ctx context.Context, tenantID string) (int64, error) {
		return tenantSIEMWatermark(ctx, pool, tenantID)
	}
	r.tenantIDs = func(ctx context.Context) ([]string, error) {
		return listRetentionTenantIDs(ctx, pool)
	}
	return r
}

// WithTenantWatermarkForTest replaces the tenant watermark source.
func (r *RetentionRunner) WithTenantWatermarkForTest(fn TenantWatermarkFunc) *RetentionRunner {
	r.tenantWatermark = fn
	return r
}

// WithTenantIDsForTest replaces tenant enumeration.
func (r *RetentionRunner) WithTenantIDsForTest(fn TenantIDsFunc) *RetentionRunner {
	r.tenantIDs = fn
	return r
}

// WithNowForTest replaces the clock.
func (r *RetentionRunner) WithNowForTest(fn func() time.Time) *RetentionRunner {
	r.now = fn
	return r
}

// Run executes Tick immediately, then at interval until ctx is canceled.
func (r *RetentionRunner) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := r.Tick(ctx); err != nil && ctx.Err() == nil {
			r.log.Warn("audit retention prune failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick runs one prune pass. Disabled retention is a no-op.
func (r *RetentionRunner) Tick(ctx context.Context) (RetentionSummary, error) {
	var sum RetentionSummary
	if r == nil || !r.policy.Enabled() {
		return sum, nil
	}
	now := r.now()
	cutoff := r.policy.cutoff(now)
	if r.providerWatermark != nil {
		watermark, err := r.providerWatermark(ctx)
		if err != nil {
			return sum, fmt.Errorf("provider audit watermark: %w", err)
		}
		pruned, err := PruneProvider(ctx, r.pool, r.policy, watermark, now)
		if err != nil {
			return sum, err
		}
		sum.ProviderPruned = pruned
		if pruned > 0 {
			if err := r.recordProviderPrune(ctx, pruned, watermark, cutoff); err != nil {
				return sum, err
			}
		}
	}
	tenants, err := r.tenantIDs(ctx)
	if err != nil {
		return sum, fmt.Errorf("list tenants for audit retention: %w", err)
	}
	sum.TenantsChecked = len(tenants)
	for _, tenantID := range tenants {
		watermark, err := r.tenantWatermark(ctx, tenantID)
		if err != nil {
			r.log.Warn("tenant audit watermark failed", "tenant", tenantID, "error", err)
			continue
		}
		pruned, err := PruneTenant(ctx, r.pool, tenantID, r.policy, watermark, now)
		if err != nil {
			r.log.Warn("tenant audit prune failed", "tenant", tenantID, "error", err)
			continue
		}
		sum.TenantPruned += pruned
		if pruned > 0 {
			if err := r.recordTenantPrune(ctx, tenantID, pruned, watermark, cutoff); err != nil {
				r.log.Warn("tenant audit prune receipt failed", "tenant", tenantID, "error", err)
			}
		}
	}
	if sum.ProviderPruned > 0 || sum.TenantPruned > 0 {
		r.log.Info("audit retention prune complete",
			"provider_pruned", sum.ProviderPruned,
			"tenant_pruned", sum.TenantPruned,
			"tenants_checked", sum.TenantsChecked,
			"retention", r.policy.Window.String())
	}
	return sum, nil
}

func (r *RetentionRunner) recordProviderPrune(ctx context.Context, pruned, watermark int64, cutoff time.Time) error {
	_, err := ProviderAppend(ctx, r.pool, "system:audit-retention", RetentionPruneAction, "provider",
		retentionReceiptData("provider", "", pruned, watermark, cutoff, r.policy.Window))
	if err != nil {
		return fmt.Errorf("record provider audit prune receipt: %w", err)
	}
	return nil
}

func (r *RetentionRunner) recordTenantPrune(ctx context.Context, tenantID string, pruned, watermark int64, cutoff time.Time) error {
	return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), r.pool,
		func(ctx context.Context, s tenancy.Scope) error {
			_, err := TenantAppend(ctx, s, "system:audit-retention", RetentionPruneAction, "audit/"+tenantID,
				retentionReceiptData("tenant", tenantID, pruned, watermark, cutoff, r.policy.Window))
			if err != nil {
				return fmt.Errorf("record tenant audit prune receipt: %w", err)
			}
			return nil
		})
}

func retentionReceiptData(stream, tenantID string, pruned, watermark int64, cutoff time.Time, window time.Duration) map[string]any {
	data := map[string]any{
		"stream":             stream,
		"pruned_rows":        pruned,
		"exported_watermark": watermark,
		"cutoff":             cutoff.UTC().Format(time.RFC3339),
		"retention_window":   window.String(),
	}
	if tenantID != "" {
		data["tenant_id"] = tenantID
	}
	return data
}

func listRetentionTenantIDs(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	rows, err := pool.Query(ctx, `SELECT id::text FROM tenants WHERE status <> 'deleted' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func tenantSIEMWatermark(ctx context.Context, pool *pgxpool.Pool, tenantID string) (int64, error) {
	var seq int64
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool,
		func(ctx context.Context, s tenancy.Scope) error {
			return s.Q.QueryRow(ctx,
				`SELECT last_seq FROM siem_delivery WHERE tenant_id = $1`, tenantID).Scan(&seq)
		})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return seq, err
}

// PruneProvider prunes the provider/break-glass stream. It deletes only events
// that are BOTH older than the retention window AND already durably exported
// (seq <= exportedWatermark) — fail closed: an un-exported or in-window event is
// never deleted. Returns the number of rows pruned. A disabled policy is a no-op.
//
// exportedWatermark is the highest provider seq the WORM exporter has signed into
// object storage (audit/worm). Pass 0 to prune nothing (nothing proven exported).
func PruneProvider(ctx context.Context, pool *pgxpool.Pool, p RetentionPolicy, exportedWatermark int64, now time.Time) (int64, error) {
	if !p.Enabled() || exportedWatermark <= 0 {
		return 0, nil
	}
	tag, err := pool.Exec(ctx,
		`WITH ordered AS (
		     SELECT seq,
		            (seq <= $1 AND created_at < $2) AS eligible,
		            bool_or(NOT (seq <= $1 AND created_at < $2))
		              OVER (ORDER BY seq ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS blocked
		       FROM provider_audit_events
		   ),
		   cut AS (
		     SELECT max(seq) AS seq FROM ordered WHERE eligible AND NOT blocked
		   )
		   DELETE FROM provider_audit_events
		    WHERE seq <= (SELECT seq FROM cut)`,
		exportedWatermark, p.cutoff(now))
	if err != nil {
		return 0, fmt.Errorf("prune provider audit: %w", err)
	}
	return tag.RowsAffected(), nil
}

// PruneTenant prunes one tenant's stream under the same fail-closed rule. The
// tenant's hash chain is independent, so its watermark is the highest tenant seq
// the SIEM/WORM export has durably captured for THAT tenant. Runs as the table
// owner via the pool (the app role cannot delete); the caller is responsible for
// having confirmed the export watermark out of band.
func PruneTenant(ctx context.Context, pool *pgxpool.Pool, tenantID string, p RetentionPolicy, exportedWatermark int64, now time.Time) (int64, error) {
	if !p.Enabled() || exportedWatermark <= 0 || tenantID == "" {
		return 0, nil
	}
	tag, err := pool.Exec(ctx,
		`WITH ordered AS (
		     SELECT seq,
		            (seq <= $2 AND created_at < $3 AND action <> $4) AS eligible,
		            bool_or(NOT (seq <= $2 AND created_at < $3 AND action <> $4))
		              OVER (ORDER BY seq ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS blocked
		       FROM audit_events
		      WHERE tenant_id = $1::uuid
		   ),
		   cut AS (
		     SELECT max(seq) AS seq FROM ordered WHERE eligible AND NOT blocked
		   )
		   DELETE FROM audit_events
		    WHERE tenant_id = $1::uuid AND seq <= (SELECT seq FROM cut)`,
		tenantID, exportedWatermark, p.cutoff(now), SubjectErasureAction)
	if err != nil {
		return 0, fmt.Errorf("prune tenant audit: %w", err)
	}
	return tag.RowsAffected(), nil
}
