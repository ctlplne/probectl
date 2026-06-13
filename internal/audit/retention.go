// SPDX-License-Identifier: LicenseRef-probectl-TBD

package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
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
		`DELETE FROM provider_audit_events
		  WHERE seq <= $1 AND created_at < $2`,
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
		`DELETE FROM audit_events
		  WHERE tenant_id = $1::uuid AND seq <= $2 AND created_at < $3`,
		tenantID, exportedWatermark, p.cutoff(now))
	if err != nil {
		return 0, fmt.Errorf("prune tenant audit: %w", err)
	}
	return tag.RowsAffected(), nil
}
