// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/tenancy"
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

// RetentionAnchorRecoveredAction records the exceptional, verified recovery of
// a pre-0075 fully-pruned provider SQL head from signed WORM evidence.
const RetentionAnchorRecoveredAction = "audit.retention_anchor_recovered"

// ProviderWatermarkFunc returns the highest provider-audit seq proven durably
// exported. Returning 0 makes provider pruning fail closed.
type ProviderWatermarkFunc func(context.Context) (int64, error)

// ProviderRetentionProof is an opaque receipt minted by WormExporter only
// after cryptographic verification. Its fields are deliberately private so a
// raw caller-supplied integer cannot masquerade as IR coverage.
type ProviderRetentionProof struct {
	watermark  int64
	verified   bool
	irVerified bool
}

// ProviderRetentionProofFunc returns one opaque provider-retention receipt.
type ProviderRetentionProofFunc func(context.Context) (ProviderRetentionProof, error)

// TenantWatermarkFunc returns the highest tenant-audit seq proven durably
// exported for one tenant. Returning 0 makes tenant pruning fail closed.
type TenantWatermarkFunc func(context.Context, string) (int64, error)

// TenantIDsFunc returns tenants whose audit streams should be considered.
type TenantIDsFunc func(context.Context) ([]string, error)

// TenantRetentionWindowFunc returns one tenant's requested local audit window.
// A non-positive result inherits the deployment window. The runner applies the
// deployment bound itself, so a stale or faulty resolver can never loosen a
// positive deployment maximum.
type TenantRetentionWindowFunc func(context.Context, string) (time.Duration, error)

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
	providerProof     ProviderRetentionProofFunc
	tenantWatermark   TenantWatermarkFunc
	tenantIDs         TenantIDsFunc
	tenantWindow      TenantRetentionWindowFunc
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

// withTenantWatermarkForTest replaces the tenant watermark source.
func (r *RetentionRunner) withTenantWatermarkForTest(fn TenantWatermarkFunc) *RetentionRunner {
	r.tenantWatermark = fn
	return r
}

// WithProviderRetentionProof replaces the legacy raw WORM watermark with an
// opaque cryptographically verified receipt. Provider-plane runtime wiring
// uses this path once encrypted IR attribution is attached.
func (r *RetentionRunner) WithProviderRetentionProof(
	fn ProviderRetentionProofFunc,
) *RetentionRunner {
	r.providerProof = fn
	return r
}

// WithTenantIDsForTest replaces tenant enumeration.
func (r *RetentionRunner) WithTenantIDsForTest(fn TenantIDsFunc) *RetentionRunner {
	r.tenantIDs = fn
	return r
}

// WithTenantRetentionWindow attaches the tenant policy owner. The callback
// returns only a requested window; RetentionRunner remains the enforcement
// boundary that defaults and clamps it against the deployment policy.
func (r *RetentionRunner) WithTenantRetentionWindow(fn TenantRetentionWindowFunc) *RetentionRunner {
	r.tenantWindow = fn
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
	if r == nil || (!r.policy.Enabled() && r.tenantWindow == nil) {
		return sum, nil
	}
	now := r.now()
	if r.policy.Enabled() {
		switch {
		case r.providerProof != nil:
			proof, err := r.providerProof(ctx)
			if err != nil {
				return sum, fmt.Errorf("provider audit retention proof: %w", err)
			}
			pruned, err := pruneProviderWithProof(
				ctx,
				r.pool,
				r.policy,
				proof,
				now,
			)
			if err != nil {
				return sum, err
			}
			sum.ProviderPruned = pruned
		case r.providerWatermark != nil:
			watermark, err := r.providerWatermark(ctx)
			if err != nil {
				return sum, fmt.Errorf("provider audit watermark: %w", err)
			}
			pruned, err := PruneProvider(
				ctx,
				r.pool,
				r.policy,
				watermark,
				now,
			)
			if err != nil {
				return sum, err
			}
			sum.ProviderPruned = pruned
		}
	}
	tenants, err := r.tenantIDs(ctx)
	if err != nil {
		return sum, fmt.Errorf("list tenants for audit retention: %w", err)
	}
	sum.TenantsChecked = len(tenants)
	for _, tenantID := range tenants {
		policy := r.policy
		if r.tenantWindow != nil {
			requested, err := r.tenantWindow(ctx, tenantID)
			if err != nil {
				r.log.Warn("tenant audit retention policy failed", "tenant", tenantID, "error", err)
				continue
			}
			policy = effectiveTenantRetentionPolicy(r.policy, requested)
		}
		if !policy.Enabled() {
			continue
		}
		watermark, err := r.tenantWatermark(ctx, tenantID)
		if err != nil {
			r.log.Warn("tenant audit watermark failed", "tenant", tenantID, "error", err)
			continue
		}
		pruned, err := PruneTenant(ctx, r.pool, tenantID, policy, watermark, now)
		if err != nil {
			r.log.Warn("tenant audit prune failed", "tenant", tenantID, "error", err)
			continue
		}
		sum.TenantPruned += pruned
	}
	if sum.ProviderPruned > 0 || sum.TenantPruned > 0 {
		r.log.Info("audit retention prune complete",
			"provider_pruned", sum.ProviderPruned,
			"tenant_pruned", sum.TenantPruned,
			"tenants_checked", sum.TenantsChecked,
			"provider_retention", r.policy.Window.String())
	}
	return sum, nil
}

func effectiveTenantRetentionPolicy(deployment RetentionPolicy, requested time.Duration) RetentionPolicy {
	if requested <= 0 {
		return deployment
	}
	if !deployment.Enabled() || requested < deployment.Window {
		return RetentionPolicy{Window: requested}
	}
	return deployment
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

type providerPruneReceiptFunc func(
	context.Context,
	tenancy.Querier,
	map[string]any,
) error

type tenantPruneReceiptFunc func(
	context.Context,
	tenancy.Scope,
	map[string]any,
) error

// PruneProvider atomically advances the durable prune anchor, deletes the
// eligible provider prefix, and appends its audit receipt. The event deletion
// and receipt can therefore neither commit separately nor reset the stream
// behind the already-durable WORM cursor.
//
// exportedWatermark is the highest provider seq jointly verified by the WORM
// exporter and, once encrypted IR attribution is active, its independent
// companion-coverage chain. Pass 0 to prune nothing.
func PruneProvider(
	ctx context.Context,
	pool *pgxpool.Pool,
	p RetentionPolicy,
	exportedWatermark int64,
	now time.Time,
) (int64, error) {
	return pruneProviderWithReceipt(
		ctx,
		pool,
		p,
		exportedWatermark,
		now,
		func(ctx context.Context, q tenancy.Querier, data map[string]any) error {
			if _, err := providerAppendLocked(
				ctx,
				q,
				"system:audit-retention",
				RetentionPruneAction,
				"provider",
				data,
			); err != nil {
				return fmt.Errorf("append provider prune receipt: %w", err)
			}
			return nil
		},
	)
}

func pruneProviderWithProof(
	ctx context.Context,
	pool *pgxpool.Pool,
	p RetentionPolicy,
	proof ProviderRetentionProof,
	now time.Time,
) (int64, error) {
	return pruneProviderWithProofReceipt(
		ctx,
		pool,
		p,
		proof,
		now,
		func(ctx context.Context, q tenancy.Querier, data map[string]any) error {
			if _, err := providerAppendLocked(
				ctx,
				q,
				"system:audit-retention",
				RetentionPruneAction,
				"provider",
				data,
			); err != nil {
				return fmt.Errorf("append provider prune receipt: %w", err)
			}
			return nil
		},
	)
}

func pruneProviderWithReceipt(
	ctx context.Context,
	pool *pgxpool.Pool,
	p RetentionPolicy,
	exportedWatermark int64,
	now time.Time,
	receipt providerPruneReceiptFunc,
) (int64, error) {
	return pruneProviderWithProofReceipt(
		ctx,
		pool,
		p,
		ProviderRetentionProof{watermark: exportedWatermark},
		now,
		receipt,
	)
}

func pruneProviderWithProofReceipt(
	ctx context.Context,
	pool *pgxpool.Pool,
	p RetentionPolicy,
	proof ProviderRetentionProof,
	now time.Time,
	receipt providerPruneReceiptFunc,
) (int64, error) {
	exportedWatermark := proof.watermark
	if !p.Enabled() {
		return 0, nil
	}
	if exportedWatermark < 0 {
		return 0, fmt.Errorf("provider audit WORM watermark must be non-negative")
	}
	if exportedWatermark == 0 {
		return 0, nil
	}
	if receipt == nil {
		return 0, fmt.Errorf("prune provider audit: receipt appender is required")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin provider audit prune: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Defense in depth: once the IR coverage schema is installed, a raw
	// caller-supplied integer can never authorize a positive prune. The
	// tenant-scoped stage tables are deliberately not inspected globally:
	// FORCE RLS makes such a query empty under the production provider role.
	// Instead, the provider event stream holds pruning closed from the atomic
	// break-glass append until signed coverage exists, and the durable global
	// coverage chain holds it closed thereafter.
	var irCoverageInstalled bool
	if err := tx.QueryRow(
		ctx,
		`SELECT to_regclass(
		     'public.ir_attribution_worm_coverage_head'
		 ) IS NOT NULL`,
	).Scan(&irCoverageInstalled); err != nil {
		return 0, fmt.Errorf("check encrypted IR coverage state: %w", err)
	}
	if irCoverageInstalled {
		if !proof.verified {
			return 0, errors.New(
				"provider audit retention blocked: a verified WORM proof is required",
			)
		}
		var irCoveredSeq int64
		err := tx.QueryRow(
			ctx,
			`SELECT covered_seq
			   FROM public.ir_attribution_worm_coverage_head
			  WHERE singleton`,
		).Scan(&irCoveredSeq)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, errors.New(
				"provider audit retention blocked: encrypted IR WORM coverage head is missing",
			)
		}
		if err != nil {
			return 0, fmt.Errorf("read encrypted IR retention watermark: %w", err)
		}
		var coverageRows, protectedEvents bool
		if err := tx.QueryRow(
			ctx,
			`SELECT EXISTS (
			     SELECT 1
			       FROM public.ir_attribution_worm_coverage
			 )`,
		).Scan(&coverageRows); err != nil {
			return 0, fmt.Errorf("inspect encrypted IR coverage rows: %w", err)
		}
		if err := tx.QueryRow(
			ctx,
			`SELECT EXISTS (
			     SELECT 1
			       FROM provider_audit_events
			      WHERE lower(btrim(action)) LIKE '%breakglass%'
			         OR lower(btrim(action)) LIKE '%break\_glass%' ESCAPE '\'
			         OR lower(btrim(action)) LIKE '%break-glass%'
			 )`,
		).Scan(&protectedEvents); err != nil {
			return 0, fmt.Errorf("inspect protected provider audit state: %w", err)
		}
		if (irCoveredSeq > 0 || coverageRows || protectedEvents) &&
			!proof.irVerified {
			return 0, errors.New(
				"provider audit retention blocked: a verified encrypted IR coverage proof is required",
			)
		}
		if proof.irVerified && exportedWatermark > irCoveredSeq {
			return 0, fmt.Errorf(
				"provider audit retention blocked: requested watermark %d exceeds encrypted IR coverage %d",
				exportedWatermark,
				irCoveredSeq,
			)
		}
	}
	if err := lockProviderStream(ctx, tx); err != nil {
		return 0, fmt.Errorf("lock provider audit prune: %w", err)
	}
	head, err := ensureProviderStreamHead(ctx, tx)
	if err != nil {
		return 0, fmt.Errorf("read provider audit prune head: %w", err)
	}
	if err := validateProviderPruneWatermark(exportedWatermark, head); err != nil {
		return 0, err
	}
	if err := providerVerifyFromLocked(ctx, tx, head, 0); err != nil {
		return 0, fmt.Errorf("verify provider audit before prune: %w", err)
	}

	cutSeq, cutHash, pruned, err := deleteProviderPrefix(
		ctx,
		tx,
		exportedWatermark,
		p.cutoff(now),
	)
	if err != nil {
		return 0, err
	}
	if pruned == 0 {
		if err := tx.Commit(ctx); err != nil {
			return 0, fmt.Errorf("commit provider audit prune no-op: %w", err)
		}
		return 0, nil
	}
	if err := updateProviderPruneAnchor(ctx, tx, head, cutSeq, cutHash); err != nil {
		return 0, err
	}
	if err := receipt(
		ctx,
		tx,
		retentionReceiptData(
			"provider",
			"",
			pruned,
			exportedWatermark,
			p.cutoff(now),
			p.Window,
		),
	); err != nil {
		return 0, fmt.Errorf("record provider audit prune receipt: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit provider audit prune: %w", err)
	}
	return pruned, nil
}

// PruneTenant applies the same atomic retention transition to one tenant. The
// transaction runs as the least-privilege provider role because the app role
// has no DELETE grant on append-only audit rows. The provider's event and head
// policies are tenant-GUC scoped at PostgreSQL, every query also carries an
// explicit tenant predicate, and the receipt switches to the app role.
func PruneTenant(
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID string,
	p RetentionPolicy,
	exportedWatermark int64,
	now time.Time,
) (int64, error) {
	return pruneTenantWithReceipt(
		ctx,
		pool,
		tenantID,
		p,
		exportedWatermark,
		now,
		func(ctx context.Context, s tenancy.Scope, data map[string]any) error {
			if _, err := tenantAppendLocked(
				ctx,
				s,
				"system:audit-retention",
				RetentionPruneAction,
				"audit/"+tenantID,
				data,
			); err != nil {
				return fmt.Errorf("append tenant prune receipt: %w", err)
			}
			return nil
		},
	)
}

func pruneTenantWithReceipt(
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID string,
	p RetentionPolicy,
	exportedWatermark int64,
	now time.Time,
	receipt tenantPruneReceiptFunc,
) (int64, error) {
	if !p.Enabled() || exportedWatermark <= 0 || tenantID == "" {
		return 0, nil
	}
	if receipt == nil {
		return 0, fmt.Errorf("prune tenant audit: receipt appender is required")
	}
	var pruned int64
	tctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	err := tenancy.InTenantProviderMaintenance(
		tctx,
		pool,
		func(ctx context.Context, scope tenancy.Scope) error {
			if err := requireDatabaseRole(
				ctx,
				scope.Q,
				tenancy.ProviderRole,
			); err != nil {
				return fmt.Errorf("verify tenant audit maintenance role: %w", err)
			}
			if err := lockTenantStream(ctx, scope.Q, tenantID); err != nil {
				return fmt.Errorf("lock tenant audit prune: %w", err)
			}
			head, err := ensureTenantStreamHeadAtCursor(
				ctx,
				scope.Q,
				tenantID,
				exportedWatermark,
			)
			if err != nil {
				return fmt.Errorf("read tenant audit prune head: %w", err)
			}
			if err := tenantVerifyFromLocked(ctx, scope, head, 0); err != nil {
				return fmt.Errorf("verify tenant audit before prune: %w", err)
			}

			cutSeq, cutHash, deleted, err := deleteTenantPrefix(
				ctx,
				scope.Q,
				tenantID,
				exportedWatermark,
				p.cutoff(now),
			)
			if err != nil {
				return err
			}
			if deleted == 0 {
				return nil
			}
			if err := updateTenantPruneAnchor(
				ctx,
				scope.Q,
				tenantID,
				head,
				cutSeq,
				cutHash,
			); err != nil {
				return err
			}

			// Deletion is a tenant-GUC-scoped provider capability; the mandatory
			// receipt is ordinary tenant audit DML and must prove it works as
			// the NOBYPASSRLS app role in this same routed transaction.
			if _, err := scope.Q.Exec(
				ctx,
				"SET LOCAL ROLE "+pgx.Identifier{tenancy.AppRole}.Sanitize(),
			); err != nil {
				return fmt.Errorf("assume app role for tenant prune receipt: %w", err)
			}
			if err := receipt(
				ctx,
				scope,
				retentionReceiptData(
					"tenant",
					tenantID,
					deleted,
					exportedWatermark,
					p.cutoff(now),
					p.Window,
				),
			); err != nil {
				return fmt.Errorf("record tenant audit prune receipt: %w", err)
			}
			pruned = deleted
			return nil
		},
	)
	if err != nil {
		return 0, err
	}
	return pruned, nil
}

func validateProviderPruneWatermark(watermark int64, head streamHead) error {
	if watermark < head.PrunedSeq {
		return fmt.Errorf(
			"provider audit WORM watermark %d is behind prune anchor %d",
			watermark,
			head.PrunedSeq,
		)
	}
	if watermark > head.HeadSeq {
		return fmt.Errorf(
			"provider audit WORM watermark %d is above durable head %d",
			watermark,
			head.HeadSeq,
		)
	}
	return nil
}

func requireDatabaseRole(
	ctx context.Context,
	q tenancy.Querier,
	want string,
) error {
	var got string
	if err := q.QueryRow(ctx, `SELECT current_user`).Scan(&got); err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("current database role is %q, want %q", got, want)
	}
	return nil
}

func deleteProviderPrefix(
	ctx context.Context,
	q tenancy.Querier,
	exportedWatermark int64,
	cutoff time.Time,
) (cutSeq int64, cutHash string, pruned int64, err error) {
	err = q.QueryRow(
		ctx,
		`WITH ordered AS (
		     SELECT seq,
		            hash,
		            (seq <= $1 AND created_at < $2) AS eligible,
		            bool_or(NOT (seq <= $1 AND created_at < $2))
		              OVER (ORDER BY seq ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS blocked
		       FROM provider_audit_events
		   ),
		   cut AS (
		     SELECT seq, hash
		       FROM ordered
		      WHERE eligible AND NOT blocked
		      ORDER BY seq DESC
		      LIMIT 1
		   ),
		   deleted AS (
		     DELETE FROM provider_audit_events
		      WHERE seq <= (SELECT seq FROM cut)
		      RETURNING seq
		   )
		   SELECT COALESCE((SELECT seq FROM cut), 0),
		          COALESCE((SELECT hash FROM cut), ''),
		          count(*)
		     FROM deleted`,
		exportedWatermark,
		cutoff,
	).Scan(&cutSeq, &cutHash, &pruned)
	if err != nil {
		return 0, "", 0, fmt.Errorf("prune provider audit: %w", err)
	}
	return cutSeq, cutHash, pruned, nil
}

func deleteTenantPrefix(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
	exportedWatermark int64,
	cutoff time.Time,
) (cutSeq int64, cutHash string, pruned int64, err error) {
	err = q.QueryRow(
		ctx,
		`WITH ordered AS (
		     SELECT seq,
		            hash,
		            (seq <= $2 AND created_at < $3) AS eligible,
		            bool_or(NOT (seq <= $2 AND created_at < $3))
		              OVER (ORDER BY seq ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS blocked
		       FROM audit_events
		      WHERE tenant_id = $1::uuid
		   ),
		   cut AS (
		     SELECT seq, hash
		       FROM ordered
		      WHERE eligible AND NOT blocked
		      ORDER BY seq DESC
		      LIMIT 1
		   )
		   SELECT COALESCE((SELECT seq FROM cut), 0),
		          COALESCE((SELECT hash FROM cut), '')`,
		tenantID,
		exportedWatermark,
		cutoff,
	).Scan(&cutSeq, &cutHash)
	if err != nil {
		return 0, "", 0, fmt.Errorf("prune tenant audit: %w", err)
	}
	if cutSeq == 0 {
		return 0, "", 0, nil
	}

	// Rolling deployments can still have an old writer that records only the
	// immutable privacy.subject_erase event. Capture every marker in the prefix
	// into the routed, append-only projection table before deleting any event.
	// A malformed marker violates the target constraint and rolls this whole
	// retention transaction back rather than silently losing a projection.
	if _, err := q.Exec(
		ctx,
		`INSERT INTO audit_subject_erasures
		    (tenant_id, subject_hash, created_at)
		 SELECT tenant_id,
		        data->>'subject_hash',
		        min(created_at)
		   FROM audit_events
		  WHERE tenant_id = $1::uuid
		    AND seq <= $2
		    AND action = $3
		  GROUP BY tenant_id, data->>'subject_hash'
		 ON CONFLICT (tenant_id, subject_hash) DO NOTHING`,
		tenantID,
		cutSeq,
		SubjectErasureAction,
	); err != nil {
		return 0, "", 0, fmt.Errorf("capture tenant audit subject erasures: %w", err)
	}

	tag, err := q.Exec(
		ctx,
		`DELETE FROM audit_events
		  WHERE tenant_id = $1::uuid
		    AND seq <= $2`,
		tenantID,
		cutSeq,
	)
	if err != nil {
		return 0, "", 0, fmt.Errorf("prune tenant audit: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return 0, "", 0, fmt.Errorf("prune tenant audit: eligible prefix disappeared")
	}
	return cutSeq, cutHash, tag.RowsAffected(), nil
}

func updateProviderPruneAnchor(
	ctx context.Context,
	q tenancy.Querier,
	head streamHead,
	cutSeq int64,
	cutHash string,
) error {
	tag, err := q.Exec(
		ctx,
		`UPDATE provider_audit_stream_head
		    SET pruned_seq = $1,
		        pruned_hash = $2,
		        updated_at = now()
		  WHERE singleton
		    AND head_seq = $3
		    AND head_hash = $4
		    AND pruned_seq < $1`,
		cutSeq,
		cutHash,
		head.HeadSeq,
		head.HeadHash,
	)
	if err != nil {
		return fmt.Errorf("advance provider audit prune anchor: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("advance provider audit prune anchor: non-monotonic state transition")
	}
	return nil
}

func updateTenantPruneAnchor(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
	head streamHead,
	cutSeq int64,
	cutHash string,
) error {
	tag, err := q.Exec(
		ctx,
		`UPDATE public.audit_stream_heads
		    SET pruned_seq = $2,
		        pruned_hash = $3,
		        updated_at = now()
		  WHERE tenant_id = $1::uuid
		    AND head_seq = $4
		    AND head_hash = $5
		    AND pruned_seq < $2`,
		tenantID,
		cutSeq,
		cutHash,
		head.HeadSeq,
		head.HeadHash,
	)
	if err != nil {
		return fmt.Errorf("advance tenant audit prune anchor: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("advance tenant audit prune anchor: non-monotonic state transition")
	}
	return nil
}
