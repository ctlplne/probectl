// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// SIEMDelivery is the per-tenant SIEM export cursor (S32, F26): the highest audit
// `seq` already forwarded to the operator's SIEM. The audit poller reads it on
// start and advances it only past delivered events, so a restart resumes without
// dropping (delivery is idempotent on the SIEM side regardless). RLS confines
// every row to the caller's tenant (F50).
//
// AUD-16: the row also carries a short-lived export CLAIM (claim_owner +
// claim_until). The poller POSTs a batch to the SIEM with NO transaction open
// (so a slow SIEM never holds a database connection), then advances the cursor
// in a short follow-up transaction. The claim is what serializes delivery across
// overlapping replicas during failover WITHOUT holding a txn across the network
// POST: a replica only forwards a page it holds the claim for, and the cursor
// advance is a compare-and-set on the last-exported position, so a page is never
// forwarded-and-committed twice and the cursor never advances past an event whose
// POST did not succeed (at-least-once).
type SIEMDelivery struct{}

// Cursor returns the tenant's last-forwarded audit seq (0 when none recorded).
func (SIEMDelivery) Cursor(ctx context.Context, s tenancy.Scope) (int64, error) {
	var seq int64
	err := s.Q.QueryRow(ctx,
		`SELECT last_seq FROM siem_delivery WHERE tenant_id = $1`, s.Tenant.String()).Scan(&seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return seq, nil
}

// Advance records seq as forwarded, monotonically (GREATEST) so an out-of-order
// call never rewinds the cursor. Production no longer calls it — the poller
// advances through ClaimPage + CommitCursor — but it remains the watermark
// setter the retention / isolation integration suites use to simulate SIEM
// export progress before asserting pruning (see dead_seams_allowlist.txt,
// alongside Cursor).
func (SIEMDelivery) Advance(ctx context.Context, s tenancy.Scope, seq int64) error {
	_, err := s.Q.Exec(ctx,
		`INSERT INTO siem_delivery (tenant_id, last_seq, updated_at)
		   VALUES ($1, $2, now())
		 ON CONFLICT (tenant_id)
		   DO UPDATE SET last_seq = GREATEST(siem_delivery.last_seq, EXCLUDED.last_seq),
		                 updated_at = now()`,
		s.Tenant.String(), seq)
	return err
}

// ClaimPage takes the tenant's export claim for owner and returns the current
// delivery cursor with held=true, so the caller may read and POST the next page.
// It grants the claim when the row is unclaimed, already owned by owner, or the
// prior owner's lease has expired; otherwise it leaves the existing claim in
// place and returns held=false (another replica is mid-flight — do not forward).
// The single conditional UPDATE takes the row lock for the duration of the
// caller's transaction, so two pollers calling it concurrently serialize and
// exactly one wins the claim. The claim itself is data that outlives the
// transaction, so it keeps serializing delivery while the POST runs with NO
// transaction open.
//
// Call this inside a SHORT read transaction that also reads the page; release
// that transaction before the network POST, then call CommitCursor (on success)
// or ReleaseClaim (nothing to send, or the POST failed).
func (SIEMDelivery) ClaimPage(ctx context.Context, s tenancy.Scope, owner string, lease time.Duration) (cursor int64, held bool, err error) {
	if owner == "" {
		return 0, false, errors.New("siem delivery claim requires an owner")
	}
	if _, err = s.Q.Exec(ctx,
		`INSERT INTO siem_delivery (tenant_id, last_seq, updated_at)
		 VALUES ($1, 0, now())
		 ON CONFLICT (tenant_id) DO NOTHING`, s.Tenant.String()); err != nil {
		return 0, false, err
	}
	leaseText := fmt.Sprintf("%d milliseconds", lease.Milliseconds())
	err = s.Q.QueryRow(ctx,
		`UPDATE siem_delivery
		    SET claim_owner = $2,
		        claim_until = now() + $3::interval,
		        updated_at  = now()
		  WHERE tenant_id = $1
		    AND (claim_owner IS NULL OR claim_owner = $2 OR claim_until < now())
		RETURNING last_seq`,
		s.Tenant.String(), owner, leaseText).Scan(&cursor)
	if errors.Is(err, pgx.ErrNoRows) {
		// The predicate failed: another owner holds an unexpired claim.
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return cursor, true, nil
}

// CommitCursor advances the cursor to `to` and clears owner's claim — but only
// if the stored cursor still equals `from` AND owner still holds the claim
// (compare-and-set). It returns committed=false when another actor moved the
// cursor or stole an expired claim; the caller then re-reads rather than
// rewinding. Because the caller invokes this ONLY after a successful batch POST,
// the cursor never advances past an event that was not delivered (at-least-once:
// a losing committer already delivered its page too, a duplicate the SIEM dedups
// on audit.seq). `to` must be greater than `from`.
func (SIEMDelivery) CommitCursor(ctx context.Context, s tenancy.Scope, owner string, from, to int64) (committed bool, err error) {
	if owner == "" {
		return false, errors.New("siem delivery commit requires an owner")
	}
	if to <= from {
		return false, fmt.Errorf("siem delivery cursor must advance: from=%d to=%d", from, to)
	}
	tag, err := s.Q.Exec(ctx,
		`UPDATE siem_delivery
		    SET last_seq    = $3,
		        claim_owner = NULL,
		        claim_until = NULL,
		        updated_at  = now()
		  WHERE tenant_id = $1
		    AND claim_owner = $2
		    AND last_seq = $4`,
		s.Tenant.String(), owner, to, from)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// ReleaseClaim clears owner's claim without moving the cursor — used when there
// is nothing to forward, or the POST failed, so the next tick can retry the page
// immediately instead of waiting for the lease to expire. It is a no-op when the
// claim is held by someone else.
func (SIEMDelivery) ReleaseClaim(ctx context.Context, s tenancy.Scope, owner string) error {
	if owner == "" {
		return errors.New("siem delivery release requires an owner")
	}
	_, err := s.Q.Exec(ctx,
		`UPDATE siem_delivery
		    SET claim_owner = NULL,
		        claim_until = NULL,
		        updated_at  = now()
		  WHERE tenant_id = $1
		    AND claim_owner = $2`,
		s.Tenant.String(), owner)
	return err
}
