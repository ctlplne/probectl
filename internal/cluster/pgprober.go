// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cluster

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGProber observes a Postgres endpoint: whether it is a read-only standby
// (pg_is_in_recovery), the current promotion epoch + writer region from the
// replicated cluster_state row, and — on a standby — the replay lag. None of
// these need elevated privileges: pg_is_in_recovery() and the lag function are
// public, and cluster_state is a normal replicated table.
type PGProber struct{ pool *pgxpool.Pool }

// NewPGProber wraps a pool (the writer or a reader endpoint).
func NewPGProber(pool *pgxpool.Pool) *PGProber { return &PGProber{pool: pool} }

// Probe runs one observation. A connection/query error surfaces as Probe.Err
// (the Manager classifies the node Unknown and fences writes).
func (p *PGProber) Probe(ctx context.Context) Probe {
	if p == nil || p.pool == nil {
		return Probe{Err: errors.New("cluster: no database pool")}
	}
	var pr Probe
	// pg_is_in_recovery() + replay lag (NULL on a primary → 0). lag is
	// seconds since the last replayed transaction's commit timestamp.
	var lag *float64
	if err := p.pool.QueryRow(ctx, `
		SELECT pg_is_in_recovery(),
		       CASE WHEN pg_is_in_recovery()
		            THEN EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))
		            ELSE NULL END`).Scan(&pr.InRecovery, &lag); err != nil {
		return Probe{Err: err}
	}
	if lag != nil && *lag > 0 {
		pr.LagSeconds = *lag
	}
	// The promotion epoch + writer region (replicated singleton). Absent row
	// (fresh deploy before the migration seed) is treated as epoch 0.
	if err := p.pool.QueryRow(ctx,
		`SELECT writer_epoch, writer_region FROM cluster_state WHERE id`).
		Scan(&pr.Epoch, &pr.WriterRegion); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Probe{Err: err}
	}
	return pr
}
