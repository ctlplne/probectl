// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pathstore

import (
	"context"
	"errors"
)

// ErrHistoryBudget refuses the whole result when complete history cannot fit.
var ErrHistoryBudget = errors.New("pathstore: complete history exceeds operation memory admission")

type historyWireBudgetKey struct{}
type historyWireBudget struct{ remaining int64 }

func admitHistory(ctx context.Context, q HistoryQuery) (context.Context, int, int64, error) {
	if q.MaxBytes == 0 {
		return ctx, historyLimit(q.Limit), 0, nil
	}
	if q.MaxBytes < 4096 || q.MaxBytes >= int64(^uint(0)>>1) {
		return ctx, 0, 0, ErrHistoryBudget
	}
	remaining := q.MaxBytes / 2
	for _, id := range q.IDs {
		if err := chargeHistory(&remaining, 128+8*int64(len(id))); err != nil {
			return ctx, 0, 0, err
		}
	}
	// Every retained snapshot costs at least 2048 bytes below. The extra row
	// is an overflow sentinel, not a supported population ceiling.
	limit := int(remaining/2048 + 1)
	if len(q.IDs) > limit {
		return ctx, 0, 0, ErrHistoryBudget
	}
	// Reserve decoded map/string and projection space across all three
	// ClickHouse responses. This is shared by the operation, not per query.
	ctx = context.WithValue(ctx, historyWireBudgetKey{}, &historyWireBudget{remaining: q.MaxBytes / 32})
	return ctx, limit, remaining, nil
}

func chargeHistory(remaining *int64, amount int64) error {
	if amount < 0 || amount > *remaining {
		return ErrHistoryBudget
	}
	*remaining -= amount
	return nil
}

// Charge before cloning a retained round. Walk the typed structure rather
// than first allocating an unbounded JSON serialization to measure it.
func chargeHistorySnapshot(ctx context.Context, remaining *int64, snapshot Snapshot) error {
	p := snapshot.Path
	if err := chargeHistory(remaining, 2048+8*int64(len(snapshot.ID)+len(p.Target)+len(p.TargetIP)+len(p.Mode)+len(p.Vantage))); err != nil {
		return err
	}
	if f := p.MeasurementFidelity; f != nil {
		if err := chargeHistory(remaining, 512+8*int64(len(f.ProbeTransport)+len(f.AcquisitionMode)+len(f.TimingSource)+len(f.HopVisibility))); err != nil {
			return err
		}
	}
	for _, hop := range p.Hops {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := chargeHistory(remaining, 128); err != nil {
			return err
		}
		for _, node := range hop.Nodes {
			if err := chargeHistory(remaining, 512+8*int64(len(node.IP))+32*int64(len(node.MPLS))); err != nil {
				return err
			}
			if g := node.Geo; g != nil {
				if err := chargeHistory(remaining, 256+8*int64(len(g.City)+len(g.Country)+len(g.Source))); err != nil {
					return err
				}
			}
		}
	}
	for _, link := range p.Links {
		if err := chargeHistory(remaining, 256+8*int64(len(link.From)+len(link.To))); err != nil {
			return err
		}
	}
	return ctx.Err()
}
