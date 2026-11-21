// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"cmp"
	"context"
	"errors"
	"math"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrSyslogPatternSelection = errors.New("device syslog patterns require an exact observation interval")
var ErrSyslogPatternBudget = errors.New("device syslog pattern input budget is exhausted")

type SyslogPatternSelection struct {
	Device       string
	PatternID    string
	From         time.Time
	To           time.Time
	Limit        int
	MaxInputRows int64
}

type SyslogPatternCount struct {
	ID      string            `json:"id"`
	Version int               `json:"version"`
	Kind    SyslogPatternKind `json:"kind"`
	Count   int64             `json:"count"`
	FirstAt time.Time         `json:"first_at"`
	LastAt  time.Time         `json:"last_at"`
}

type SyslogPatternCounts struct {
	Patterns      []SyslogPatternCount `json:"patterns"`
	IndexedRows   int64                `json:"indexed_rows"`
	UnindexedRows int64                `json:"unindexed_rows"`
	TotalPatterns int64                `json:"total_patterns"`
}

func (selection SyslogPatternSelection) validate(ctx context.Context, tenant string) error {
	current, ok := tenancy.FromContext(ctx)
	if !ok || tenant == "" || tenant != current.String() {
		return tenancy.ErrNoTenant
	}
	if selection.From.IsZero() || !selection.From.Before(selection.To) || selection.Limit <= 0 ||
		selection.MaxInputRows < 1 || selection.MaxInputRows == math.MaxInt64 {
		return ErrSyslogPatternSelection
	}
	return ctx.Err()
}

func (m *MemoryOpsStore) ListSyslogPatterns(ctx context.Context, tenant string, selection SyslogPatternSelection) (SyslogPatternCounts, error) {
	var result SyslogPatternCounts
	if err := selection.validate(ctx, tenant); err != nil {
		return result, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	counts := make(map[string]SyslogPatternCount)
	for _, row := range m.syslog[tenant] {
		if err := ctx.Err(); err != nil {
			return SyslogPatternCounts{}, err
		}
		if row.ObservedAt.Before(selection.From) || !row.ObservedAt.Before(selection.To) ||
			selection.Device != "" && row.Device != selection.Device {
			continue
		}
		if result.IndexedRows+result.UnindexedRows == selection.MaxInputRows {
			return SyslogPatternCounts{}, ErrSyslogPatternBudget
		}
		if row.PatternID == "" {
			result.UnindexedRows++
			continue
		}
		result.IndexedRows++
		count, found := counts[row.PatternID]
		if !found {
			count = SyslogPatternCount{ID: row.PatternID, Version: row.PatternVersion, Kind: row.PatternKind, FirstAt: row.ObservedAt, LastAt: row.ObservedAt}
		}
		count.Count++
		if row.ObservedAt.Before(count.FirstAt) {
			count.FirstAt = row.ObservedAt
		}
		if row.ObservedAt.After(count.LastAt) {
			count.LastAt = row.ObservedAt
		}
		counts[row.PatternID] = count
	}
	result.Patterns = make([]SyslogPatternCount, 0, len(counts))
	for _, count := range counts {
		if selection.PatternID == "" || count.ID == selection.PatternID {
			result.Patterns = append(result.Patterns, count)
		}
	}
	slices.SortFunc(result.Patterns, func(a, b SyslogPatternCount) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.ID, b.ID), cmp.Compare(a.Version, b.Version))
	})
	result.TotalPatterns = int64(len(counts))
	result.Patterns = result.Patterns[:min(len(result.Patterns), selection.Limit)]
	return result, nil
}

// ListSyslogPatterns reads only the caller's stored population across the
// original receiver interval. Old rows remain visible in coverage counts.
func (s *PostgresOpsStore) ListSyslogPatterns(ctx context.Context, tenant string, selection SyslogPatternSelection) (SyslogPatternCounts, error) {
	var result SyslogPatternCounts
	if err := selection.validate(ctx, tenant); err != nil {
		return result, err
	}
	result.Patterns = []SyslogPatternCount{}
	err := s.inTenant(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `
WITH matched AS (
    SELECT pattern_id, pattern_version, pattern_kind, observed_at
      FROM device_syslog
     WHERE tenant_id=$1 AND observed_at >= $2 AND observed_at < $3
       AND ($4 = '' OR device=$4)
     LIMIT $6
),
grouped AS (
    SELECT pattern_id, pattern_version, pattern_kind, count(*) AS occurrences,
           min(observed_at) AS first_at, max(observed_at) AS last_at
      FROM matched
     GROUP BY pattern_id, pattern_version, pattern_kind
),
coverage AS (
    SELECT coalesce(sum(occurrences) FILTER (WHERE pattern_id IS NOT NULL), 0)::bigint AS indexed_rows,
           coalesce(sum(occurrences) FILTER (WHERE pattern_id IS NULL), 0)::bigint AS unindexed_rows,
           count(*) FILTER (WHERE pattern_id IS NOT NULL) AS total_patterns
      FROM grouped
)
SELECT coverage.indexed_rows, coverage.unindexed_rows, coverage.total_patterns,
       chosen.pattern_id, chosen.pattern_version, chosen.pattern_kind,
       chosen.occurrences, chosen.first_at, chosen.last_at
  FROM coverage
  LEFT JOIN LATERAL (
    SELECT pattern_id, pattern_version, pattern_kind, occurrences, first_at, last_at
      FROM grouped
     WHERE pattern_id IS NOT NULL AND ($7 = '' OR pattern_id=$7)
     ORDER BY occurrences DESC, pattern_id, pattern_version
     LIMIT $5
  ) AS chosen ON TRUE
 ORDER BY chosen.occurrences DESC NULLS LAST, chosen.pattern_id, chosen.pattern_version
`, tenant, selection.From.UTC(), selection.To.UTC(), selection.Device, selection.Limit, selection.MaxInputRows+1, selection.PatternID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, kind *string
			var version *int
			var count *int64
			var first, last *time.Time
			if err := rows.Scan(&result.IndexedRows, &result.UnindexedRows, &result.TotalPatterns, &id, &version, &kind, &count, &first, &last); err != nil {
				return err
			}
			if result.IndexedRows+result.UnindexedRows > selection.MaxInputRows {
				return ErrSyslogPatternBudget
			}
			if id == nil {
				continue
			}
			if version == nil || kind == nil || count == nil || first == nil || last == nil {
				return ErrSyslogPatternSelection
			}
			result.Patterns = append(result.Patterns, SyslogPatternCount{ID: *id, Version: *version, Kind: SyslogPatternKind(*kind),
				Count: *count, FirstAt: first.UTC(), LastAt: last.UTC()})
		}
		return rows.Err()
	})
	if err != nil {
		return SyslogPatternCounts{}, err
	}
	return result, nil
}
