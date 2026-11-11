// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrAlertTagFilterChanged = errors.New("alert metadata configuration changed; read the rule again")

// GetTagFilter loads only one already tenant-owned rule configuration and only
// at the caller's captured rule version. SQL withholds oversized JSON before
// transfer; reserve decoding/normalization memory in addition to encoded bytes.
// An owner ID inside the returned record is not authorization to read data.
func (AlertRules) GetTagFilter(ctx context.Context, sc tenancy.Scope, id string, expected time.Time, maxBytes int64) (*alert.TagFilter, error) {
	if sc.Tenant.String() == "" || sc.Q == nil || expected.IsZero() {
		return nil, tags.ErrScopeMismatch
	}
	if maxBytes < 8 {
		return nil, ErrTagSnapshotBudget
	}
	var present bool
	var size int64
	var raw []byte
	err := sc.Q.QueryRow(ctx, `SELECT tag_filter IS NOT NULL,
		COALESCE(octet_length(tag_filter::text),0)::bigint,
		CASE WHEN octet_length(tag_filter::text)<=$4 THEN tag_filter::text ELSE NULL END
		FROM alert_rules WHERE tenant_id=$1 AND id=$2 AND updated_at=$3`,
		sc.Tenant.String(), id, expected, maxBytes/8).Scan(&present, &size, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAlertTagFilterChanged
	}
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, nil
	}
	if size <= 0 || size > maxBytes/8 || len(raw) == 0 {
		return nil, ErrTagSnapshotBudget
	}
	var filter alert.TagFilter
	if err := json.Unmarshal(raw, &filter); err != nil {
		return nil, err
	}
	if err := filter.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &filter, nil
}

// SetTagFilter changes only metadata configuration in the caller's existing
// FORCE-RLS rule. Preparation/owner authority and domain audit belong to the
// same caller transaction. A nil filter is an explicit clear, not a read error.
func (AlertRules) SetTagFilter(ctx context.Context, sc tenancy.Scope, id string, expected time.Time, filter *alert.TagFilter) (*alert.Rule, error) {
	if sc.Tenant.String() == "" || sc.Q == nil || expected.IsZero() {
		return nil, tags.ErrScopeMismatch
	}
	var encoded any
	if filter != nil {
		if err := filter.Validate(); err != nil {
			return nil, err
		}
		raw, err := json.Marshal(filter)
		if err != nil {
			return nil, err
		}
		if len(raw) > 8<<20 {
			return nil, ErrTagSnapshotBudget
		}
		encoded = string(raw)
	}
	var out alert.Rule
	err := scanAlertRule(sc.Q.QueryRow(ctx, `UPDATE alert_rules SET tag_filter=$4::jsonb,updated_at=now()
		WHERE tenant_id=$1 AND id=$2 AND updated_at=$3
		AND ($4::jsonb IS NULL OR (query_source IS NULL AND metric<>$5)) RETURNING `+alertRuleCols,
		sc.Tenant.String(), id, expected, encoded, alert.QueryMetric), &out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAlertTagFilterChanged
	}
	if err != nil {
		return nil, mapWriteErr("alert rule", err)
	}
	if err := openChannelSecrets(ctx, sc.Tenant.String(), out.Channels); err != nil {
		return nil, err
	}
	return &out, nil
}
