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
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrAlertPathHealthChanged = errors.New("alert path-health configuration changed or is unavailable")

// Configuration is selected through FORCE-RLS and the expected rule revision.
// SQL bounds encoded bytes before transfer; the operation owns decode memory.
func (AlertRules) GetPathHealthSource(ctx context.Context, sc tenancy.Scope, id string, expected time.Time, maxBytes int64) (*alert.PathHealthSource, error) {
	if err := alertQueryScope(ctx, sc, expected, maxBytes); err != nil {
		return nil, err
	}
	var present bool
	var size int64
	var raw []byte
	err := sc.Q.QueryRow(ctx, `SELECT path_health_source IS NOT NULL,
 COALESCE(octet_length(path_health_source::text),0)::bigint,
 CASE WHEN COALESCE(octet_length(path_health_source::text),0)::bigint<=$4 THEN path_health_source::text END
 FROM alert_rules WHERE tenant_id=$1 AND id=$2 AND updated_at=$3 AND metric=$5`,
		sc.Tenant.String(), id, expected, maxBytes/8, alert.PathHealthMetric).Scan(&present, &size, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAlertPathHealthChanged
	}
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, nil
	}
	if size <= 0 || size > maxBytes/8 || len(raw) == 0 {
		return nil, alert.ErrPathHealthSource
	}
	var source alert.PathHealthSource
	if err := json.Unmarshal(raw, &source); err != nil {
		return nil, err
	}
	if err := source.Validate(); err != nil {
		return nil, err
	}
	return &source, nil
}

// SetPathHealthSource persists configuration only. The caller must authorize a
// complete current source read and repeat publication checks in this writer
// scope. Existing alert notification state owns episode/restart deduplication.
func (AlertRules) SetPathHealthSource(ctx context.Context, sc tenancy.Scope, id string, expected time.Time, source *alert.PathHealthSource, maxBytes int64, publication func(context.Context, tenancy.Scope) error) (*alert.Rule, error) {
	if err := alertQueryScope(ctx, sc, expected, maxBytes); err != nil {
		return nil, err
	}
	if publication == nil {
		return nil, alert.ErrPathHealthSource
	}
	if err := lockAlertQueryRule(ctx, sc, id, expected); err != nil {
		return nil, err
	}
	var encoded any
	if source != nil {
		if err := source.Validate(); err != nil {
			return nil, err
		}
		value, err := alertQueryEncode(source, maxBytes)
		if err != nil {
			return nil, err
		}
		var present int
		err = sc.Q.QueryRow(ctx, `SELECT 1 FROM users u WHERE u.tenant_id=$1 AND u.id=$2 AND u.status='active'
 AND EXISTS (SELECT 1 FROM tests t WHERE t.tenant_id=$1 AND t.id=$3)
 AND EXISTS (SELECT 1 FROM entities e WHERE e.tenant_id=$1 AND e.id=$4 AND e.kind='interface')`,
			sc.Tenant.String(), source.OwnerUserID, source.TestID, source.InterfaceID).Scan(&present)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAlertPathHealthChanged
		}
		if err != nil {
			return nil, err
		}
		encoded = value
	}
	if err := publication(ctx, sc); err != nil {
		return nil, err
	}
	var out alert.Rule
	err := scanAlertRule(sc.Q.QueryRow(ctx, `UPDATE alert_rules SET path_health_source=$4::jsonb,
 enabled=CASE WHEN $4::jsonb IS NULL THEN false ELSE enabled END,updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND id=$2 AND updated_at=$3 AND metric=$5
 AND type='threshold' AND comparison='gte' AND threshold=1 AND match_labels='{}'::jsonb
 AND window_n=0 AND sensitivity=0 AND trap_match IS NULL AND tag_filter IS NULL AND query_source IS NULL
 RETURNING `+alertRuleCols, sc.Tenant.String(), id, expected, encoded, alert.PathHealthMetric), &out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAlertPathHealthChanged
	}
	if err != nil {
		return nil, err
	}
	if err := openChannelSecrets(ctx, sc.Tenant.String(), out.Channels); err != nil {
		return nil, err
	}
	return &out, nil
}
