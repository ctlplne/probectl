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

var ErrAlertSeasonalChanged = errors.New("alert seasonal source changed or is unavailable")

func (r AlertRules) WithSeasonalPublication(ctx context.Context, sc tenancy.Scope, id string, expected time.Time, maxBytes int64, publish func(context.Context, tenancy.Scope, *alert.SeasonalSource) error) error {
	if err := alertQueryScope(ctx, sc, expected, maxBytes); err != nil {
		return err
	}
	if publish == nil {
		return alert.ErrSeasonalSource
	}
	if err := lockAlertQueryRule(ctx, sc, id, expected); err != nil {
		return err
	}
	source, err := r.GetSeasonalSource(ctx, sc, id, expected, maxBytes)
	if err != nil {
		return err
	}
	if source == nil {
		return ErrAlertSeasonalChanged
	}
	return publish(ctx, sc, source)
}

// GetSeasonalSource checks the exact tenant and revision before selecting the
// private source authority. Postgres applies the budget before transfer.
func (AlertRules) GetSeasonalSource(ctx context.Context, sc tenancy.Scope, id string, expected time.Time, maxBytes int64) (*alert.SeasonalSource, error) {
	if err := alertQueryScope(ctx, sc, expected, maxBytes); err != nil {
		return nil, err
	}
	var present bool
	var size int64
	var raw []byte
	err := sc.Q.QueryRow(ctx, `SELECT seasonal_source IS NOT NULL,
 COALESCE(octet_length(seasonal_source::text),0)::bigint,
 CASE WHEN COALESCE(octet_length(seasonal_source::text),0)::bigint<=$4 THEN seasonal_source::text END
 FROM alert_rules WHERE tenant_id=$1 AND id=$2 AND updated_at=$3 AND type='baseline'`,
		sc.Tenant.String(), id, expected, maxBytes/8).Scan(&present, &size, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAlertSeasonalChanged
	}
	if err != nil || !present {
		return nil, err
	}
	if size <= 0 || size > maxBytes/8 || len(raw) == 0 {
		return nil, alert.ErrSeasonalSource
	}
	var source alert.SeasonalSource
	if err := json.Unmarshal(raw, &source); err != nil {
		return nil, err
	}
	if _, err := source.CredentialCeiling(sc.Tenant.String()); err != nil {
		return nil, err
	}
	return &source, nil
}

// SetSeasonalSource keeps the revision-bound selection and its authority in
// the normal tenant rule. The caller supplies current source checks under the
// same row and audit locks used by other alert source edits.
func (AlertRules) SetSeasonalSource(ctx context.Context, sc tenancy.Scope, id string, expected time.Time, source *alert.SeasonalSource, maxBytes int64, publication func(context.Context, tenancy.Scope) error) (*alert.Rule, error) {
	if err := alertQueryScope(ctx, sc, expected, maxBytes); err != nil {
		return nil, err
	}
	if publication == nil {
		return nil, alert.ErrSeasonalSource
	}
	if err := lockAlertQueryRule(ctx, sc, id, expected); err != nil {
		return nil, err
	}
	var encoded any
	if source != nil {
		if _, err := source.CredentialCeiling(sc.Tenant.String()); err != nil {
			return nil, err
		}
		value, err := alertQueryEncode(source, maxBytes)
		if err != nil {
			return nil, err
		}
		encoded = value
	}
	if err := publication(ctx, sc); err != nil {
		return nil, err
	}
	var out alert.Rule
	err := scanAlertRule(sc.Q.QueryRow(ctx, `UPDATE alert_rules SET seasonal_source=$4::jsonb, seasonal_last_window_at=NULL,
 enabled=CASE WHEN $4::jsonb IS NULL THEN false ELSE enabled END, updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND id=$2 AND updated_at=$3 AND type='baseline'
 AND query_source IS NULL AND path_health_source IS NULL AND tag_filter IS NULL AND dependency_policy IS NULL
 RETURNING `+alertRuleCols, sc.Tenant.String(), id, expected, encoded), &out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAlertSeasonalChanged
	}
	if err != nil {
		return nil, err
	}
	if err := openChannelSecrets(ctx, sc.Tenant.String(), out.Channels); err != nil {
		return nil, err
	}
	return &out, nil
}
