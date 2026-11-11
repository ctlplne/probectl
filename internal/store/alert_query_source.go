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
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrAlertQueryChanged = errors.New("alert saved-query configuration or state changed")

type AlertQuerySource struct {
	Source       alert.QuerySource
	State        alert.QueryGroupState
	StateVersion int64
	NextAt       *time.Time
}

func alertQueryScope(ctx context.Context, sc tenancy.Scope, expected time.Time, maxBytes int64) error {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || sc.Q == nil || sc.Tenant != tenant || sc.Tenant.String() == "" || expected.IsZero() {
		return tenancy.ErrNoTenant
	}
	if maxBytes < 8192 {
		return alert.ErrQueryGroups
	}
	return ctx.Err()
}

// GetQuerySource reads configuration and opaque group state only after the
// tenant has been bound. SQL admits their combined encoded bytes before any
// transfer; decoding and retained maps share the caller's memory allowance.
func (AlertRules) GetQuerySource(ctx context.Context, sc tenancy.Scope, id string, expected time.Time, maxBytes int64) (*AlertQuerySource, error) {
	if err := alertQueryScope(ctx, sc, expected, maxBytes); err != nil {
		return nil, err
	}
	var present bool
	var size int64
	var source, state []byte
	out := &AlertQuerySource{}
	err := sc.Q.QueryRow(ctx, `SELECT query_source IS NOT NULL,
 COALESCE(octet_length(query_source::text),0)::bigint+COALESCE(octet_length(query_group_state::text),0)::bigint,
 CASE WHEN COALESCE(octet_length(query_source::text),0)::bigint+COALESCE(octet_length(query_group_state::text),0)::bigint<=$4 THEN query_source::text END,
 CASE WHEN COALESCE(octet_length(query_source::text),0)::bigint+COALESCE(octet_length(query_group_state::text),0)::bigint<=$4 THEN query_group_state::text END,
 query_state_version,query_next_eval_at FROM alert_rules
 WHERE tenant_id=$1 AND id=$2 AND updated_at=$3`, sc.Tenant.String(), id, expected, maxBytes/8).
		Scan(&present, &size, &source, &state, &out.StateVersion, &out.NextAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAlertQueryChanged
	}
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, nil
	}
	if size <= 0 || size > maxBytes/8 || len(source) == 0 || out.StateVersion < 0 {
		return nil, alert.ErrQueryGroups
	}
	if err := json.Unmarshal(source, &out.Source); err != nil {
		return nil, err
	}
	if err := out.Source.Validate(); err != nil {
		return nil, err
	}
	if len(state) != 0 {
		if err := json.Unmarshal(state, &out.State); err != nil {
			return nil, err
		}
	}
	if (out.StateVersion == 0 && out.State.Initialized) || (out.StateVersion > 0 && !out.State.Initialized) {
		return nil, alert.ErrQueryGroups
	}
	if err := out.State.Validate(ctx, out.Source.Binding(sc.Tenant.String(), id), alert.QueryGroupBudget{MemoryBytes: maxBytes / 2, WorkUnits: maxBytes}); err != nil {
		return nil, err
	}
	return out, ctx.Err()
}

// The source parent and owner are selected through the same FORCE-RLS scope.
// Lock them through publication so a deleted/private/revised saved query or
// inactive configuring user cannot leave a newly published valid binding.
func lockAlertQueryParents(ctx context.Context, sc tenancy.Scope, source alert.QuerySource) error {
	version, err := flow.QueryViewVersion(source.ViewVersion)
	if err != nil {
		return err
	}
	var present int
	err = sc.Q.QueryRow(ctx, `SELECT 1 FROM flow_query_views v
 JOIN users u ON u.tenant_id=v.tenant_id AND u.id=$2::text::uuid AND u.status='active'
 WHERE v.tenant_id=$1 AND v.id=$3 AND v.version=$4
 AND (v.owner_id=$2::text OR v.visibility='tenant')
 AND ($5='new_group' OR EXISTS (SELECT 1 FROM jsonb_array_elements(v.definition->'plan'->'metrics') m
     WHERE (m->>'measure')||':'||(m->>'calculation')=$6)) FOR SHARE OF v,u`,
		sc.Tenant.String(), source.OwnerUserID, source.ViewID, version, source.Condition.Mode, source.Condition.Metric).Scan(&present)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrAlertQueryChanged
	}
	return err
}

func alertQueryEncode(value any, maxBytes int64) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	if int64(len(raw)) > maxBytes/8 {
		return "", alert.ErrQueryGroups
	}
	return string(raw), nil
}

// SetQuerySource is only configuration persistence. The caller must first run
// the complete source plan under current source authority/cost admission and
// recheck its authority in this writer transaction, recording the domain audit.
// Legacy metric/trap rules cannot accidentally acquire a different data path.
func (AlertRules) SetQuerySource(ctx context.Context, sc tenancy.Scope, id string, expected time.Time, source *alert.QuerySource, maxBytes int64) (*alert.Rule, error) {
	if err := alertQueryScope(ctx, sc, expected, maxBytes); err != nil {
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
		if err := lockAlertQueryParents(ctx, sc, *source); err != nil {
			return nil, err
		}
		encoded = value
	}
	var out alert.Rule
	err := scanAlertRule(sc.Q.QueryRow(ctx, `UPDATE alert_rules SET query_source=$4::jsonb,
 query_group_state=NULL,query_state_version=0,query_next_eval_at=NULL,updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND id=$2 AND updated_at=$3
 AND ($4::jsonb IS NULL OR (type='threshold' AND metric=$5 AND comparison='gte' AND threshold=1
     AND trap_match IS NULL AND tag_filter IS NULL)) RETURNING `+alertRuleCols,
		sc.Tenant.String(), id, expected, encoded, alert.QueryMetric), &out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAlertQueryChanged
	}
	if err != nil {
		return nil, err
	}
	if err := openChannelSecrets(ctx, sc.Tenant.String(), out.Channels); err != nil {
		return nil, err
	}
	return &out, nil
}

// CommitQueryState compares both rule and state versions. A late worker may
// neither advance a reconfigured rule nor overwrite a newer scheduled read.
// Current read authorization is the caller's separate publication obligation;
// stored IDs or a successful earlier query never replace that obligation.
func (AlertRules) CommitQueryState(ctx context.Context, sc tenancy.Scope, id string, expected time.Time, previous AlertQuerySource, next alert.QueryGroupState, maxBytes int64) error {
	if err := alertQueryScope(ctx, sc, expected, maxBytes); err != nil {
		return err
	}
	if previous.StateVersion < 0 || !next.Initialized || (previous.State.Initialized && !next.At.After(previous.State.At)) {
		return ErrAlertQueryChanged
	}
	if err := previous.Source.Validate(); err != nil {
		return err
	}
	if err := next.Validate(ctx, previous.Source.Binding(sc.Tenant.String(), id), alert.QueryGroupBudget{MemoryBytes: maxBytes / 2, WorkUnits: maxBytes}); err != nil {
		return err
	}
	source, err := alertQueryEncode(previous.Source, maxBytes/2)
	if err != nil {
		return err
	}
	state, err := alertQueryEncode(next, maxBytes/2)
	if err != nil {
		return err
	}
	if err := lockAlertQueryParents(ctx, sc, previous.Source); err != nil {
		return err
	}
	nextAt := next.At.Add(time.Duration(previous.Source.EverySeconds) * time.Second)
	tag, err := sc.Q.Exec(ctx, `UPDATE alert_rules SET query_group_state=$5::jsonb,
 query_state_version=query_state_version+1,query_next_eval_at=$6
 WHERE tenant_id=$1 AND id=$2 AND updated_at=$3 AND enabled
 AND query_source=$4::jsonb AND query_state_version=$7 AND query_state_version<9223372036854775807`,
		sc.Tenant.String(), id, expected, source, state, nextAt, previous.StateVersion)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrAlertQueryChanged
	}
	return ctx.Err()
}
