// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrAlertDependencyChanged = errors.New("alert dependency configuration changed")
var ErrAlertDependencyBudget = errors.New("alert dependency operation memory admission refused")

// GetDependencyPolicy admits configuration bytes before transfer or decoding.
// It supplies no source grant; the actual reader must recheck current authority.
func (AlertRules) GetDependencyPolicy(ctx context.Context, sc tenancy.Scope, id string, expected time.Time, maxBytes int64) (*alert.DependencyPolicy, error) {
	if err := alertQueryScope(ctx, sc, expected, maxBytes); err != nil {
		return nil, err
	}
	var present bool
	var size int64
	var raw []byte
	err := sc.Q.QueryRow(ctx, `SELECT dependency_policy IS NOT NULL,
 COALESCE(octet_length(dependency_policy::text),0)::bigint,
 CASE WHEN COALESCE(octet_length(dependency_policy::text),0)::bigint<=$4 THEN dependency_policy::text END
 FROM alert_rules WHERE tenant_id=$1 AND id=$2 AND updated_at=$3`,
		sc.Tenant.String(), id, expected, maxBytes/8).Scan(&present, &size, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAlertDependencyChanged
	}
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, nil
	}
	if size > maxBytes/8 || len(raw) == 0 {
		return nil, ErrAlertDependencyBudget
	}
	var out alert.DependencyPolicy
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil {
		return nil, err
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return &out, ctx.Err()
}

// SetDependencyPolicy shares lifecycle -> rule row -> audit publication order
// with ordinary alert edits. Current owner/context are read through this same
// tenant scope; a callback must recheck the configuring credential's authority.
// Clearing removes notification policy only, preserving detection and sources.
func (AlertRules) SetDependencyPolicy(ctx context.Context, sc tenancy.Scope, id string, expected time.Time, policy *alert.DependencyPolicy, maxBytes int64, publication func(context.Context, tenancy.Scope) error) (*alert.Rule, error) {
	if err := alertQueryScope(ctx, sc, expected, maxBytes); err != nil {
		return nil, err
	}
	if publication == nil {
		return nil, alert.ErrDependencyEvidence
	}
	var encoded any
	if policy != nil {
		if err := policy.Validate(); err != nil {
			return nil, err
		}
		body, err := json.Marshal(policy)
		if err != nil {
			return nil, err
		}
		if int64(len(body)) > maxBytes/8 {
			return nil, ErrAlertDependencyBudget
		}
		encoded = string(body)
	}
	if err := lockAlertQueryRule(ctx, sc, id, expected); err != nil {
		if errors.Is(err, ErrAlertQueryChanged) {
			return nil, ErrAlertDependencyChanged
		}
		return nil, err
	}
	if policy != nil {
		var present int
		err := sc.Q.QueryRow(ctx, `SELECT 1 FROM entity_contexts c
 JOIN users u ON u.tenant_id=c.tenant_id AND u.id=$3 AND u.status='active'
 WHERE c.tenant_id=$1 AND c.id=$2`, sc.Tenant.String(), policy.ContextID, policy.OwnerUserID).Scan(&present)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAlertDependencyChanged
		}
		if err != nil {
			return nil, err
		}
		if err := ValidateDependencyGraphInScope(ctx, sc, policy.ContextID, policy.Graph, maxBytes); err != nil {
			return nil, err
		}
	}
	if err := publication(ctx, sc); err != nil {
		return nil, err
	}
	var out alert.Rule
	err := scanAlertRule(sc.Q.QueryRow(ctx, `UPDATE alert_rules SET dependency_policy=$4::jsonb,updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND id=$2 AND updated_at=$3 RETURNING `+alertRuleCols,
		sc.Tenant.String(), id, expected, encoded), &out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAlertDependencyChanged
	}
	if err != nil {
		return nil, err
	}
	if err := openChannelSecrets(ctx, sc.Tenant.String(), out.Channels); err != nil {
		return nil, err
	}
	return &out, nil
}
