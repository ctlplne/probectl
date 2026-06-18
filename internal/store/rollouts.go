// SPDX-License-Identifier: LicenseRef-probectl-TBD

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// Rollouts persists staged fleet rollout plans and their operator-visible event
// ledger. Rows are tenant-confined by Postgres RLS; callers must run inside
// tenancy.InTenant so storage, not handler code alone, is the isolation wall.
type Rollouts struct{}

// RolloutRecord is one persisted staged-rollout plan.
type RolloutRecord struct {
	ID        string
	TenantID  string
	Plan      json.RawMessage
	Revision  int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

func validateRolloutPlanJSON(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("rollout plan json is empty")
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return raw, nil
}

func scanRollout(row interface{ Scan(...any) error }, r *RolloutRecord) error {
	var raw []byte
	if err := row.Scan(&r.ID, &r.TenantID, &raw, &r.Revision, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return notFound("rollout", err)
	}
	r.Plan = append(r.Plan[:0], raw...)
	return nil
}

const rolloutCols = `rollout_id, tenant_id::text, plan, revision, created_at, updated_at`

// Create stores a freshly planned rollout. The caller supplies the id so the
// Location header and audit entry are stable inside the same request.
func (Rollouts) Create(ctx context.Context, s tenancy.Scope, id string, plan json.RawMessage) (*RolloutRecord, error) {
	raw, err := validateRolloutPlanJSON(plan)
	if err != nil {
		return nil, err
	}
	var r RolloutRecord
	if err := scanRollout(s.Q.QueryRow(ctx,
		`INSERT INTO rollout_plans (tenant_id, rollout_id, plan)
		 VALUES (current_setting('probectl.tenant_id')::uuid, $1, $2::jsonb)
		 RETURNING `+rolloutCols,
		id, raw), &r); err != nil {
		return nil, mapWriteErr("rollout", err)
	}
	return &r, nil
}

// Get returns one rollout for the current tenant. A matching id in another
// tenant is invisible because RLS filters it out before scanRollout runs.
func (Rollouts) Get(ctx context.Context, s tenancy.Scope, id string) (*RolloutRecord, error) {
	var r RolloutRecord
	if err := scanRollout(s.Q.QueryRow(ctx,
		`SELECT `+rolloutCols+` FROM rollout_plans WHERE rollout_id = $1`, id), &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// List returns persisted rollout plans for the current tenant, newest first.
func (Rollouts) List(ctx context.Context, s tenancy.Scope) ([]RolloutRecord, error) {
	rows, err := s.Q.Query(ctx,
		`SELECT `+rolloutCols+` FROM rollout_plans ORDER BY updated_at DESC, rollout_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RolloutRecord
	for rows.Next() {
		var r RolloutRecord
		if err := scanRollout(rows, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Update advances the plan with optimistic concurrency. A stale revision means
// another operator/process changed the rollout after this request read it.
func (Rollouts) Update(ctx context.Context, s tenancy.Scope, id string, expectedRevision int64, plan json.RawMessage) (int64, error) {
	raw, err := validateRolloutPlanJSON(plan)
	if err != nil {
		return 0, err
	}
	var rev int64
	err = s.Q.QueryRow(ctx,
		`UPDATE rollout_plans
		    SET plan = $3::jsonb, revision = revision + 1, updated_at = now()
		  WHERE rollout_id = $1 AND revision = $2
		  RETURNING revision`,
		id, expectedRevision, raw).Scan(&rev)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, apierror.Conflict("rollout changed; reload before retrying")
		}
		return 0, err
	}
	return rev, nil
}

// AppendEvent records an operator-visible transition for audit/debug replay.
func (Rollouts) AppendEvent(ctx context.Context, s tenancy.Scope, id, action string, plan json.RawMessage) error {
	raw, err := validateRolloutPlanJSON(plan)
	if err != nil {
		return err
	}
	_, err = s.Q.Exec(ctx,
		`INSERT INTO rollout_events (tenant_id, rollout_id, action, plan)
		 VALUES (current_setting('probectl.tenant_id')::uuid, $1, $2, $3::jsonb)`,
		id, action, raw)
	return err
}
