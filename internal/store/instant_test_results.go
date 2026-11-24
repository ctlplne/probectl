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
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const maxInstantResultProjectionBytes = 8 << 10

// InstantRunResult is the bounded public projection of one authenticated result.
// The transport checks the normal result limits before installing this view.
type InstantRunResult struct {
	RunID, LeaseID, TestID, ResultID string
	StartedAt                        time.Time
	DurationNanos                    int64
	Success                          bool
	Outcome, TestType                string
	Metrics                          map[string]float64
}

// Complete accepts one result for the exact lease and current agent registration.
// A byte-identical retry is acknowledged without rewriting the result.
func (InstantTestRuns) Complete(ctx context.Context, sc tenancy.Scope, agent, serial string, in InstantRunResult) (bool, error) {
	tenant, err := instantRunScope(ctx, sc)
	if err != nil {
		return false, err
	}
	if in.RunID == "" || in.LeaseID == "" || in.TestID == "" || in.TestType == "" || in.ResultID == "" || in.StartedAt.IsZero() || in.DurationNanos < 0 {
		return false, ErrInstantRunUnavailable
	}
	switch in.Outcome {
	case "measured", "policy_refused", "execution_failed", "timed_out":
	default:
		return false, ErrInstantRunUnavailable
	}
	if in.Outcome != "measured" && (in.Success || len(in.Metrics) != 0) {
		return false, ErrInstantRunUnavailable
	}
	if err := tenancy.RequireTenantCollection(ctx, sc); err != nil {
		return false, err
	}
	registeredAt, err := lockInstantAgent(ctx, sc, tenant, agent, serial)
	if err != nil {
		return false, err
	}
	view, err := json.Marshal(struct {
		StartedAt     time.Time          `json:"started_at"`
		DurationNanos int64              `json:"duration_nanos"`
		Success       bool               `json:"success"`
		Outcome       string             `json:"outcome"`
		Metrics       map[string]float64 `json:"metrics,omitempty"`
	}{in.StartedAt.UTC(), in.DurationNanos, in.Success, in.Outcome, in.Metrics})
	if err != nil || len(view) > maxInstantResultProjectionBytes {
		return false, ErrInstantRunUnavailable
	}
	hash := crypto.Hash(view)
	tag, err := sc.Q.Exec(ctx, `UPDATE instant_test_assignments a SET result_id=$6,result_hash=$7,result=$8::jsonb
 FROM instant_test_runs r JOIN tests t ON (t.tenant_id,t.id,t.updated_at)=(r.tenant_id,r.test_id,r.test_updated_at)
 WHERE (r.tenant_id,r.id)=(a.tenant_id,a.run_id) AND a.tenant_id=$1 AND a.run_id=$2 AND a.agent_id=$3
   AND a.agent_registered_at=$4 AND a.lease_id=$5 AND a.result_id IS NULL AND r.test_id=$9
   AND statement_timestamp()<a.lease_until
   AND $10::timestamptz>=a.leased_at-interval '30 seconds' AND $10<a.lease_until
   AND t.type=$11 AND $12::bigint<=(r.timeout_seconds+5)::bigint*1000000000`,
		tenant, in.RunID, agent, registeredAt, in.LeaseID, in.ResultID, hash, view, in.TestID, in.StartedAt, in.TestType, in.DurationNanos)
	if err != nil || tag.RowsAffected() == 1 {
		return err == nil, err
	}
	var existing []byte
	err = sc.Q.QueryRow(ctx, `SELECT a.result_hash FROM instant_test_assignments a
 JOIN instant_test_runs r ON (r.tenant_id,r.id)=(a.tenant_id,a.run_id)
 WHERE a.tenant_id=$1 AND a.run_id=$2 AND a.agent_id=$3 AND a.agent_registered_at=$4
   AND a.lease_id=$5 AND a.result_id=$6 AND r.test_id=$7`,
		tenant, in.RunID, agent, registeredAt, in.LeaseID, in.ResultID, in.TestID).Scan(&existing)
	if err != nil {
		return false, instantAuthorityError(err)
	}
	if !bytes.Equal(existing, hash) {
		return false, ErrInstantRunUnavailable
	}
	return false, nil
}

// Get returns one tenant-bound run. Callers must authorize the exact test and
// visible agent set before serializing the completed execution view.
func (InstantTestRuns) Get(ctx context.Context, sc tenancy.Scope, id string) (InstantRunSummary, []InstantRunAgent, error) {
	var run InstantRunSummary
	tenant, err := instantRunScope(ctx, sc)
	if err != nil {
		return run, nil, err
	}
	err = sc.Q.QueryRow(ctx, `SELECT id::text,test_id::text,created_at,dispatch_until
 FROM instant_test_runs WHERE tenant_id=$1 AND id=$2 AND statement_timestamp()<retain_until`, tenant, id).
		Scan(&run.ID, &run.TestID, &run.CreatedAt, &run.DispatchUntil)
	if err != nil {
		return InstantRunSummary{}, nil, instantAuthorityError(err)
	}
	rows, err := sc.Q.Query(ctx, `SELECT a.agent_id::text,
 CASE WHEN a.result_id IS NOT NULL THEN 'completed'
      WHEN a.lease_id IS NOT NULL AND statement_timestamp()<a.lease_until THEN 'leased'
      WHEN a.lease_id IS NULL AND statement_timestamp()<r.dispatch_until THEN 'queued'
      ELSE 'expired' END,
 a.result
 FROM instant_test_assignments a JOIN instant_test_runs r ON (r.tenant_id,r.id)=(a.tenant_id,a.run_id)
 WHERE a.tenant_id=$1 AND a.run_id=$2 ORDER BY a.agent_id`, tenant, id)
	if err != nil {
		return InstantRunSummary{}, nil, err
	}
	defer rows.Close()
	agents := make([]InstantRunAgent, 0)
	for rows.Next() {
		var agent InstantRunAgent
		if err := rows.Scan(&agent.AgentID, &agent.State, &agent.Result); err != nil {
			return InstantRunSummary{}, nil, err
		}
		agents = append(agents, agent)
	}
	if err := rows.Err(); err != nil {
		return InstantRunSummary{}, nil, err
	}
	if len(agents) == 0 {
		return InstantRunSummary{}, nil, ErrInstantRunUnavailable
	}
	return run, agents, nil
}

// DeleteExpired removes internally retained rows through the normal tenant
// lifecycle worker. The assignment foreign key removes its child rows.
func (InstantTestRuns) DeleteExpired(ctx context.Context, sc tenancy.Scope) error {
	tenant, err := instantRunScope(ctx, sc)
	if err != nil {
		return err
	}
	_, err = sc.Q.Exec(ctx, `DELETE FROM instant_test_runs WHERE tenant_id=$1 AND retain_until<=statement_timestamp()`, tenant)
	return err
}
