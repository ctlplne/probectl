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

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var (
	ErrInstantRunUnavailable = errors.New("store: instant test run or current authority is unavailable")
	ErrInstantRunConflict    = errors.New("store: instant test idempotency key names another request")
	ErrInstantRunBudget      = errors.New("store: tenant instant test budget exhausted")
)

type InstantTestRuns struct{}

// InstantRunInput is prepared from a saved test and fully authorized current
// agent registrations. The caller commits the audit in the same transaction.
type InstantRunInput struct {
	ID, RequestedBy, IdempotencyKey string
	RequestHash                     []byte
	RequestedWithMFA                bool
	DefinitionHash                  string
	Test                            Test
	AgentRegistrations              map[string]time.Time
}

type InstantRunSummary struct {
	ID            string    `json:"id"`
	TestID        string    `json:"test_id"`
	CreatedAt     time.Time `json:"created_at"`
	DispatchUntil time.Time `json:"dispatch_until"`
}

type InstantRunAgent struct {
	AgentID string          `json:"agent_id"`
	State   string          `json:"state"`
	Result  json.RawMessage `json:"result,omitempty"`
}

type InstantTestLease struct {
	RunID, LeaseID   string
	RequestedBy      string
	RequestedWithMFA bool
	DefinitionHash   string
	Test             Test
	IssuedAt         time.Time
	ExpiresAt        time.Time
}

func instantRunScope(ctx context.Context, sc tenancy.Scope) (string, error) {
	id, present := tenancy.FromContext(ctx)
	if !present || id != sc.Tenant || sc.Q == nil {
		return "", tenancy.ErrNoTenant
	}
	return id.String(), nil
}

// Create atomically records the whole authorized selection. An identical retry
// returns the existing run before charging the tenant or inserting assignments.
// The caller must roll back the enclosing transaction on every error.
func (InstantTestRuns) Create(ctx context.Context, sc tenancy.Scope, in InstantRunInput, admit func(context.Context, string, int64) bool) (InstantRunSummary, bool, error) {
	var out InstantRunSummary
	tenant, err := instantRunScope(ctx, sc)
	if err != nil {
		return out, false, err
	}
	if tenant != in.Test.TenantID || len(in.RequestHash) != 32 || len(in.AgentRegistrations) == 0 || admit == nil {
		return out, false, ErrInstantRunUnavailable
	}
	if err := tenancy.RequireTenantCollection(ctx, sc); err != nil {
		return out, false, err
	}
	err = sc.Q.QueryRow(ctx, `INSERT INTO instant_test_runs (
 tenant_id,id,requested_by,idempotency_key,request_hash,requested_with_mfa,test_id,test_updated_at,
 definition_hash,timeout_seconds,created_at,dispatch_until,retain_until)
 SELECT t.tenant_id,$2,$3,$4,$5,$9,t.id,t.updated_at,$6,t.timeout_seconds,
        statement_timestamp(),statement_timestamp()+interval '20 seconds',statement_timestamp()+interval '1 day'
 FROM tests t WHERE t.tenant_id=$1 AND t.id=$7 AND t.updated_at=$8
 ON CONFLICT (tenant_id,requested_by,idempotency_key) DO NOTHING
 RETURNING id::text,test_id::text,created_at,dispatch_until`, tenant, in.ID, in.RequestedBy,
		in.IdempotencyKey, in.RequestHash, in.DefinitionHash, in.Test.ID, in.Test.UpdatedAt, in.RequestedWithMFA).
		Scan(&out.ID, &out.TestID, &out.CreatedAt, &out.DispatchUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		retry, found, lookupErr := lookupInstantRunRetry(ctx, sc, tenant, in)
		if lookupErr != nil {
			return InstantRunSummary{}, false, lookupErr
		}
		if !found {
			return InstantRunSummary{}, false, ErrInstantRunUnavailable
		}
		return retry, false, nil
	}
	if err != nil {
		return InstantRunSummary{}, false, err
	}
	if !admit(ctx, tenant, int64(len(in.AgentRegistrations))) {
		return InstantRunSummary{}, false, ErrInstantRunBudget
	}
	ids := make([]string, 0, len(in.AgentRegistrations))
	registrations := make([]time.Time, 0, len(in.AgentRegistrations))
	for agent, registeredAt := range in.AgentRegistrations {
		ids = append(ids, agent)
		registrations = append(registrations, registeredAt)
	}
	tag, err := sc.Q.Exec(ctx, `INSERT INTO instant_test_assignments (tenant_id,run_id,agent_id,agent_registered_at)
 SELECT a.tenant_id,$2,a.id,a.registered_at
 FROM unnest($3::uuid[],$4::timestamptz[]) AS requested(id,registered_at)
 JOIN agents a ON a.tenant_id=$1 AND a.id=requested.id AND a.registered_at=requested.registered_at
 WHERE EXISTS (SELECT 1 FROM agent_identities AS i WHERE i.tenant_id=a.tenant_id
   AND i.agent_id=a.id::text AND i.spiffe_id=a.spiffe_id AND i.revoked_at IS NULL
   AND i.not_after > statement_timestamp())`, tenant, out.ID, ids, registrations)
	if err != nil {
		return InstantRunSummary{}, false, err
	}
	if tag.RowsAffected() != int64(len(ids)) {
		return InstantRunSummary{}, false, ErrInstantRunUnavailable
	}
	return out, true, nil
}

// LookupRetry finds an existing request before reading a possibly changed
// site, tag or agent selector. Both the original test and request must match.
func (InstantTestRuns) LookupRetry(ctx context.Context, sc tenancy.Scope, in InstantRunInput) (InstantRunSummary, bool, error) {
	tenant, err := instantRunScope(ctx, sc)
	if err != nil {
		return InstantRunSummary{}, false, err
	}
	return lookupInstantRunRetry(ctx, sc, tenant, in)
}

func lookupInstantRunRetry(ctx context.Context, sc tenancy.Scope, tenant string, in InstantRunInput) (InstantRunSummary, bool, error) {
	var out InstantRunSummary
	var hash []byte
	err := sc.Q.QueryRow(ctx, `SELECT id::text,test_id::text,created_at,dispatch_until,request_hash
 FROM instant_test_runs WHERE tenant_id=$1 AND requested_by=$2 AND idempotency_key=$3`,
		tenant, in.RequestedBy, in.IdempotencyKey).Scan(&out.ID, &out.TestID, &out.CreatedAt, &out.DispatchUntil, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return InstantRunSummary{}, false, nil
	}
	if err != nil {
		return InstantRunSummary{}, false, err
	}
	if out.TestID != in.Test.ID || !bytes.Equal(hash, in.RequestHash) {
		return InstantRunSummary{}, false, ErrInstantRunConflict
	}
	return out, true, nil
}

// LeaseNext returns at most one assignment for the currently authenticated
// agent. During the dispatch window, a lost reply can recover the same lease
// with its original deadline. The agent consumes every lease at most once.
// Prefer fresh assignments so an already-consumed lease cannot block new runs.
// The exact test revision stays locked through authorization and signing.
func (InstantTestRuns) LeaseNext(ctx context.Context, sc tenancy.Scope, agent, serial, leaseID string) (*InstantTestLease, error) {
	tenant, err := instantRunScope(ctx, sc)
	if err != nil {
		return nil, err
	}
	// Most polls are idle. Check the pending index before taking row locks
	// on the enrollment, which would otherwise contend with heartbeats.
	var waiting bool
	err = sc.Q.QueryRow(ctx, `SELECT EXISTS (
 SELECT 1 FROM instant_test_assignments a
 JOIN instant_test_runs r ON (r.tenant_id,r.id)=(a.tenant_id,a.run_id)
 WHERE a.tenant_id=$1 AND a.agent_id=$2 AND a.result_id IS NULL
   AND statement_timestamp()<r.dispatch_until
   AND (a.lease_id IS NULL OR statement_timestamp()<a.lease_until))`, tenant, agent).Scan(&waiting)
	if err != nil || !waiting {
		return nil, err
	}
	if err := tenancy.RequireTenantCollection(ctx, sc); err != nil {
		return nil, err
	}
	registeredAt, err := lockInstantAgent(ctx, sc, tenant, agent, serial)
	if err != nil {
		return nil, err
	}
	var lease InstantTestLease
	var testID string
	var testUpdatedAt time.Time
	err = sc.Q.QueryRow(ctx, `WITH candidate AS (
 SELECT a.run_id,r.test_id,r.test_updated_at,r.definition_hash,r.timeout_seconds,r.requested_by,r.requested_with_mfa
 FROM instant_test_assignments a JOIN instant_test_runs r ON (r.tenant_id,r.id)=(a.tenant_id,a.run_id)
 JOIN tests t ON (t.tenant_id,t.id,t.updated_at)=(r.tenant_id,r.test_id,r.test_updated_at)
 WHERE a.tenant_id=$1 AND a.agent_id=$2 AND a.agent_registered_at=$3 AND a.result_id IS NULL
   AND statement_timestamp()<r.dispatch_until
   AND (a.lease_id IS NULL OR statement_timestamp()<a.lease_until)
 ORDER BY (a.lease_id IS NOT NULL),r.created_at,r.id LIMIT 1 FOR SHARE OF t SKIP LOCKED FOR UPDATE OF a SKIP LOCKED
 ) UPDATE instant_test_assignments a
 SET lease_id=COALESCE(a.lease_id,$4),leased_at=COALESCE(a.leased_at,statement_timestamp()),
     lease_until=COALESCE(a.lease_until,statement_timestamp()+make_interval(secs=>candidate.timeout_seconds+30))
 FROM candidate WHERE a.tenant_id=$1 AND a.agent_id=$2 AND a.run_id=candidate.run_id
 RETURNING a.run_id::text,a.lease_id::text,candidate.test_id::text,candidate.test_updated_at,
           candidate.definition_hash,candidate.requested_by::text,candidate.requested_with_mfa,a.leased_at,a.lease_until`, tenant, agent, registeredAt, leaseID).
		Scan(&lease.RunID, &lease.LeaseID, &testID, &testUpdatedAt, &lease.DefinitionHash, &lease.RequestedBy, &lease.RequestedWithMFA, &lease.IssuedAt, &lease.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	err = scanTest(sc.Q.QueryRow(ctx, `SELECT `+testCols+` FROM tests
 WHERE tenant_id=$1 AND id=$2 AND updated_at=$3`, tenant, testID, testUpdatedAt), &lease.Test)
	if err != nil {
		return nil, instantAuthorityError(err)
	}
	return &lease, nil
}

func lockInstantAgent(ctx context.Context, sc tenancy.Scope, tenant, agent, serial string) (time.Time, error) {
	var registeredAt time.Time
	if serial == "" || agent == "" {
		return registeredAt, ErrInstantRunUnavailable
	}
	spiffe := crypto.AgentSPIFFEID(tenant, agent)
	err := sc.Q.QueryRow(ctx, `SELECT registered_at FROM agents WHERE tenant_id=$1 AND id=$2 AND spiffe_id=$3
 FOR SHARE`, tenant, agent, spiffe).Scan(&registeredAt)
	if err != nil {
		return time.Time{}, instantAuthorityError(err)
	}
	var present int
	err = sc.Q.QueryRow(ctx, `SELECT 1 FROM agent_identities WHERE tenant_id=$1 AND agent_id=$2
 AND spiffe_id=$3 AND serial=$4 AND revoked_at IS NULL AND not_after>statement_timestamp() FOR SHARE`,
		tenant, agent, spiffe, serial).Scan(&present)
	if err != nil {
		return time.Time{}, instantAuthorityError(err)
	}
	return registeredAt, nil
}

func instantAuthorityError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInstantRunUnavailable
	}
	return err
}
