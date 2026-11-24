// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	gouuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/httpbody"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/internal/testsync"
)

type instantRunRequest struct {
	IdempotencyKey string                    `json:"idempotency_key"`
	Selection      testspec.InstantSelection `json:"selection"`
}

type instantRunView struct {
	store.InstantRunSummary
	Agents []store.InstantRunAgent `json:"agents"`
}

func (s *Server) handleCreateInstantTestRun(w http.ResponseWriter, r *http.Request) error {
	var request instantRunRequest
	if err := decodeJSONLimit(r, 1<<20, &request); err != nil {
		return err
	}
	testID := r.PathValue("id")
	if !canonicalInstantResource(testID) || !canonicalInstantResource(request.IdempotencyKey) {
		return apierror.Validation("a test ID and idempotency key are required")
	}
	selection, err := testspec.NormalizeInstantSelection(request.Selection)
	if err != nil {
		return apierror.Validation(err.Error())
	}
	request.Selection = selection
	if s.pool == nil || s.cfg == nil || !s.cfg.AgentTransportEnabled() || s.cfg.TestSyncSigningKeyFile == "" || s.fairnessGate == nil || s.cfg.FairnessInstantTestAgentsPerSec <= 0 {
		return apierror.Unavailable("instant test dispatch is not configured")
	}
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.UserID == "" || actor.TenantID == "" {
		return apierror.Forbidden("instant test dispatch requires a tenant operator")
	}
	release, err := s.fairnessGate.BeginQuery(r.Context(), actor.TenantID)
	if err != nil {
		return apierror.RateLimited("too many active instant test selections")
	}
	defer release()
	requestBytes, err := json.Marshal(request.Selection)
	if err != nil {
		return apierror.Validation("invalid agent selection")
	}
	id, err := crypto.UUIDv4()
	if err != nil {
		return err
	}
	ctx, flush := scopedABACDenial(r.Context())
	defer flush(s)
	ctx = tenancy.WithTenant(ctx, tenancy.ID(actor.TenantID))
	var run store.InstantRunSummary
	var created bool
	write := func() error {
		run, created = store.InstantRunSummary{}, false
		return tenancy.InTenantWriteSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
			authority, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
			if err != nil {
				return err
			}
			ctx, actor, err := authority.requestContext(ctx, actor)
			if err != nil {
				return err
			}
			test, err := (store.Tests{}).Get(ctx, sc, testID)
			if err != nil {
				return err
			}
			if err := s.authorizeInstantTest(ctx, actor, *test, true); err != nil {
				return err
			}
			if tag := selection.Tag; tag != nil {
				record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, tag.ContextID)
				if err != nil {
					return entityAPIError(err)
				}
				if err := s.authorize(ctx, actor, permTagsRead, auth.RBACGlobal, entityContextResource(record)); err != nil {
					return err
				}
			}
			input := store.InstantRunInput{
				ID: id, RequestedBy: actor.UserID, RequestedWithMFA: actor.MFASatisfied, IdempotencyKey: request.IdempotencyKey,
				RequestHash: crypto.Hash(requestBytes), Test: *test,
			}
			existing, found, err := (store.InstantTestRuns{}).LookupRetry(ctx, sc, input)
			if err != nil {
				return err
			}
			if found {
				run, created = existing, false
				return s.authorizeInstantRunAgents(ctx, sc, actor, existing.ID)
			}
			agents, err := (store.InstantTestRuns{}).Targets(ctx, sc, selection, test.Type, httpbody.MaxClientResponseBodyBytes)
			if err != nil {
				return err
			}
			registrations := make(map[string]time.Time, len(agents))
			for _, agent := range agents {
				if err := s.authorizeInstantAgent(ctx, actor, agent.ID); err != nil {
					return err
				}
				registrations[agent.ID] = agent.RegisteredAt
			}
			digest, err := testspec.DefinitionHash(testspec.ExecutableDefinition{
				ID: test.ID, Type: test.Type, Target: test.Target, Params: test.Params,
				IntervalSeconds: test.IntervalSeconds, TimeoutSeconds: test.TimeoutSeconds,
			})
			if err != nil {
				return err
			}
			input.DefinitionHash, input.AgentRegistrations = digest, registrations
			run, created, err = (store.InstantTestRuns{}).Create(ctx, sc, input, s.fairnessGate.AdmitInstantTestAgents)
			if err != nil {
				return err
			}
			if !created {
				return s.authorizeInstantRunAgents(ctx, sc, actor, run.ID)
			}
			return s.recordAudit(ctx, sc, r.WithContext(ctx), "test.instant.create", run.ID,
				map[string]any{"test_id": test.ID, "assigned_agents": len(agents)})
		})
	}
	err = write()
	var conflict *pgconn.PgError
	if errors.As(err, &conflict) && (conflict.Code == "40001" || conflict.Code == "40P01") {
		// A concurrent request with this key may have committed after the
		// first snapshot. Rebind all authority in a fresh transaction.
		err = write()
	}
	if err != nil {
		return instantRunAPIError(err)
	}
	w.Header().Set("Location", "/v1/test-runs/"+run.ID)
	if created {
		writeJSON(w, http.StatusAccepted, run)
	} else {
		writeJSON(w, http.StatusOK, run)
	}
	return nil
}

func (s *Server) authorizeInstantTest(ctx context.Context, actor *auth.Principal, test store.Test, launch bool) error {
	resource := map[string]string{auth.ResourceTenantKey: test.TenantID, "test_id": test.ID}
	if err := s.authorize(ctx, actor, permTestRead, auth.RBACGlobal, resource); err != nil {
		return err
	}
	if !launch {
		return s.authorize(ctx, actor, permMetricsRead, auth.RBACGlobal, resource)
	}
	if err := s.authorize(ctx, actor, permTestWrite, auth.RBACGlobal, resource); err != nil {
		return err
	}
	return s.guardAllowPrivate((&http.Request{}).WithContext(auth.WithPrincipal(ctx, actor)), test.Params)
}

func (s *Server) authorizeInstantAgent(ctx context.Context, actor *auth.Principal, agentID string) error {
	return s.authorize(ctx, actor, permAgentRead, auth.RBACGlobal,
		map[string]string{auth.ResourceTenantKey: actor.TenantID, "agent_id": agentID})
}

func (s *Server) authorizeInstantRunAgents(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, id string) error {
	_, agents, err := (store.InstantTestRuns{}).Get(ctx, sc, id)
	if err != nil {
		return err
	}
	for _, agent := range agents {
		if err := s.authorizeInstantAgent(ctx, actor, agent.AgentID); err != nil {
			return err
		}
	}
	return nil
}

// PullInstantTestForAgent flushes authorization audit records after the
// assignment transaction releases its tenant connection.
func (s *Server) PullInstantTestForAgent(ctx context.Context, source *testsync.Source, tenant, agent, serial string) ([]byte, error) {
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	return source.PullInstantAssignment(ctx, tenant, agent, serial, s.authorizeInstantTestLease)
}

// authorizeInstantTestLease rechecks the original operator's current grants at
// claim. The stored MFA fact applies only to this already authorized run.
func (s *Server) authorizeInstantTestLease(ctx context.Context, sc tenancy.Scope, lease store.InstantTestLease, agent string) error {
	authority, err := readCurrentUserAuthorityScope(ctx, sc, lease.RequestedBy)
	if err != nil {
		return err
	}
	initiator := auth.ClonePrincipal(authority.principal)
	initiator.MFASatisfied = lease.RequestedWithMFA
	ctx, initiator, err = authority.requestContext(ctx, initiator)
	if err != nil {
		return err
	}
	if err := s.authorizeInstantTest(ctx, initiator, lease.Test, true); err != nil {
		return err
	}
	return s.authorizeInstantAgent(ctx, initiator, agent)
}

func (s *Server) readInstantRun(ctx context.Context, actor *auth.Principal, id string) (instantRunView, error) {
	var view instantRunView
	if actor == nil || actor.UserID == "" || actor.TenantID == "" {
		return view, apierror.Forbidden("instant test results require a tenant operator")
	}
	if !canonicalInstantResource(id) {
		return view, apierror.Validation("an instant test run ID is required")
	}
	if s.pool == nil {
		return view, apierror.Unavailable("instant test storage is unavailable")
	}
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	ctx = tenancy.WithTenant(ctx, tenancy.ID(actor.TenantID))
	err := tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		authority, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, actor, err := authority.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		view.InstantRunSummary, view.Agents, err = (store.InstantTestRuns{}).Get(ctx, sc, id)
		if err != nil {
			return err
		}
		test, err := (store.Tests{}).Get(ctx, sc, view.TestID)
		if err != nil {
			return err
		}
		if err := s.authorizeInstantTest(ctx, actor, *test, false); err != nil {
			return err
		}
		for _, agent := range view.Agents {
			if err := s.authorizeInstantAgent(ctx, actor, agent.AgentID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return instantRunView{}, instantRunAPIError(err)
	}
	return view, nil
}

func canonicalInstantResource(value string) bool {
	id, err := gouuid.Parse(value)
	return err == nil && id != gouuid.Nil && id.String() == value
}

func instantRunAPIError(err error) error {
	switch {
	case tenancy.IsProspectCollectionEnded(err):
		return apierror.Conflict("prospect collection ended")
	case errors.Is(err, store.ErrInstantRunUnavailable), errors.Is(err, tags.ErrScopeMismatch):
		return apierror.NotFound("instant test run or complete agent selection is unavailable")
	case errors.Is(err, store.ErrInstantRunConflict):
		return apierror.Conflict("instant test idempotency key names another request")
	case errors.Is(err, store.ErrInstantRunBudget), errors.Is(err, store.ErrTagSnapshotBudget):
		return apierror.RateLimited("the tenant can retry when its instant test budget is available")
	default:
		return err
	}
}
