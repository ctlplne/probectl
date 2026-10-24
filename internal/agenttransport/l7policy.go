// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/l7redact"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// l7PolicyCapability is advertised in RegisterResponse.server_capabilities
// only when the L7 capture policy is wired.
const l7PolicyCapability = "agent.l7_policy.v1"

// L7PostureAuditAction is the tenant-chain audit action for an agent's first
// consented L7 capture report or any later change of its capture mode (D-43
// addendum (a), docs/guardrails.md G7-7).
const L7PostureAuditAction = "agent.l7_capture.posture"

// L7Policy is the control plane's L7 capture policy seam (D-43, refinement 3):
// the tenant's redaction floor, and the record of each agent's reported capture
// posture. Every method takes the tenant from the caller's verified client
// certificate — the transport never passes a tenant read from a request body.
type L7Policy interface {
	// Floor returns the tenant's effective L7 capture redaction floor.
	Floor(ctx context.Context, tenantID string) (string, error)
	// RecordPosture stores the agent's validated posture and reports whether
	// it changed; a material change is audited on the tenant's chain in the
	// same transaction.
	RecordPosture(ctx context.Context, tenantID, agentID string, p store.L7CapturePosture) (bool, error)
}

// WithL7Policy wires the L7 capture policy. nil (the default) leaves both RPCs
// answering FailedPrecondition, and an agent that receives no floor applies
// metadata.
func (s *Server) WithL7Policy(p L7Policy) *Server {
	s.svc.l7policy = p
	return s
}

// FetchL7Policy serves the calling agent's tenant's redaction floor. The tenant
// is the one in the verified client certificate (docs/guardrails.md G7-4).
func (svc *service) FetchL7Policy(ctx context.Context, _ *agentv1.FetchL7PolicyRequest) (*agentv1.FetchL7PolicyResponse, error) {
	id, err := svc.authenticateEBPFCollector(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if svc.l7policy == nil {
		return nil, status.Error(codes.FailedPrecondition, "L7 capture policy is not configured on this control plane")
	}
	floor, err := svc.l7policy.Floor(ctx, id.TenantID)
	if err != nil {
		// Fail closed without inventing a floor: the agent treats "no floor
		// received" as metadata (D-43 refinement 3).
		svc.log.Error("l7 redaction floor read failed", "tenant", id.TenantID, "agent", id.AgentID, "error", err.Error())
		return nil, status.Error(codes.Unavailable, "L7 capture policy unavailable")
	}
	return &agentv1.FetchL7PolicyResponse{RedactionFloor: floor}, nil
}

// ReportL7Posture validates and records the calling agent's capture posture.
func (svc *service) ReportL7Posture(ctx context.Context, req *agentv1.ReportL7PostureRequest) (*agentv1.ReportL7PostureResponse, error) {
	id, err := svc.authenticateEBPFCollector(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if svc.l7policy == nil {
		return nil, status.Error(codes.FailedPrecondition, "L7 capture policy is not configured on this control plane")
	}
	p, err := validateL7Posture(id.TenantID, req.GetPosture(), time.Now().UTC())
	if err != nil {
		svc.log.Warn("rejecting malformed l7 capture posture", "tenant", id.TenantID, "agent", id.AgentID, "reason", err.Error())
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	changed, err := svc.l7policy.RecordPosture(ctx, id.TenantID, id.AgentID, p)
	if err != nil {
		if de, ok := apierror.As(err); ok && de.Kind == apierror.KindNotFound {
			return nil, status.Error(codes.NotFound, "agent is not registered in its tenant (register the collector first)")
		}
		svc.log.Error("l7 capture posture record failed", "tenant", id.TenantID, "agent", id.AgentID, "error", err.Error())
		return nil, status.Error(codes.Internal, "posture record failed")
	}
	if changed {
		svc.log.Info("agent l7 capture posture recorded",
			"tenant", id.TenantID, "agent", id.AgentID, "state", p.State,
			"redaction_mode", p.RedactionMode, "effective_mode", p.EffectiveMode, "floor", p.RedactionFloor)
	}
	return &agentv1.ReportL7PostureResponse{Changed: changed}, nil
}

// Posture bounds: the scope is an allowlist of workloads, not a transcript.
const (
	maxPostureScope      = 64
	maxPostureScopeBytes = 512
	maxPostureTenant     = 128
)

// postureStates is the closed vocabulary an agent's state must come from.
var postureStates = map[string]bool{
	"off": true, "refused_consent": true, "refused_floor": true,
	"attach_failed": true, "capturing": true, "replaying": true,
}

// validateL7Posture bounds and validates an agent-reported posture. Every field
// is untrusted input (docs/guardrails.md G7-12): modes and the state must come
// from their closed vocabularies, scope entries must have the pid:/exe:/cgroup:
// shape and carry no control characters, and the consent tenant is kept only
// when it equals the certificate's tenant — a foreign tenant id is never stored
// in this tenant's row, only the fact that it did not match.
func validateL7Posture(tenantID string, in *agentv1.L7CapturePosture, now time.Time) (store.L7CapturePosture, error) {
	if in == nil {
		return store.L7CapturePosture{}, fmt.Errorf("posture is required")
	}
	out := store.L7CapturePosture{Enabled: in.GetEnabled(), Active: in.GetActive(), ReportedAt: now, Scope: []string{}}
	if ct := in.GetConsentTenant(); ct != "" {
		if len(ct) > maxPostureTenant || strings.ContainsFunc(ct, unicode.IsControl) {
			return out, fmt.Errorf("consent_tenant is malformed")
		}
		if ct == tenantID {
			out.ConsentTenant = ct
		} else {
			out.ConsentMismatch = true
		}
	}
	if len(in.GetScope()) > maxPostureScope {
		return out, fmt.Errorf("scope exceeds %d entries", maxPostureScope)
	}
	for _, e := range in.GetScope() {
		if len(e) > maxPostureScopeBytes || strings.ContainsFunc(e, unicode.IsControl) || !scopeShaped(e) {
			return out, fmt.Errorf("scope entry is not pid:<n>, exe:/path or cgroup:/path")
		}
		out.Scope = append(out.Scope, e)
	}
	var err error
	if out.RedactionMode, err = postureMode("redaction_mode", in.GetRedactionMode(), false); err != nil {
		return out, err
	}
	if out.EffectiveMode, err = postureMode("effective_mode", in.GetEffectiveMode(), true); err != nil {
		return out, err
	}
	if out.RedactionFloor, err = postureMode("redaction_floor", in.GetRedactionFloor(), true); err != nil {
		return out, err
	}
	if !postureStates[in.GetState()] {
		return out, fmt.Errorf("state %q is not a known capture state", in.GetState())
	}
	out.State = in.GetState()
	return out, nil
}

// scopeShaped reports whether e has one of the three scope-entry forms.
func scopeShaped(e string) bool {
	return strings.HasPrefix(e, "pid:") || strings.HasPrefix(e, "exe:/") || strings.HasPrefix(e, "cgroup:/")
}

func postureMode(field, mode string, allowEmpty bool) (string, error) {
	if mode == "" && allowEmpty {
		return "", nil
	}
	if !l7redact.ValidMode(mode) {
		return "", fmt.Errorf("%s must be one of %s", field, strings.Join(l7redact.Modes(), ", "))
	}
	return mode, nil
}

// l7PostureMaterial reports whether recording next over prior is a change the
// tenant's audit chain must carry: the agent's first consented report, or any
// later change of consent, scope, mode, floor or state while either side is
// consented. A never-consented agent reporting "off" again is not audit noise.
func l7PostureMaterial(prior *store.L7CapturePosture, next store.L7CapturePosture) bool {
	if prior == nil {
		return next.Consented()
	}
	if prior.SameMaterial(next) {
		return false
	}
	return prior.Consented() || next.Consented()
}

// pgL7Policy is the shipping L7Policy over the control-plane database: the
// floor from the tenant's governance row (govern.PolicyStore), the posture on
// the agent's registry row, the audit receipt on the tenant's chain.
type pgL7Policy struct {
	pool      *pgxpool.Pool
	floors    *govern.PolicyStore
	regulated bool
}

// NewL7Policy builds the database-backed L7 capture policy. regulated is the
// deployment profile: under it the floor is never looser than metadata.
func NewL7Policy(pool *pgxpool.Pool, regulated bool) L7Policy {
	return &pgL7Policy{pool: pool, floors: govern.NewPolicyStore(pool), regulated: regulated}
}

func (p *pgL7Policy) Floor(ctx context.Context, tenantID string) (string, error) {
	return p.floors.L7CaptureFloor(ctx, tenantID, p.regulated)
}

func (p *pgL7Policy) RecordPosture(ctx context.Context, tenantID, agentID string, next store.L7CapturePosture) (bool, error) {
	changed := false
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), p.pool, func(ctx context.Context, sc tenancy.Scope) error {
		prior, err := (store.Agents{}).RecordL7CapturePosture(ctx, sc, agentID, next)
		if err != nil {
			return err
		}
		changed = prior == nil || !prior.SameMaterial(next)
		if !l7PostureMaterial(prior, next) {
			return nil
		}
		// G7-7: the receipt is appended in the SAME transaction as the
		// posture write; a failing append rolls the record back.
		_, err = audit.TenantAppend(ctx, sc, "agent:"+agentID, L7PostureAuditAction, agentID, l7PostureAuditData(prior, next))
		return err
	})
	return changed, err
}

// l7PostureAuditData is the receipt body: the new posture, and the prior mode
// and state it replaced. It never carries anything the agent captured.
func l7PostureAuditData(prior *store.L7CapturePosture, next store.L7CapturePosture) map[string]any {
	data := map[string]any{
		"enabled":          next.Enabled,
		"consented":        next.Consented(),
		"consent_tenant":   next.ConsentTenant,
		"consent_mismatch": next.ConsentMismatch,
		"scope":            next.Scope,
		"redaction_mode":   next.RedactionMode,
		"effective_mode":   next.EffectiveMode,
		"redaction_floor":  next.RedactionFloor,
		"active":           next.Active,
		"state":            next.State,
		"first_report":     prior == nil,
	}
	if prior != nil {
		data["prior_redaction_mode"] = prior.RedactionMode
		data["prior_effective_mode"] = prior.EffectiveMode
		data["prior_state"] = prior.State
		data["prior_consented"] = prior.Consented()
	}
	return data
}
