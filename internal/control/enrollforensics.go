// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/enroll"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	enrollmentRejectedAuditAction = "security.enrollment_rejected"
	enrollmentFailureAuditTimeout = 5 * time.Second
)

type enrollmentFailureClass string

const (
	enrollmentFailureInvalidToken            enrollmentFailureClass = "invalid_token"
	enrollmentFailureInvalidCSR              enrollmentFailureClass = "invalid_csr"
	enrollmentFailureInvalidCollectorPlane   enrollmentFailureClass = "invalid_collector_plane"
	enrollmentFailureInvalidRotationIdentity enrollmentFailureClass = "invalid_rotation_identity"
	enrollmentFailureInvalidRotationProof    enrollmentFailureClass = "invalid_rotation_proof"
	enrollmentFailureRevokedIdentity         enrollmentFailureClass = "revoked_identity"
	enrollmentFailureUnknown                 enrollmentFailureClass = "unknown"
)

type enrollmentSurface string

const (
	enrollmentSurfaceAgent     enrollmentSurface = "agent_enroll"
	enrollmentSurfaceCollector enrollmentSurface = "collector_register"
	enrollmentSurfaceRotation  enrollmentSurface = "agent_rotate"
	enrollmentSurfaceUnknown   enrollmentSurface = "unknown"
)

var enrollmentFailureClasses = [...]enrollmentFailureClass{
	enrollmentFailureInvalidToken,
	enrollmentFailureInvalidCSR,
	enrollmentFailureInvalidCollectorPlane,
	enrollmentFailureInvalidRotationIdentity,
	enrollmentFailureInvalidRotationProof,
	enrollmentFailureRevokedIdentity,
	enrollmentFailureUnknown,
}

type enrollmentFailureEvent struct {
	Class    enrollmentFailureClass
	Surface  enrollmentSurface
	TenantID string
	Actor    string
}

func normalizeEnrollmentFailureClass(class enrollmentFailureClass) enrollmentFailureClass {
	switch class {
	case enrollmentFailureInvalidToken,
		enrollmentFailureInvalidCSR,
		enrollmentFailureInvalidCollectorPlane,
		enrollmentFailureInvalidRotationIdentity,
		enrollmentFailureInvalidRotationProof,
		enrollmentFailureRevokedIdentity:
		return class
	default:
		return enrollmentFailureUnknown
	}
}

func normalizeEnrollmentSurface(surface enrollmentSurface) enrollmentSurface {
	switch surface {
	case enrollmentSurfaceAgent, enrollmentSurfaceCollector, enrollmentSurfaceRotation:
		return surface
	default:
		return enrollmentSurfaceUnknown
	}
}

func enrollmentFailureMetricName(class enrollmentFailureClass) string {
	return "probectl_enrollment_failures_" + string(normalizeEnrollmentFailureClass(class)) + "_total"
}

func (s *Server) registerEnrollmentFailureMetrics() {
	const help = "Rejected enrollment attempts by bounded failure class; contains no tenant or credential labels."
	for _, class := range enrollmentFailureClasses {
		s.metrics.Counter(enrollmentFailureMetricName(class), help)
	}
}

// recordEnrollmentFailure emits one aggregate counter, one redacted structured
// warning, and one best-effort tamper-evident audit event. tenantID is accepted
// only from an authenticated principal or enroll.RefusalTenant; request fields
// (tokens, CSRs, certificates, and proofs) cannot enter the event structure.
func (s *Server) recordEnrollmentFailure(r *http.Request, class enrollmentFailureClass, surface enrollmentSurface, tenantID string) {
	class = normalizeEnrollmentFailureClass(class)
	surface = normalizeEnrollmentSurface(surface)
	if tenantID != "" && !uuidRe.MatchString(tenantID) {
		tenantID = ""
	}

	event := enrollmentFailureEvent{
		Class:    class,
		Surface:  surface,
		TenantID: tenantID,
		Actor:    "anonymous",
	}
	// Public enrollment routes may carry an unrelated ambient browser/API
	// session. Never write that principal into another tenant's audit chain.
	if p := auth.PrincipalFrom(r.Context()); tenantID != "" && p != nil && p.TenantID == tenantID {
		event.Actor = auditActor(r)
	}

	s.metrics.Counter(enrollmentFailureMetricName(class), "").Inc()
	if s.enrollmentFailureAudit != nil {
		// The security event happened even if the caller disconnected. Preserve
		// request values but replace client cancellation with a strict deadline
		// so the durable append gets a bounded opportunity to finish.
		auditCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), enrollmentFailureAuditTimeout)
		defer cancel()
		if err := s.enrollmentFailureAudit(auditCtx, event); err != nil {
			s.log.Warn("failed to persist enrollment rejection audit",
				"failure_class", string(class),
				"surface", string(surface),
				"tenant_resolved", tenantID != "",
				"error", err.Error())
		}
	}

	attrs := []any{
		"failure_class", string(class),
		"surface", string(surface),
		"tenant_resolved", tenantID != "",
	}
	if tenantID != "" {
		attrs = append(attrs, "tenant_id", tenantID)
	}
	s.log.Warn("enrollment rejected", attrs...)
}

// Identity lifecycle audit actions (DPR-098): a first SVID and every rotation
// land in the agent's tenant stream, attributed to the agent itself.
const (
	agentEnrolledAuditAction        = "agent.enrolled"
	agentIdentityRotatedAuditAction = "agent.identity.rotated"
)

// recordIdentityAudit appends a successful issuance/rotation to the tenant's
// audit stream. Best effort with a bounded deadline: the SVID has already been
// issued, so a failed append is logged, never surfaced as a rotation failure.
func (s *Server) recordIdentityAudit(r *http.Request, action string, id *enroll.Identity, extra map[string]any) {
	if s.identityAudit == nil || id == nil || id.TenantID == "" || id.AgentID == "" {
		return
	}
	data := map[string]any{
		"spiffe_id": id.SPIFFEID,
		"serial":    id.Serial,
		"not_after": id.NotAfter.UTC().Format(time.RFC3339),
		"plane":     id.Plane,
	}
	for k, v := range extra {
		data[k] = v
	}
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), enrollmentFailureAuditTimeout)
	defer cancel()
	if err := s.identityAudit(auditCtx, id.TenantID, id.AgentID, action, data); err != nil {
		s.log.Warn("failed to persist agent identity audit", "action", action, "agent_id", id.AgentID, "error", err.Error())
	}
}

// persistIdentityAudit is the shipping identityAudit: the agent is the actor.
func (s *Server) persistIdentityAudit(ctx context.Context, tenantID, agentID, action string, data map[string]any) error {
	if s.pool == nil {
		return nil
	}
	return s.inTenantID(ctx, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := audit.TenantAppend(ctx, sc, "agent:"+agentID, action, agentID, data)
		return err
	})
}

func (s *Server) persistEnrollmentFailure(ctx context.Context, event enrollmentFailureEvent) error {
	data := map[string]any{
		"failure_class": string(event.Class),
		"outcome":       "denied",
		"surface":       string(event.Surface),
	}
	if event.TenantID != "" {
		return s.inTenantID(ctx, event.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := audit.TenantAppend(ctx, sc, event.Actor, enrollmentRejectedAuditAction, string(event.Surface), data)
			return err
		})
	}
	if s.pool == nil {
		return nil
	}
	_, err := audit.ProviderAppend(ctx, s.pool, event.Actor, enrollmentRejectedAuditAction, string(event.Surface), data)
	return err
}
