// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// Active-alert surface (S-FE1): the read/act side of S16 alerting. The
// evaluator's engine is the single source of truth — these handlers only
// expose its state and forward operator actions; nothing is derived or stored
// client-side. The engine is per tenant (one evaluator per tenant; the default
// deployment runs the default tenant's), so the caller's tenant selects the
// engine FIRST and an unknown tenant fails closed (CLAUDE.md §7 guardrail 1).

// AlertStateSource is the engine-truth contract (implemented by *alert.Engine).
type AlertStateSource interface {
	Active() []alert.ActiveAlert
	Silence(fingerprint string, d time.Duration) (alert.ActiveAlert, error)
	Acknowledge(fingerprint, by string) (alert.ActiveAlert, error)
}

// WithAlertState attaches a tenant's alert-state source (its evaluator engine).
// Returns the server for chaining.
func (s *Server) WithAlertState(tenant string, src AlertStateSource) *Server {
	s.alertStateMu.Lock()
	defer s.alertStateMu.Unlock()
	if src != nil {
		if s.alertState == nil {
			s.alertState = map[string]AlertStateSource{}
		}
		s.alertState[tenant] = src
	}
	return s
}

// WithoutAlertState detaches a tenant's evaluator engine when lifecycle fan-out
// observes that the tenant is no longer active.
func (s *Server) WithoutAlertState(tenant string) *Server {
	s.alertStateMu.Lock()
	defer s.alertStateMu.Unlock()
	delete(s.alertState, tenant)
	return s
}

// alertStateFor resolves the CALLER's engine (tenant boundary first).
func (s *Server) alertStateFor(r *http.Request) (AlertStateSource, string, error) {
	tid, err := s.principalTenant(r)
	if err != nil {
		return nil, "", err
	}
	s.alertStateMu.RLock()
	defer s.alertStateMu.RUnlock()
	return s.alertState[tid], tid, nil
}

// handleListActiveAlerts serves GET /v1/alerts/active — every firing series in
// the caller's tenant, engine truth. evaluator_running distinguishes "quiet"
// from "not evaluating" so the UI never has to guess.
func (s *Server) handleListActiveAlerts(w http.ResponseWriter, r *http.Request) error {
	src, _, err := s.alertStateFor(r)
	if err != nil {
		return err
	}
	if src == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []alert.ActiveAlert{}, "evaluator_running": false})
		return nil
	}
	items := src.Active()
	if items == nil {
		items = []alert.ActiveAlert{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "evaluator_running": true})
	return nil
}

// silenceRequest is the silence action body. DurationMinutes 0 clears an
// existing silence.
type silenceRequest struct {
	Fingerprint     string `json:"fingerprint"`
	DurationMinutes int    `json:"duration_minutes"`
	Reason          string `json:"reason,omitempty"`
}

type alertActionResponse struct {
	alert.ActiveAlert
	PersistenceRunning bool      `json:"persistence_running"`
	OperationActor     string    `json:"operation_actor"`
	OperationReason    string    `json:"operation_reason"`
	OperationStartedAt time.Time `json:"operation_started_at"`
	AuditRef           string    `json:"audit_ref,omitempty"`
}

// handleSilenceAlert serves POST /v1/alerts/active/silence.
func (s *Server) handleSilenceAlert(w http.ResponseWriter, r *http.Request) error {
	src, _, err := s.alertStateFor(r)
	if err != nil {
		return err
	}
	if src == nil {
		return apierror.Unavailable("the alert evaluator is not running for this tenant")
	}
	var req silenceRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if req.Fingerprint == "" {
		return apierror.Validation("fingerprint is required")
	}
	a, serr := src.Silence(req.Fingerprint, time.Duration(req.DurationMinutes)*time.Minute)
	if serr != nil {
		if errors.Is(serr, alert.ErrNotActive) {
			return apierror.NotFound("no firing alert with that fingerprint")
		}
		return apierror.Validation(serr.Error())
	}
	startedAt := time.Now().UTC()
	reason := boundedAlertReason(req.Reason, "Operator silence")
	auditRef := ""
	if s.pool != nil {
		if aerr := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			// ARCH-005: persist the operator action so it survives a restart.
			if req.DurationMinutes <= 0 && a.AckedBy == "" {
				if derr := (store.AlertOps{}).Delete(ctx, sc, a.Fingerprint); derr != nil {
					return derr
				}
			} else if perr := (store.AlertOps{}).Upsert(ctx, sc, store.AlertOp{
				Fingerprint: a.Fingerprint, RuleID: a.RuleID,
				SilencedUntil: a.SilencedUntil, AckedBy: a.AckedBy, AckedAt: a.AckedAt,
			}); perr != nil {
				return perr
			}
			data := map[string]any{
				"fingerprint": a.Fingerprint, "duration_minutes": req.DurationMinutes,
				"reason": reason, "starts_at": startedAt,
			}
			if a.SilencedUntil != nil {
				data["expires_at"] = a.SilencedUntil
			}
			ev, err := audit.TenantAppend(ctx, sc, auditActor(r), "alert.silence", a.RuleID, data)
			if err == nil {
				auditRef = alertAuditReference(ev)
			}
			return err
		}); aerr != nil {
			s.log.Warn("alert.silence persist/audit failed", "error", aerr)
			return aerr
		}
	}
	writeJSON(w, http.StatusOK, alertActionResponse{
		ActiveAlert: a, PersistenceRunning: s.pool != nil, OperationActor: auditActor(r),
		OperationReason: reason, OperationStartedAt: startedAt, AuditRef: auditRef,
	})
	return nil
}

// ackRequest is the acknowledge action body.
type ackRequest struct {
	Fingerprint string `json:"fingerprint"`
	Reason      string `json:"reason,omitempty"`
}

// handleAckAlert serves POST /v1/alerts/active/ack.
func (s *Server) handleAckAlert(w http.ResponseWriter, r *http.Request) error {
	src, _, err := s.alertStateFor(r)
	if err != nil {
		return err
	}
	if src == nil {
		return apierror.Unavailable("the alert evaluator is not running for this tenant")
	}
	var req ackRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if req.Fingerprint == "" {
		return apierror.Validation("fingerprint is required")
	}
	by := "unknown"
	if p := auth.PrincipalFrom(r.Context()); p != nil {
		if p.Email != "" {
			by = p.Email
		} else if p.UserID != "" {
			by = p.UserID
		}
	}
	a, aerr := src.Acknowledge(req.Fingerprint, by)
	if aerr != nil {
		if errors.Is(aerr, alert.ErrNotActive) {
			return apierror.NotFound("no firing alert with that fingerprint")
		}
		return apierror.Validation(aerr.Error())
	}
	startedAt := time.Now().UTC()
	reason := boundedAlertReason(req.Reason, "Investigation accepted")
	auditRef := ""
	if s.pool != nil {
		if auErr := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			// ARCH-005: persist the ack so it survives a restart.
			if perr := (store.AlertOps{}).Upsert(ctx, sc, store.AlertOp{
				Fingerprint: a.Fingerprint, RuleID: a.RuleID,
				SilencedUntil: a.SilencedUntil, AckedBy: a.AckedBy, AckedAt: a.AckedAt,
			}); perr != nil {
				return perr
			}
			ev, err := audit.TenantAppend(ctx, sc, auditActor(r), "alert.acknowledge", a.RuleID,
				map[string]any{
					"fingerprint": a.Fingerprint, "by": by, "reason": reason,
					"starts_at": startedAt,
				})
			if err == nil {
				auditRef = alertAuditReference(ev)
			}
			return err
		}); auErr != nil {
			s.log.Warn("alert.acknowledge audit failed", "error", auErr)
			return auErr
		}
	}
	writeJSON(w, http.StatusOK, alertActionResponse{
		ActiveAlert: a, PersistenceRunning: s.pool != nil, OperationActor: by,
		OperationReason: reason, OperationStartedAt: startedAt, AuditRef: auditRef,
	})
	return nil
}

type alertWorkflowOperation struct {
	Action         string     `json:"action"`
	Actor          string     `json:"actor"`
	Reason         string     `json:"reason"`
	StartedAt      time.Time  `json:"started_at"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	DeliveryStatus string     `json:"delivery_status"`
	AuditRef       string     `json:"audit_ref"`
}

type alertWorkflowDelivery struct {
	Connector   string    `json:"connector"`
	ExternalRef string    `json:"external_ref"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	ReceiptRef  string    `json:"receipt_ref"`
}

type alertWorkflowResponse struct {
	Alert              *alert.ActiveAlert       `json:"alert,omitempty"`
	Operations         []alertWorkflowOperation `json:"operations"`
	Incident           *incident.Incident       `json:"incident,omitempty"`
	Deliveries         []alertWorkflowDelivery  `json:"deliveries"`
	EvaluatorRunning   bool                     `json:"evaluator_running"`
	PersistenceRunning bool                     `json:"persistence_running"`
	ConnectorRunning   bool                     `json:"connector_running"`
}

// handleAlertWorkflow joins the engine's current state to durable, immutable
// operator audit receipts and (when supplied) a freshly tenant-authorized
// incident plus its persisted on-call/ticket delivery links.
func (s *Server) handleAlertWorkflow(w http.ResponseWriter, r *http.Request) error {
	src, _, err := s.alertStateFor(r)
	if err != nil {
		return err
	}
	fingerprint := strings.TrimSpace(r.PathValue("fingerprint"))
	if fingerprint == "" {
		return apierror.Validation("fingerprint is required")
	}
	var active *alert.ActiveAlert
	if src != nil {
		for _, item := range src.Active() {
			if item.Fingerprint == fingerprint {
				itemCopy := item
				active = &itemCopy
				break
			}
		}
	}
	resp := alertWorkflowResponse{
		Alert: active, Operations: []alertWorkflowOperation{}, Deliveries: []alertWorkflowDelivery{},
		EvaluatorRunning: src != nil, PersistenceRunning: s.pool != nil,
		ConnectorRunning: s.dispatcher != nil,
	}
	if s.pool == nil {
		if active == nil {
			return apierror.NotFound("no alert workflow with that fingerprint")
		}
		writeJSON(w, http.StatusOK, resp)
		return nil
	}
	incidentID := strings.TrimSpace(r.URL.Query().Get("incident_id"))
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		events, err := audit.ListAlertWorkflow(ctx, sc, fingerprint, 200)
		if err != nil {
			return err
		}
		for _, ev := range events {
			resp.Operations = append(resp.Operations, alertWorkflowOperationFromAudit(ev))
		}
		if incidentID == "" {
			return nil
		}
		inc, err := (store.Incidents{}).Get(ctx, sc, incidentID)
		if err != nil {
			return err
		}
		resp.Incident = inc
		links, err := (store.IncidentIntegrations{}).ListForIncident(ctx, sc, incidentID)
		if err != nil {
			return err
		}
		for _, link := range links {
			resp.Deliveries = append(resp.Deliveries, alertWorkflowDelivery{
				Connector: link.Connector, ExternalRef: link.ExternalRef, Status: link.Status,
				CreatedAt: link.CreatedAt, UpdatedAt: link.UpdatedAt,
				ReceiptRef: fmt.Sprintf("connector:%s:%s", link.Connector, link.ExternalRef),
			})
		}
		return nil
	}); err != nil {
		return err
	}
	if active == nil && len(resp.Operations) == 0 {
		return apierror.NotFound("no alert workflow with that fingerprint")
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

func alertWorkflowOperationFromAudit(ev audit.Event) alertWorkflowOperation {
	action := "acknowledged"
	if ev.Action == "alert.silence" {
		action = "silenced"
		if numberFromAuditData(ev.Data["duration_minutes"]) == 0 {
			action = "unsilenced"
		}
	}
	return alertWorkflowOperation{
		Action: action, Actor: ev.Actor, Reason: stringFromAuditData(ev.Data["reason"]),
		StartedAt: ev.CreatedAt, ExpiresAt: timeFromAuditData(ev.Data["expires_at"]),
		DeliveryStatus: "not_applicable", AuditRef: alertAuditReference(ev),
	}
}

func alertAuditReference(ev audit.Event) string {
	return fmt.Sprintf("audit:%d:%s", ev.Seq, ev.Hash)
}

func boundedAlertReason(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = fallback
	}
	runes := []rune(value)
	if len(runes) > 500 {
		value = string(runes[:500])
	}
	return value
}

func stringFromAuditData(value any) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func numberFromAuditData(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	default:
		n, _ := strconv.Atoi(fmt.Sprint(value))
		return n
	}
}

func timeFromAuditData(value any) *time.Time {
	raw := stringFromAuditData(value)
	if raw == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return nil
	}
	return &parsed
}
