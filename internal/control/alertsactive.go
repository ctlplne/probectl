package control

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
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
	if src != nil {
		if s.alertState == nil {
			s.alertState = map[string]AlertStateSource{}
		}
		s.alertState[tenant] = src
	}
	return s
}

// alertStateFor resolves the CALLER's engine (tenant boundary first).
func (s *Server) alertStateFor(r *http.Request) (AlertStateSource, string, error) {
	tid, err := s.principalTenant(r)
	if err != nil {
		return nil, "", err
	}
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
	if s.pool != nil {
		if aerr := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			return s.recordAudit(ctx, sc, r, "alert.silence", a.RuleID,
				map[string]any{"fingerprint": a.Fingerprint, "duration_minutes": req.DurationMinutes})
		}); aerr != nil {
			s.log.Warn("alert.silence audit failed", "error", aerr)
		}
	}
	writeJSON(w, http.StatusOK, a)
	return nil
}

// ackRequest is the acknowledge action body.
type ackRequest struct {
	Fingerprint string `json:"fingerprint"`
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
	if s.pool != nil {
		if auErr := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			return s.recordAudit(ctx, sc, r, "alert.acknowledge", a.RuleID,
				map[string]any{"fingerprint": a.Fingerprint, "by": by})
		}); auErr != nil {
			s.log.Warn("alert.acknowledge audit failed", "error", auErr)
		}
	}
	writeJSON(w, http.StatusOK, a)
	return nil
}
