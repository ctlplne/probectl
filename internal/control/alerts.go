// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"net/http"

	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// alertRequest is the create/update body for an alert rule.
type alertRequest struct {
	Name            string              `json:"name"`
	Enabled         *bool               `json:"enabled"`
	Metric          string              `json:"metric"`
	Match           map[string]string   `json:"match"`
	Type            string              `json:"type"`
	Comparison      string              `json:"comparison"`
	Threshold       float64             `json:"threshold"`
	Window          int                 `json:"window"`
	Sensitivity     float64             `json:"sensitivity"`
	ForN            int                 `json:"for_n"`
	RenotifySeconds int                 `json:"renotify_seconds"`
	Severity        string              `json:"severity"`
	Channels        []alert.ChannelSpec `json:"channels"`
}

func (req alertRequest) toRule() (alert.Rule, error) {
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	severity := alert.Severity(req.Severity)
	if severity == "" {
		severity = alert.SeverityWarning
	}
	r := alert.Rule{
		Name:            req.Name,
		Enabled:         enabled,
		Metric:          req.Metric,
		Match:           req.Match,
		Type:            alert.RuleType(req.Type),
		Comparison:      alert.Comparison(req.Comparison),
		Threshold:       req.Threshold,
		Window:          req.Window,
		Sensitivity:     req.Sensitivity,
		ForN:            req.ForN,
		RenotifySeconds: req.RenotifySeconds,
		Severity:        severity,
		Channels:        req.Channels,
	}
	if err := r.Validate(); err != nil {
		return alert.Rule{}, apierror.Validation(err.Error())
	}
	return r, nil
}

// redactRule blanks webhook secrets so they are never returned in an API
// response (the engine still reads the stored secret to sign — guardrail 6).
func redactRule(r *alert.Rule) alert.Rule {
	out := *r
	if len(r.Channels) > 0 {
		ch := make([]alert.ChannelSpec, len(r.Channels))
		copy(ch, r.Channels)
		for i := range ch {
			if ch[i].Secret != "" {
				ch[i].Secret = "***"
			}
		}
		out.Channels = ch
	}
	return out
}

func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) error {
	var rules []alert.Rule
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		rs, e := store.AlertRules{}.List(ctx, sc)
		rules = rs
		return e
	}); err != nil {
		return err
	}
	items := make([]alert.Rule, len(rules))
	for i := range rules {
		items[i] = redactRule(&rules[i])
	}
	resp := map[string]any{"items": items, "alerting_active": s.alertingActive}
	if !s.alertingActive {
		// ARCH-002/CORRECT-006: don't let the UI imply these rules fire. Say so.
		resp["warning"] = "alerting is INACTIVE in this deployment profile — these rules are stored but NOT evaluated (no query backend wired); see docs/alerting.md"
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// WithAlertingActive records whether the alert evaluator is running in this
// profile so the rules API can tell the operator the truth (ARCH-002).
func (s *Server) WithAlertingActive(active bool) *Server {
	s.alertingActive = active
	return s
}

func (s *Server) handleCreateAlert(w http.ResponseWriter, r *http.Request) error {
	var req alertRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	rule, err := req.toRule()
	if err != nil {
		return err
	}
	var created *alert.Rule
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.AlertRules{}.Create(ctx, sc, rule)
		if e != nil {
			return e
		}
		created = x
		return s.recordAudit(ctx, sc, r, "alert.create", x.ID, map[string]any{"name": x.Name})
	}); err != nil {
		return err
	}
	w.Header().Set("Location", "/v1/alerts/"+created.ID)
	out := redactRule(created)
	if !s.alertingActive {
		// ARCH-002/CORRECT-006: the rule is persisted (config survives a profile
		// change) but will NOT fire until a query backend is wired. Surface that
		// as a Warning HEADER, NOT by wrapping the body: the create response must
		// stay a consistent bare alert.Rule — the web client (web/src/api/alerts.ts
		// expects AlertRule) and the API contract depend on it. This keeps the
		// "never silently store a dead rule" guarantee without breaking the shape.
		w.Header().Set("Warning", `199 - "alert rule stored but NOT evaluated: alerting is inactive in this deployment profile (no query backend); see docs/alerting.md"`)
		w.Header().Set("X-Probectl-Alerting-Active", "false")
	}
	writeJSON(w, http.StatusCreated, &out)
	return nil
}

func (s *Server) handleGetAlert(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	var rule *alert.Rule
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.AlertRules{}.Get(ctx, sc, id)
		rule = x
		return e
	}); err != nil {
		return err
	}
	out := redactRule(rule)
	writeJSON(w, http.StatusOK, &out)
	return nil
}

func (s *Server) handleUpdateAlert(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	var req alertRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	rule, err := req.toRule()
	if err != nil {
		return err
	}
	var updated *alert.Rule
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.AlertRules{}.Update(ctx, sc, id, rule)
		if e != nil {
			return e
		}
		updated = x
		return s.recordAudit(ctx, sc, r, "alert.update", id, map[string]any{"name": x.Name})
	}); err != nil {
		return err
	}
	out := redactRule(updated)
	writeJSON(w, http.StatusOK, &out)
	return nil
}

func (s *Server) handleDeleteAlert(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if e := (store.AlertRules{}).Delete(ctx, sc, id); e != nil {
			return e
		}
		return s.recordAudit(ctx, sc, r, "alert.delete", id, nil)
	}); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
