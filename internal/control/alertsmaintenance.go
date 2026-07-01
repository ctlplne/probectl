// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

const maintenancePreviewMaxRange = 90 * 24 * time.Hour

// AlertMaintenanceSource is the reusable planned-window contract implemented
// by *alert.Engine. It is optional so older/pool-less test sources still fail
// closed instead of fabricating a schedule.
type AlertMaintenanceSource interface {
	MaintenanceWindows() []alert.MaintenanceWindow
	UpsertMaintenanceWindow(alert.MaintenanceWindow) (alert.MaintenanceWindow, error)
	DeleteMaintenanceWindow(string) bool
	PreviewMaintenance(alert.Rule, map[string]string, time.Time, time.Time) []alert.MaintenancePreview
}

type maintenanceWindowRequest struct {
	ID         string                      `json:"id,omitempty"`
	Name       string                      `json:"name"`
	Reason     string                      `json:"reason,omitempty"`
	StartsAt   time.Time                   `json:"starts_at"`
	EndsAt     time.Time                   `json:"ends_at"`
	Recurrence alert.MaintenanceRecurrence `json:"recurrence,omitempty"`
	Match      map[string]string           `json:"match,omitempty"`
	RuleIDs    []string                    `json:"rule_ids,omitempty"`
}

type maintenancePreviewRequest struct {
	Window   *maintenanceWindowRequest `json:"window,omitempty"`
	RuleID   string                    `json:"rule_id,omitempty"`
	RuleName string                    `json:"rule_name,omitempty"`
	Labels   map[string]string         `json:"labels,omitempty"`
	From     time.Time                 `json:"from,omitempty"`
	To       time.Time                 `json:"to,omitempty"`
}

func (s *Server) alertMaintenanceFor(r *http.Request) (AlertMaintenanceSource, string, error) {
	src, tid, err := s.alertStateFor(r)
	if err != nil {
		return nil, "", err
	}
	m, ok := src.(AlertMaintenanceSource)
	if !ok {
		return nil, tid, nil
	}
	return m, tid, nil
}

func (req maintenanceWindowRequest) toWindow(tid, createdBy string) alert.MaintenanceWindow {
	return alert.MaintenanceWindow{
		ID:         strings.TrimSpace(req.ID),
		TenantID:   tid,
		Name:       strings.TrimSpace(req.Name),
		Reason:     strings.TrimSpace(req.Reason),
		StartsAt:   req.StartsAt,
		EndsAt:     req.EndsAt,
		Recurrence: req.Recurrence,
		Match:      cloneStringMapControl(req.Match),
		RuleIDs:    cloneStringSlice(req.RuleIDs),
		CreatedBy:  createdBy,
	}
}

func (req maintenancePreviewRequest) rangeOrDefault(now time.Time) (time.Time, time.Time, error) {
	from, to := req.From, req.To
	if from.IsZero() {
		from = now
	}
	if to.IsZero() {
		to = from.Add(7 * 24 * time.Hour)
	}
	if !to.After(from) {
		return time.Time{}, time.Time{}, apierror.Validation("preview requires from < to")
	}
	if to.Sub(from) > maintenancePreviewMaxRange {
		return time.Time{}, time.Time{}, apierror.Validation("preview range must be <= 90 days")
	}
	return from, to, nil
}

func (s *Server) handleListMaintenanceWindows(w http.ResponseWriter, r *http.Request) error {
	src, _, err := s.alertMaintenanceFor(r)
	if err != nil {
		return err
	}
	if src == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []alert.MaintenanceWindow{}, "evaluator_running": false})
		return nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": src.MaintenanceWindows(), "evaluator_running": true})
	return nil
}

func (s *Server) handleUpsertMaintenanceWindow(w http.ResponseWriter, r *http.Request) error {
	src, tid, err := s.alertMaintenanceFor(r)
	if err != nil {
		return err
	}
	if src == nil {
		return apierror.Unavailable("the alert evaluator is not running for this tenant")
	}
	var req maintenanceWindowRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		req.ID = fmt.Sprintf("mw-%d", time.Now().UTC().UnixNano())
	}
	before, existed := maintenanceWindowSnapshot(src, req.ID)
	createdBy := ""
	if !existed {
		createdBy = auditActor(r)
	}
	win := req.toWindow(tid, createdBy)
	if err := win.Validate(); err != nil {
		return apierror.Validation(err.Error())
	}
	out, err := src.UpsertMaintenanceWindow(win)
	if err != nil {
		return apierror.Validation(err.Error())
	}
	if s.pool != nil {
		if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			return s.recordAudit(ctx, sc, r, "alert.maintenance_upsert", out.ID, maintenanceWindowAuditData(out))
		}); err != nil {
			restoreMaintenanceWindow(src, before, existed, out.ID)
			return err
		}
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) handleDeleteMaintenanceWindow(w http.ResponseWriter, r *http.Request) error {
	src, _, err := s.alertMaintenanceFor(r)
	if err != nil {
		return err
	}
	if src == nil {
		return apierror.Unavailable("the alert evaluator is not running for this tenant")
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		return apierror.Validation("maintenance window id is required")
	}
	before, existed := maintenanceWindowSnapshot(src, id)
	if !existed {
		return apierror.NotFound("no maintenance window with that id")
	}
	if !src.DeleteMaintenanceWindow(id) {
		return apierror.NotFound("no maintenance window with that id")
	}
	if s.pool != nil {
		if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			return s.recordAudit(ctx, sc, r, "alert.maintenance_delete", id, map[string]any{"name": before.Name})
		}); err != nil {
			restoreMaintenanceWindow(src, before, true, id)
			return err
		}
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) handlePreviewMaintenanceWindows(w http.ResponseWriter, r *http.Request) error {
	src, tid, err := s.alertMaintenanceFor(r)
	if err != nil {
		return err
	}
	if src == nil {
		return apierror.Unavailable("the alert evaluator is not running for this tenant")
	}
	var req maintenancePreviewRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	from, to, err := req.rangeOrDefault(time.Now().UTC())
	if err != nil {
		return err
	}
	labels := cloneStringMapControl(req.Labels)
	rule := alert.Rule{ID: strings.TrimSpace(req.RuleID), TenantID: tid, Name: strings.TrimSpace(req.RuleName)}
	items := src.PreviewMaintenance(rule, labels, from, to)
	if req.Window != nil {
		win := req.Window.toWindow(tid, "")
		if strings.TrimSpace(win.ID) == "" {
			win.ID = "preview"
		}
		if err := win.Validate(); err != nil {
			return apierror.Validation(err.Error())
		}
		items = nil
		if win.Matches(rule, labels) {
			items = win.OccurrencesBetween(from, to)
		}
	}
	if items == nil {
		items = []alert.MaintenancePreview{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "from": from, "to": to})
	return nil
}

func maintenanceWindowSnapshot(src AlertMaintenanceSource, id string) (alert.MaintenanceWindow, bool) {
	for _, win := range src.MaintenanceWindows() {
		if win.ID == id {
			return win, true
		}
	}
	return alert.MaintenanceWindow{}, false
}

func restoreMaintenanceWindow(src AlertMaintenanceSource, before alert.MaintenanceWindow, existed bool, id string) {
	if existed {
		_, _ = src.UpsertMaintenanceWindow(before)
		return
	}
	src.DeleteMaintenanceWindow(id)
}

func maintenanceWindowAuditData(w alert.MaintenanceWindow) map[string]any {
	return map[string]any{
		"name":       w.Name,
		"starts_at":  w.StartsAt,
		"ends_at":    w.EndsAt,
		"recurrence": string(w.Recurrence),
		"match":      cloneStringMapControl(w.Match),
		"rule_ids":   cloneStringSlice(w.RuleIDs),
	}
}

func cloneStringMapControl(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneStringSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	return append([]string(nil), in...)
}
