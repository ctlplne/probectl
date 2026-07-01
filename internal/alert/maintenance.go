// SPDX-License-Identifier: LicenseRef-probectl-TBD

package alert

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// MaintenanceRecurrence controls whether a planned maintenance window repeats.
type MaintenanceRecurrence string

const (
	RecurrenceNone   MaintenanceRecurrence = ""
	RecurrenceDaily  MaintenanceRecurrence = "daily"
	RecurrenceWeekly MaintenanceRecurrence = "weekly"
)

const MaxMaintenanceWindow = 30 * 24 * time.Hour

// MaintenanceWindow is a reusable planned-maintenance suppressor. A window is
// tenant-owned; it can target specific rules, specific resource labels, or both.
type MaintenanceWindow struct {
	ID         string                `json:"id"`
	TenantID   string                `json:"tenant_id,omitempty"`
	Name       string                `json:"name"`
	Reason     string                `json:"reason,omitempty"`
	StartsAt   time.Time             `json:"starts_at"`
	EndsAt     time.Time             `json:"ends_at"`
	Recurrence MaintenanceRecurrence `json:"recurrence,omitempty"`
	Match      map[string]string     `json:"match,omitempty"`
	RuleIDs    []string              `json:"rule_ids,omitempty"`
	CreatedBy  string                `json:"created_by,omitempty"`
	CreatedAt  time.Time             `json:"created_at,omitempty"`
	UpdatedAt  time.Time             `json:"updated_at,omitempty"`
}

// MaintenancePreview is one future/active occurrence of a window.
type MaintenancePreview struct {
	WindowID string    `json:"window_id"`
	Name     string    `json:"name"`
	StartsAt time.Time `json:"starts_at"`
	EndsAt   time.Time `json:"ends_at"`
	Reason   string    `json:"reason,omitempty"`
}

func (w MaintenanceWindow) Validate() error {
	if strings.TrimSpace(w.Name) == "" || len(w.Name) > 200 {
		return fmt.Errorf("alert: maintenance window name is required (1-200 chars)")
	}
	if w.StartsAt.IsZero() || w.EndsAt.IsZero() || !w.EndsAt.After(w.StartsAt) {
		return fmt.Errorf("alert: maintenance window requires starts_at < ends_at")
	}
	d := w.EndsAt.Sub(w.StartsAt)
	if d > MaxMaintenanceWindow {
		return fmt.Errorf("alert: maintenance window duration must be <= %s", MaxMaintenanceWindow)
	}
	switch w.Recurrence {
	case RecurrenceNone, RecurrenceDaily, RecurrenceWeekly:
	default:
		return fmt.Errorf("alert: recurrence must be daily, weekly, or omitted")
	}
	if period := w.period(); period > 0 && d >= period {
		return fmt.Errorf("alert: recurring maintenance window duration must be shorter than its period")
	}
	for k, v := range w.Match {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			return fmt.Errorf("alert: maintenance match labels require non-empty keys and values")
		}
	}
	for _, id := range w.RuleIDs {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("alert: maintenance rule_ids cannot contain empty values")
		}
	}
	return nil
}

// Matches reports whether this window targets the supplied rule/series labels.
func (w MaintenanceWindow) Matches(rule Rule, labels map[string]string) bool {
	return w.matches(rule, labels)
}

func (w MaintenanceWindow) matches(rule Rule, labels map[string]string) bool {
	if w.TenantID != "" && rule.TenantID != "" && w.TenantID != rule.TenantID {
		return false
	}
	if len(w.RuleIDs) > 0 && !slices.Contains(w.RuleIDs, rule.ID) {
		return false
	}
	for k, want := range w.Match {
		if labels[k] != want {
			return false
		}
	}
	return true
}

func (w MaintenanceWindow) occurrenceAt(t time.Time) (MaintenancePreview, bool) {
	if w.Recurrence == RecurrenceNone {
		if !t.Before(w.StartsAt) && t.Before(w.EndsAt) {
			return w.preview(w.StartsAt, w.EndsAt), true
		}
		return MaintenancePreview{}, false
	}
	period := w.period()
	if period <= 0 || t.Before(w.StartsAt) {
		return MaintenancePreview{}, false
	}
	n := int64(t.Sub(w.StartsAt) / period)
	start := w.StartsAt.Add(time.Duration(n) * period)
	end := start.Add(w.EndsAt.Sub(w.StartsAt))
	if !t.Before(start) && t.Before(end) {
		return w.preview(start, end), true
	}
	return MaintenancePreview{}, false
}

// OccurrencesBetween previews every occurrence that overlaps [from, to).
func (w MaintenanceWindow) OccurrencesBetween(from, to time.Time) []MaintenancePreview {
	return w.occurrencesBetween(from, to)
}

func (w MaintenanceWindow) occurrencesBetween(from, to time.Time) []MaintenancePreview {
	if !to.After(from) {
		return nil
	}
	if w.Recurrence == RecurrenceNone {
		if w.EndsAt.After(from) && w.StartsAt.Before(to) {
			return []MaintenancePreview{w.preview(w.StartsAt, w.EndsAt)}
		}
		return nil
	}
	period := w.period()
	if period <= 0 {
		return nil
	}
	duration := w.EndsAt.Sub(w.StartsAt)
	start := w.StartsAt
	if from.After(start) {
		n := int64(from.Sub(start) / period)
		start = start.Add(time.Duration(n) * period)
		for start.Add(duration).Before(from) || start.Add(duration).Equal(from) {
			start = start.Add(period)
		}
	}
	var out []MaintenancePreview
	for start.Before(to) {
		end := start.Add(duration)
		if end.After(from) {
			out = append(out, w.preview(start, end))
		}
		start = start.Add(period)
	}
	return out
}

func (w MaintenanceWindow) preview(start, end time.Time) MaintenancePreview {
	return MaintenancePreview{WindowID: w.ID, Name: w.Name, StartsAt: start, EndsAt: end, Reason: w.Reason}
}

func (w MaintenanceWindow) period() time.Duration {
	switch w.Recurrence {
	case RecurrenceDaily:
		return 24 * time.Hour
	case RecurrenceWeekly:
		return 7 * 24 * time.Hour
	default:
		return 0
	}
}

// UpsertMaintenanceWindow installs or updates one tenant's reusable window.
func (en *Engine) UpsertMaintenanceWindow(w MaintenanceWindow) (MaintenanceWindow, error) {
	en.mu.Lock()
	defer en.mu.Unlock()
	now := en.clock()
	if w.ID == "" {
		w.ID = fmt.Sprintf("mw-%d", now.UnixNano())
	}
	if existing, ok := en.maintenance[w.ID]; ok {
		if w.CreatedAt.IsZero() {
			w.CreatedAt = existing.CreatedAt
		}
		if w.CreatedBy == "" {
			w.CreatedBy = existing.CreatedBy
		}
	}
	if w.CreatedAt.IsZero() {
		w.CreatedAt = now
	}
	w.UpdatedAt = now
	if err := w.Validate(); err != nil {
		return MaintenanceWindow{}, err
	}
	if en.maintenance == nil {
		en.maintenance = map[string]MaintenanceWindow{}
	}
	en.maintenance[w.ID] = cloneMaintenanceWindow(w)
	return cloneMaintenanceWindow(w), nil
}

func (en *Engine) DeleteMaintenanceWindow(id string) bool {
	en.mu.Lock()
	defer en.mu.Unlock()
	if en.maintenance == nil {
		return false
	}
	if _, ok := en.maintenance[id]; !ok {
		return false
	}
	delete(en.maintenance, id)
	return true
}

func (en *Engine) MaintenanceWindows() []MaintenanceWindow {
	en.mu.Lock()
	defer en.mu.Unlock()
	out := make([]MaintenanceWindow, 0, len(en.maintenance))
	for _, w := range en.maintenance {
		out = append(out, cloneMaintenanceWindow(w))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].StartsAt.Equal(out[j].StartsAt) {
			return out[i].StartsAt.Before(out[j].StartsAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (en *Engine) PreviewMaintenance(rule Rule, labels map[string]string, from, to time.Time) []MaintenancePreview {
	en.mu.Lock()
	defer en.mu.Unlock()
	var out []MaintenancePreview
	for _, w := range en.maintenance {
		if !w.matches(rule, labels) {
			continue
		}
		out = append(out, w.occurrencesBetween(from, to)...)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].StartsAt.Equal(out[j].StartsAt) {
			return out[i].StartsAt.Before(out[j].StartsAt)
		}
		return out[i].WindowID < out[j].WindowID
	})
	return out
}

func (en *Engine) activeMaintenanceLocked(rule Rule, s Sample, now time.Time) (MaintenancePreview, bool) {
	for _, w := range en.maintenance {
		if !w.matches(rule, s.Labels) {
			continue
		}
		if occ, ok := w.occurrenceAt(now); ok {
			return occ, true
		}
	}
	return MaintenancePreview{}, false
}

func cloneMaintenanceWindow(w MaintenanceWindow) MaintenanceWindow {
	w.Match = cloneStringMap(w.Match)
	w.RuleIDs = append([]string(nil), w.RuleIDs...)
	return w
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
