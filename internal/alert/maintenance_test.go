// SPDX-License-Identifier: LicenseRef-probectl-TBD

package alert

import (
	"testing"
	"time"
)

func TestMaintenanceWindowSuppressesExpiresAndStaysTenantScoped(t *testing.T) {
	h, rule := newActiveHarness(t)
	end := h.now.Add(10 * time.Minute)
	_, err := h.en.UpsertMaintenanceWindow(MaintenanceWindow{
		ID: "mw-planned-db", TenantID: "t-a", Name: "database patch",
		StartsAt: h.now.Add(-time.Minute), EndsAt: end,
		Match: map[string]string{"target": "db"},
	})
	if err != nil {
		t.Fatal(err)
	}

	h.value = 250
	h.eval(t, rule)
	if h.sinked != 0 {
		t.Fatalf("maintenance leaked notification: sinked=%d", h.sinked)
	}
	active := h.en.Active()
	if len(active) != 1 || active[0].SilencedUntil == nil || !active[0].SilencedUntil.Equal(end) {
		t.Fatalf("active during maintenance = %+v", active)
	}

	// The same still-breaching episode notifies once the planned window expires;
	// initial delivery was suppressed, so last_notified is still empty.
	h.now = end.Add(time.Second)
	h.eval(t, rule)
	if h.sinked != 1 {
		t.Fatalf("maintenance expiry did not re-notify: sinked=%d", h.sinked)
	}
	active = h.en.Active()
	if len(active) != 1 || active[0].SilencedUntil != nil {
		t.Fatalf("active after maintenance expiry = %+v", active)
	}

	// Tenant B's schedule is invisible to tenant A's evaluator/rule.
	h2, rule2 := newActiveHarness(t)
	_, err = h2.en.UpsertMaintenanceWindow(MaintenanceWindow{
		ID: "mw-other-tenant", TenantID: "t-b", Name: "other tenant patch",
		StartsAt: h2.now.Add(-time.Minute), EndsAt: h2.now.Add(time.Hour),
		Match: map[string]string{"target": "db"},
	})
	if err != nil {
		t.Fatal(err)
	}
	h2.value = 250
	h2.eval(t, rule2)
	if h2.sinked != 1 {
		t.Fatalf("cross-tenant maintenance suppressed tenant A: sinked=%d", h2.sinked)
	}
}

func TestMaintenanceWindowRecurrencePreviewAndCopies(t *testing.T) {
	h, rule := newActiveHarness(t)
	start := h.now.Add(-24 * time.Hour)
	_, err := h.en.UpsertMaintenanceWindow(MaintenanceWindow{
		ID: "mw-daily", TenantID: "t-a", Name: "daily database deploy",
		StartsAt: start, EndsAt: start.Add(30 * time.Minute), Recurrence: RecurrenceDaily,
		Match: map[string]string{"target": "db"},
	})
	if err != nil {
		t.Fatal(err)
	}

	items := h.en.PreviewMaintenance(rule, map[string]string{"target": "db"}, h.now, h.now.Add(48*time.Hour))
	if len(items) != 2 {
		t.Fatalf("daily preview count = %d, items=%+v", len(items), items)
	}
	if !items[0].StartsAt.Equal(h.now) || !items[1].StartsAt.Equal(h.now.Add(24*time.Hour)) {
		t.Fatalf("daily preview occurrences = %+v", items)
	}

	windows := h.en.MaintenanceWindows()
	windows[0].Match["target"] = "api"
	windows[0].RuleIDs = append(windows[0].RuleIDs, "r2")
	again := h.en.MaintenanceWindows()
	if again[0].Match["target"] != "db" || len(again[0].RuleIDs) != 0 {
		t.Fatalf("maintenance windows were not defensively copied: %+v", again[0])
	}
}

func TestMaintenanceWindowValidation(t *testing.T) {
	base := MaintenanceWindow{
		ID: "mw-ok", TenantID: "t-a", Name: "valid",
		StartsAt: time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC),
		EndsAt:   time.Date(2026, 6, 4, 13, 0, 0, 0, time.UTC),
	}
	cases := map[string]func(MaintenanceWindow) MaintenanceWindow{
		"missing name":   func(w MaintenanceWindow) MaintenanceWindow { w.Name = ""; return w },
		"backwards time": func(w MaintenanceWindow) MaintenanceWindow { w.EndsAt = w.StartsAt; return w },
		"too long": func(w MaintenanceWindow) MaintenanceWindow {
			w.EndsAt = w.StartsAt.Add(MaxMaintenanceWindow + time.Second)
			return w
		},
		"bad recurrence":  func(w MaintenanceWindow) MaintenanceWindow { w.Recurrence = MaintenanceRecurrence("yearly"); return w },
		"empty match key": func(w MaintenanceWindow) MaintenanceWindow { w.Match = map[string]string{"": "db"}; return w },
		"empty rule id":   func(w MaintenanceWindow) MaintenanceWindow { w.RuleIDs = []string{"r1", ""}; return w },
	}
	for name, mutate := range cases {
		if err := mutate(base).Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
