// SPDX-License-Identifier: LicenseRef-probectl-TBD

package inventory

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryViewStoreTenantIsolation(t *testing.T) {
	store := NewMemoryViewStore()
	store.now = fixed(time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC))
	a, err := store.Save(context.Background(), "tenant-a", "user-a", SaveViewInput{
		Surface: SurfaceEndpoints,
		Name:    "WiFi trouble",
		Filters: map[string]string{"cause": "wifi", "q": "anna"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(context.Background(), "tenant-b", "user-a", SaveViewInput{
		Surface: SurfaceEndpoints,
		Name:    "Tenant B",
		Filters: map[string]string{"cause": "none"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(context.Background(), "tenant-a", "user-b", SaveViewInput{
		Surface: SurfaceEndpoints,
		Name:    "Other user",
		Filters: map[string]string{"cause": "isp"},
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := store.List(context.Background(), "tenant-a", "user-a", SurfaceEndpoints)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != a.ID || rows[0].Filters["cause"] != "wifi" {
		t.Fatalf("tenant-a rows = %+v", rows)
	}
	if _, err := store.Get(context.Background(), "tenant-b", "user-a", a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant-b opened tenant-a view: %v", err)
	}
	if _, err := store.Get(context.Background(), "tenant-a", "user-b", a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("user-b opened user-a view: %v", err)
	}
}

func TestMemoryViewStoreValidation(t *testing.T) {
	store := NewMemoryViewStore()
	for name, input := range map[string]SaveViewInput{
		"no surface":  {Name: "x"},
		"bad surface": {Surface: "secrets", Name: "x"},
		"no name":     {Surface: SurfaceEndpoints},
	} {
		if _, err := store.Save(context.Background(), "tenant-a", "user-a", input); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	for _, surface := range []string{SurfaceEndpoints, SurfaceTargets, SurfaceAgents, SurfaceIncidents, SurfaceAlerts} {
		if _, err := store.Save(context.Background(), "tenant-a", "user-a", SaveViewInput{
			Surface: surface,
			Name:    surface,
		}); err != nil {
			t.Fatalf("surface %s rejected: %v", surface, err)
		}
	}
}

func fixed(t time.Time) func() time.Time {
	return func() time.Time {
		t = t.Add(time.Second)
		return t
	}
}
