// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package inventory contains reusable operator-list primitives such as saved
// views. A saved view is tenant-owned UI/config state: it stores filter choices,
// not inventory rows, so opening one always re-queries the caller's current
// tenant-scoped list.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	SurfaceEndpoints = "endpoints"
	SurfaceTargets   = "targets"
	SurfaceAgents    = "agents"
	SurfaceIncidents = "incidents"
	SurfaceAlerts    = "alerts"
)

var ErrNotFound = errors.New("inventory saved view not found")

// SaveViewInput is the create/update payload.
type SaveViewInput struct {
	Surface string            `json:"surface"`
	Name    string            `json:"name"`
	Filters map[string]string `json:"filters,omitempty"`
}

// SavedView is the tenant-owned saved filter set returned to clients.
type SavedView struct {
	ID        string            `json:"id"`
	TenantID  string            `json:"tenant_id"`
	OwnerID   string            `json:"owner_id,omitempty"`
	Surface   string            `json:"surface"`
	Name      string            `json:"name"`
	Filters   map[string]string `json:"filters"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// ViewStore persists saved views behind a tenant boundary.
type ViewStore interface {
	Save(ctx context.Context, tenantID, ownerID string, input SaveViewInput) (SavedView, error)
	List(ctx context.Context, tenantID, ownerID, surface string) ([]SavedView, error)
	Get(ctx context.Context, tenantID, ownerID, id string) (SavedView, error)
}

// MemoryViewStore is the lightweight/test implementation. Its outer map key is
// tenant_id, matching the storage-layer boundary pattern used by other in-memory
// read models.
type MemoryViewStore struct {
	mu       sync.RWMutex
	seq      atomic.Uint64
	now      func() time.Time
	byTenant map[string]map[string]SavedView
}

// NewMemoryViewStore builds an empty tenant-scoped saved-view store.
func NewMemoryViewStore() *MemoryViewStore {
	return &MemoryViewStore{now: time.Now, byTenant: map[string]map[string]SavedView{}}
}

// Save creates a saved view for one tenant.
func (s *MemoryViewStore) Save(ctx context.Context, tenantID, ownerID string, input SaveViewInput) (SavedView, error) {
	if err := ctx.Err(); err != nil {
		return SavedView{}, err
	}
	if strings.TrimSpace(tenantID) == "" {
		return SavedView{}, errors.New("inventory saved view: tenant_id is required")
	}
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return SavedView{}, errors.New("inventory saved view: owner_id is required")
	}
	input, err := cleanInput(input)
	if err != nil {
		return SavedView{}, err
	}
	now := s.now()
	view := SavedView{
		ID:        fmt.Sprintf("view-%d", s.seq.Add(1)),
		TenantID:  tenantID,
		OwnerID:   ownerID,
		Surface:   input.Surface,
		Name:      input.Name,
		Filters:   copyFilters(input.Filters),
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byTenant[tenantID] == nil {
		s.byTenant[tenantID] = map[string]SavedView{}
	}
	s.byTenant[tenantID][view.ID] = cloneView(view)
	return view, nil
}

// List returns the tenant's saved views, newest first.
func (s *MemoryViewStore) List(ctx context.Context, tenantID, ownerID, surface string) ([]SavedView, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(tenantID) == "" {
		return nil, errors.New("inventory saved view: tenant_id is required")
	}
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return nil, errors.New("inventory saved view: owner_id is required")
	}
	surface = strings.ToLower(strings.TrimSpace(surface))
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []SavedView{}
	for _, view := range s.byTenant[tenantID] {
		if view.OwnerID != ownerID {
			continue
		}
		if surface != "" && view.Surface != surface {
			continue
		}
		out = append(out, cloneView(view))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// Get returns one tenant-owned saved view by ID.
func (s *MemoryViewStore) Get(ctx context.Context, tenantID, ownerID, id string) (SavedView, error) {
	if err := ctx.Err(); err != nil {
		return SavedView{}, err
	}
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return SavedView{}, errors.New("inventory saved view: owner_id is required")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	view, ok := s.byTenant[tenantID][id]
	if !ok || view.OwnerID != ownerID {
		return SavedView{}, ErrNotFound
	}
	return cloneView(view), nil
}

func cleanInput(input SaveViewInput) (SaveViewInput, error) {
	input.Surface = strings.ToLower(strings.TrimSpace(input.Surface))
	input.Name = strings.TrimSpace(input.Name)
	if input.Surface == "" {
		return SaveViewInput{}, errors.New("inventory saved view: surface is required")
	}
	if !supportedSurface(input.Surface) {
		return SaveViewInput{}, fmt.Errorf("inventory saved view: unsupported surface %q", input.Surface)
	}
	if input.Name == "" {
		return SaveViewInput{}, errors.New("inventory saved view: name is required")
	}
	if len(input.Name) > 80 {
		return SaveViewInput{}, errors.New("inventory saved view: name is too long")
	}
	input.Filters = copyFilters(input.Filters)
	if len(input.Filters) > 12 {
		return SaveViewInput{}, errors.New("inventory saved view: too many filters")
	}
	for k, v := range input.Filters {
		key := strings.TrimSpace(k)
		value := strings.TrimSpace(v)
		if key == "" {
			return SaveViewInput{}, errors.New("inventory saved view: empty filter key")
		}
		if len(key) > 40 || len(value) > 200 {
			return SaveViewInput{}, errors.New("inventory saved view: filter key/value too long")
		}
		if key != k || value != v {
			delete(input.Filters, k)
			input.Filters[key] = value
		}
	}
	return input, nil
}

func supportedSurface(surface string) bool {
	switch surface {
	case SurfaceEndpoints, SurfaceTargets, SurfaceAgents, SurfaceIncidents, SurfaceAlerts:
		return true
	default:
		return false
	}
}

func copyFilters(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		if strings.TrimSpace(v) == "" {
			continue
		}
		out[k] = v
	}
	return out
}

func cloneView(in SavedView) SavedView {
	out := in
	out.Filters = copyFilters(in.Filters)
	return out
}
