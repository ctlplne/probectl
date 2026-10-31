// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

const maxQueryViewPageBytes = 8 << 20

type QueryViewList struct {
	After      string
	Limit      int
	Search     string
	Label      string
	Visibility string
	Owner      string
	Sort       string
	Tab        string
}

type QueryViewPage struct {
	Items []SavedQueryView `json:"items"`
	Next  string           `json:"next,omitempty"`
}

type QueryViewStore interface {
	SaveQueryView(context.Context, string, string, SaveQueryView) (SavedQueryView, error)
	GetQueryView(context.Context, string, string, string) (SavedQueryView, error)
	ListQueryViews(context.Context, string, string, QueryViewList) (QueryViewPage, error)
	DeleteQueryView(context.Context, string, string, string, string) error
	SetQueryViewPreference(context.Context, string, string, string, *bool, bool) error
}

func NormalizeQueryViewList(input QueryViewList) (QueryViewList, error) {
	if input.Limit == 0 {
		input.Limit = 100
	}
	if input.Limit < 1 || input.Limit > 1000 || len(input.After) > 128 || len(input.Search) > 256 || len(input.Label) > 256 || len(input.Owner) > 1024 {
		return input, errors.New("saved flow query list exceeds its page/filter byte budget")
	}
	switch input.Visibility {
	case "", "private", "tenant":
	default:
		return input, errors.New("saved query list visibility must be private or tenant")
	}
	if input.Sort == "" {
		input.Sort = "name"
	}
	switch input.Sort {
	case "name", "created_at", "updated_at":
	default:
		return input, errors.New("saved query list sort must be name,created_at or updated_at")
	}
	if input.Tab == "" {
		input.Tab = "all"
	}
	switch input.Tab {
	case "all", "favorites", "recents":
	default:
		return input, errors.New("saved query list tab must be all,favorites or recents")
	}
	return input, nil
}

func cloneQueryView(item SavedQueryView) (SavedQueryView, error) {
	body, err := json.Marshal(item)
	if err != nil {
		return SavedQueryView{}, err
	}
	var owned SavedQueryView
	if err := json.Unmarshal(body, &owned); err != nil {
		return SavedQueryView{}, err
	}
	owned.TenantID = item.TenantID
	return owned, nil
}

func queryViewVisible(item SavedQueryView, owner string) bool {
	return item.OwnerID == owner || item.Definition.Visibility == "tenant"
}

func compareQueryViews(a, b SavedQueryView, input QueryViewList) int {
	if input.Tab == "recents" {
		if a.LastOpenedAt != nil && b.LastOpenedAt != nil && !a.LastOpenedAt.Equal(*b.LastOpenedAt) {
			if a.LastOpenedAt.After(*b.LastOpenedAt) {
				return -1
			}
			return 1
		}
		return strings.Compare(a.ID, b.ID)
	}
	switch input.Sort {
	case "name":
		if a.Definition.Name != b.Definition.Name {
			return strings.Compare(a.Definition.Name, b.Definition.Name)
		}
	case "created_at":
		if !a.CreatedAt.Equal(b.CreatedAt) {
			if a.CreatedAt.After(b.CreatedAt) {
				return -1
			}
			return 1
		}
	case "updated_at":
		if !a.UpdatedAt.Equal(b.UpdatedAt) {
			if a.UpdatedAt.After(b.UpdatedAt) {
				return -1
			}
			return 1
		}
	}
	return strings.Compare(a.ID, b.ID)
}

func appendQueryViewPage(page *QueryViewPage, item SavedQueryView, limit int, used *int) (bool, error) {
	encoded, err := json.Marshal(item)
	if err != nil {
		return false, err
	}
	if len(encoded) > maxQueryViewPageBytes {
		return false, ErrQueryViewBudget
	}
	if len(page.Items) >= limit || *used+len(encoded)+1 > maxQueryViewPageBytes {
		page.Next = page.Items[len(page.Items)-1].ID
		return true, nil
	}
	*used += len(encoded) + 1
	page.Items = append(page.Items, item)
	return false, nil
}

type queryViewPreference struct {
	Favorite bool
	Opened   *time.Time
}

type MemoryQueryViewStore struct {
	mu          sync.Mutex
	byTenant    map[string]map[string]SavedQueryView
	preferences map[string]map[string]map[string]queryViewPreference
	filters     QueryFilterReader
	maxBytes    int
	now         func() time.Time
}

func NewMemoryQueryViewStore(filters QueryFilterReader, maxBytes int) *MemoryQueryViewStore {
	if maxBytes <= 0 {
		maxBytes = 64 << 20
	}
	return &MemoryQueryViewStore{byTenant: map[string]map[string]SavedQueryView{}, preferences: map[string]map[string]map[string]queryViewPreference{}, filters: filters, maxBytes: maxBytes, now: time.Now}
}

func queryViewScope(tenant, owner string) error {
	if strings.TrimSpace(tenant) == "" || strings.TrimSpace(owner) == "" || len(owner) > 1024 {
		return errors.New("saved flow query requires authenticated tenant and owner")
	}
	return nil
}

func (s *MemoryQueryViewStore) SaveQueryView(ctx context.Context, tenant, owner string, input SaveQueryView) (SavedQueryView, error) {
	if err := ctx.Err(); err != nil {
		return SavedQueryView{}, err
	}
	if err := queryViewScope(tenant, owner); err != nil {
		return SavedQueryView{}, err
	}
	input, err := NormalizeSaveQueryView(input, s.now())
	if err != nil {
		return SavedQueryView{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := SavedQueryView{}
	if input.ID != "" {
		var ok bool
		previous, ok = s.byTenant[tenant][input.ID]
		if !ok || previous.OwnerID != owner {
			return SavedQueryView{}, ErrQueryViewNotFound
		}
		if input.Version != previous.Version {
			return SavedQueryView{}, ErrQueryViewConflict
		}
	}
	if _, err := ResolveQueryFilters(ctx, tenant, input.Definition.Plan.Filter, s.filters, ""); err != nil {
		return SavedQueryView{}, err
	}
	revision := int64(0)
	if previous.Version != "" {
		revision, err = QueryViewVersion(previous.Version)
		if err != nil {
			return SavedQueryView{}, err
		}
	}
	if revision == int64(^uint64(0)>>1) {
		return SavedQueryView{}, ErrQueryViewConflict
	}
	now := s.now().UTC()
	id := input.ID
	created := previous.CreatedAt
	if id == "" {
		id, err = crypto.UUIDv4()
		if err != nil {
			return SavedQueryView{}, err
		}
		created = now
	}
	item := SavedQueryView{ID: id, TenantID: tenant, OwnerID: owner, Definition: input.Definition, Version: strconv.FormatInt(revision+1, 10), CreatedAt: created, UpdatedAt: now}
	body, err := json.Marshal(item)
	if err != nil {
		return SavedQueryView{}, err
	}
	used := len(body)
	for otherID, stored := range s.byTenant[tenant] {
		if otherID == id {
			continue
		}
		body, err := json.Marshal(stored)
		if err != nil {
			return SavedQueryView{}, err
		}
		used += len(body)
	}
	if used > s.maxBytes {
		return SavedQueryView{}, ErrQueryViewBudget
	}
	if s.byTenant[tenant] == nil {
		s.byTenant[tenant] = map[string]SavedQueryView{}
	}
	s.byTenant[tenant][id] = item
	return s.decorate(tenant, owner, item)
}

func (s *MemoryQueryViewStore) decorate(tenant, owner string, item SavedQueryView) (SavedQueryView, error) {
	pref := s.preferences[tenant][owner][item.ID]
	item.Favorite = pref.Favorite
	item.LastOpenedAt = pref.Opened
	return cloneQueryView(item)
}

func (s *MemoryQueryViewStore) GetQueryView(ctx context.Context, tenant, owner, id string) (SavedQueryView, error) {
	if err := ctx.Err(); err != nil {
		return SavedQueryView{}, err
	}
	if err := queryViewScope(tenant, owner); err != nil {
		return SavedQueryView{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.byTenant[tenant][id]
	if !ok || !queryViewVisible(item, owner) {
		return SavedQueryView{}, ErrQueryViewNotFound
	}
	return s.decorate(tenant, owner, item)
}

func (s *MemoryQueryViewStore) ListQueryViews(ctx context.Context, tenant, owner string, input QueryViewList) (QueryViewPage, error) {
	if err := ctx.Err(); err != nil {
		return QueryViewPage{}, err
	}
	if err := queryViewScope(tenant, owner); err != nil {
		return QueryViewPage{}, err
	}
	input, err := NormalizeQueryViewList(input)
	if err != nil {
		return QueryViewPage{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var after SavedQueryView
	if input.After != "" {
		var ok bool
		after, ok = s.byTenant[tenant][input.After]
		if !ok || !queryViewVisible(after, owner) {
			return QueryViewPage{}, ErrQueryViewNotFound
		}
		after, err = s.decorate(tenant, owner, after)
		if err != nil {
			return QueryViewPage{}, err
		}
		if input.Tab == "recents" && after.LastOpenedAt == nil {
			return QueryViewPage{}, ErrQueryViewNotFound
		}
	}
	items := []SavedQueryView{}
	for _, stored := range s.byTenant[tenant] {
		if !queryViewVisible(stored, owner) || input.Visibility != "" && stored.Definition.Visibility != input.Visibility || input.Owner != "" && stored.OwnerID != input.Owner || !strings.Contains(strings.ToLower(stored.Definition.Name), strings.ToLower(input.Search)) {
			continue
		}
		item, err := s.decorate(tenant, owner, stored)
		if err != nil {
			return QueryViewPage{}, err
		}
		if input.Tab == "favorites" && !item.Favorite || input.Tab == "recents" && item.LastOpenedAt == nil {
			continue
		}
		if input.Label != "" {
			found := false
			for _, label := range item.Definition.Labels {
				found = found || label == input.Label
			}
			if !found {
				continue
			}
		}
		if input.After != "" && compareQueryViews(item, after, input) <= 0 {
			continue
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return compareQueryViews(items[i], items[j], input) < 0 })
	page := QueryViewPage{Items: []SavedQueryView{}}
	used := 0
	for _, item := range items {
		more, err := appendQueryViewPage(&page, item, input.Limit, &used)
		if err != nil {
			return QueryViewPage{}, err
		}
		if more {
			break
		}
	}
	return page, nil
}

func (s *MemoryQueryViewStore) DeleteQueryView(ctx context.Context, tenant, owner, id, version string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := queryViewScope(tenant, owner); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.byTenant[tenant][id]
	if !ok || item.OwnerID != owner {
		return ErrQueryViewNotFound
	}
	if _, err := QueryViewVersion(version); err != nil {
		return err
	}
	if item.Version != version {
		return ErrQueryViewConflict
	}
	delete(s.byTenant[tenant], id)
	for _, preferences := range s.preferences[tenant] {
		delete(preferences, id)
	}
	return nil
}

func (s *MemoryQueryViewStore) SetQueryViewPreference(ctx context.Context, tenant, owner, id string, favorite *bool, opened bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := queryViewScope(tenant, owner); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.byTenant[tenant][id]
	if !ok || !queryViewVisible(item, owner) {
		return ErrQueryViewNotFound
	}
	if s.preferences[tenant] == nil {
		s.preferences[tenant] = map[string]map[string]queryViewPreference{}
	}
	if s.preferences[tenant][owner] == nil {
		s.preferences[tenant][owner] = map[string]queryViewPreference{}
	}
	pref := s.preferences[tenant][owner][id]
	if favorite != nil {
		pref.Favorite = *favorite
	}
	if opened {
		now := s.now().UTC()
		pref.Opened = &now
	}
	if _, exists := s.preferences[tenant][owner][id]; !exists {
		count := 0
		for _, preferences := range s.preferences[tenant] {
			count += len(preferences)
		}
		if count > (s.maxBytes / 128) {
			return ErrQueryViewBudget
		}
	}
	s.preferences[tenant][owner][id] = pref
	return nil
}
