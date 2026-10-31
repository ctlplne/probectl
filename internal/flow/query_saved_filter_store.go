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
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

const maxQueryFilterPageBytes = 8 << 20

var (
	ErrQueryFilterNotFound      = errors.New("saved flow filter not found")
	ErrQueryFilterConflict      = errors.New("saved flow filter version conflict")
	ErrQueryFilterStorageBudget = errors.New("saved flow filter storage byte budget exceeded")
)

// SaveQueryFilter carries structured configuration and optimistic concurrency.
// New records omit ID and Version; an update requires the last observed version.
type SaveQueryFilter struct {
	ID          string           `json:"id,omitempty"`
	Version     int64            `json:"version,omitempty"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Expression  QueryFilterGroup `json:"expression"`
}

// QueryFilterPage is an explicitly paged tenant-local configuration listing.
type QueryFilterPage struct {
	Items []SavedQueryFilter `json:"items"`
	Next  string             `json:"next,omitempty"`
}

// QueryFilterStore provides durable implementations with the same tenant-first
// CRUD contract as the memory reference. Durable mutations append their domain audit in the same transaction.
type QueryFilterStore interface {
	QueryFilterReader
	SaveQueryFilter(context.Context, string, string, SaveQueryFilter) (SavedQueryFilter, error)
	ListQueryFilters(context.Context, string, string, int) (QueryFilterPage, error)
	DeleteQueryFilter(context.Context, string, string, string, int64) error
}

// MemoryQueryFilterStore is bounded configuration for lightweight mode/tests.
// Its outer map is the tenant boundary; entries are never silently evicted.
type MemoryQueryFilterStore struct {
	mu                sync.Mutex
	byTenant          map[string]map[string]SavedQueryFilter
	maxBytesPerTenant int
	now               func() time.Time
}

// NewMemoryQueryFilterStore takes an explicit per-tenant storage-byte budget.
func NewMemoryQueryFilterStore(maxBytesPerTenant int) *MemoryQueryFilterStore {
	if maxBytesPerTenant <= 0 {
		maxBytesPerTenant = 64 << 20
	}
	return &MemoryQueryFilterStore{byTenant: map[string]map[string]SavedQueryFilter{}, maxBytesPerTenant: maxBytesPerTenant, now: time.Now}
}

// NormalizeSaveQueryFilter validates reusable configuration before transport authorization.
// Stores repeat validation under their own mutation boundary.
func NormalizeSaveQueryFilter(input SaveQueryFilter) (SaveQueryFilter, error) {
	input.ID = strings.TrimSpace(input.ID)
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	if input.Name == "" || len(input.Name) > 256 || len(input.Description) > 4096 {
		return SaveQueryFilter{}, errors.New("saved flow filter needs a name of 1-256 bytes and description at most 4096 bytes")
	}
	if (input.ID == "" && input.Version != 0) || (input.ID != "" && input.Version < 1) {
		return SaveQueryFilter{}, ErrQueryFilterConflict
	}
	expression, err := NormalizeQueryFilterGroup(&input.Expression)
	if err != nil {
		return SaveQueryFilter{}, err
	}
	input.Expression = *expression
	encoded, err := json.Marshal(input.Expression)
	if err != nil {
		return SaveQueryFilter{}, err
	}
	if len(encoded) > MaxPlanGrammarBytes {
		return SaveQueryFilter{}, ErrQueryFilterStorageBudget
	}
	return input, nil
}

func cloneSavedQueryFilter(input SavedQueryFilter) (SavedQueryFilter, error) {
	input.VersionText = strconv.FormatInt(input.Version, 10)
	normalized, err := NormalizeQueryFilterGroup(&input.Expression)
	if err != nil {
		return SavedQueryFilter{}, err
	}
	input.Expression = *normalized
	encoded, err := json.Marshal(input.Expression)
	if err != nil {
		return SavedQueryFilter{}, err
	}
	if len(encoded) > MaxPlanGrammarBytes {
		return SavedQueryFilter{}, ErrQueryFilterStorageBudget
	}
	return input, nil
}

// GetQueryFilter reads only the selected outer tenant partition and returns
// an owned expression copy; unknown and foreign IDs share one error.
func (s *MemoryQueryFilterStore) GetQueryFilter(ctx context.Context, tenant, id string) (SavedQueryFilter, error) {
	if err := ctx.Err(); err != nil {
		return SavedQueryFilter{}, err
	}
	if strings.TrimSpace(tenant) == "" {
		return SavedQueryFilter{}, errors.New("saved flow filter tenant is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.byTenant[tenant][id]
	if !ok {
		return SavedQueryFilter{}, ErrQueryFilterNotFound
	}
	return cloneSavedQueryFilter(item)
}

// lockedQueryFilterReader is used only under the memory store's mutation lock,
// preventing two simultaneous updates from racing cycle validation.
type lockedQueryFilterReader struct{ store *MemoryQueryFilterStore }

func (r lockedQueryFilterReader) GetQueryFilter(ctx context.Context, tenant, id string) (SavedQueryFilter, error) {
	if err := ctx.Err(); err != nil {
		return SavedQueryFilter{}, err
	}
	item, ok := r.store.byTenant[tenant][id]
	if !ok {
		return SavedQueryFilter{}, ErrQueryFilterNotFound
	}
	return cloneSavedQueryFilter(item)
}

// SaveQueryFilter checks dependencies/cycles atomically with the write.
func (s *MemoryQueryFilterStore) SaveQueryFilter(ctx context.Context, tenant, actor string, input SaveQueryFilter) (SavedQueryFilter, error) {
	if err := ctx.Err(); err != nil {
		return SavedQueryFilter{}, err
	}
	if strings.TrimSpace(tenant) == "" || strings.TrimSpace(actor) == "" {
		return SavedQueryFilter{}, errors.New("saved flow filter requires tenant and actor")
	}
	input, err := NormalizeSaveQueryFilter(input)
	if err != nil {
		return SavedQueryFilter{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := SavedQueryFilter{}
	if input.ID != "" {
		var ok bool
		previous, ok = s.byTenant[tenant][input.ID]
		if !ok {
			return SavedQueryFilter{}, ErrQueryFilterNotFound
		}
		if previous.Version != input.Version || previous.Version == math.MaxInt64 {
			return SavedQueryFilter{}, ErrQueryFilterConflict
		}
	}
	if _, err := ResolveQueryFilters(ctx, tenant, &input.Expression, lockedQueryFilterReader{s}, input.ID); err != nil {
		return SavedQueryFilter{}, err
	}
	now := s.now().UTC()
	id := input.ID
	created := previous.CreatedAt
	if id == "" {
		id, err = crypto.UUIDv4()
		if err != nil {
			return SavedQueryFilter{}, err
		}
		created = now
	}
	item := SavedQueryFilter{ID: id, TenantID: tenant, Name: input.Name, Description: input.Description, Expression: input.Expression, Version: previous.Version + 1, UpdatedBy: actor, CreatedAt: created, UpdatedAt: now}
	encoded, err := json.Marshal(item)
	if err != nil {
		return SavedQueryFilter{}, err
	}
	size := len(encoded)
	for otherID, stored := range s.byTenant[tenant] {
		if otherID == id {
			continue
		}
		body, err := json.Marshal(stored)
		if err != nil {
			return SavedQueryFilter{}, err
		}
		size += len(body)
		if size > s.maxBytesPerTenant {
			return SavedQueryFilter{}, ErrQueryFilterStorageBudget
		}
	}
	if size > s.maxBytesPerTenant {
		return SavedQueryFilter{}, ErrQueryFilterStorageBudget
	}
	if s.byTenant[tenant] == nil {
		s.byTenant[tenant] = map[string]SavedQueryFilter{}
	}
	s.byTenant[tenant][id] = item
	return cloneSavedQueryFilter(item)
}

// ListQueryFilters pages stable IDs within one tenant. The following cursor is
// a configuration position, not an authorization credential or tenant selector.
func (s *MemoryQueryFilterStore) ListQueryFilters(ctx context.Context, tenant, after string, limit int) (QueryFilterPage, error) {
	if err := ctx.Err(); err != nil {
		return QueryFilterPage{}, err
	}
	if tenant == "" {
		return QueryFilterPage{}, errors.New("saved flow filter tenant is required")
	}
	if limit < 1 || limit > 1000 {
		return QueryFilterPage{}, errors.New("saved flow filter page size must be 1-1000")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := []string{}
	for id := range s.byTenant[tenant] {
		if id > after {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	page := QueryFilterPage{Items: []SavedQueryFilter{}}
	bytesUsed := 0
	for _, id := range ids {
		item, err := cloneSavedQueryFilter(s.byTenant[tenant][id])
		if err != nil {
			return QueryFilterPage{}, err
		}
		more, err := appendQueryFilterPage(&page, item, limit, maxQueryFilterPageBytes, &bytesUsed)
		if err != nil {
			return QueryFilterPage{}, err
		}
		if more {
			break
		}
	}
	return page, nil
}

// DeleteQueryFilter cannot erase another tenant's or an unseen newer version.
func (s *MemoryQueryFilterStore) DeleteQueryFilter(ctx context.Context, tenant, actor, id string, version int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(tenant) == "" || strings.TrimSpace(actor) == "" {
		return errors.New("saved flow filter requires tenant and actor")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.byTenant[tenant][id]
	if !ok {
		return ErrQueryFilterNotFound
	}
	if version < 1 || item.Version != version {
		return ErrQueryFilterConflict
	}
	delete(s.byTenant[tenant], id)
	return nil
}

// appendQueryFilterPage bounds serialized response bytes as well as row count.
// It returns true when this item belongs on the next page, without skipping it.
func appendQueryFilterPage(page *QueryFilterPage, item SavedQueryFilter, limit, byteLimit int, used *int) (bool, error) {
	encoded, err := json.Marshal(item)
	if err != nil {
		return false, err
	}
	if len(page.Items) == limit || *used+len(encoded) > byteLimit {
		if len(page.Items) == 0 {
			return false, ErrQueryFilterStorageBudget
		}
		page.Next = page.Items[len(page.Items)-1].ID
		return true, nil
	}
	page.Items = append(page.Items, item)
	*used += len(encoded)
	return false, nil
}
