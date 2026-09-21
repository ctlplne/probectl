// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package objectstore

import (
	"errors"
	"sort"
	"strings"

	"context"
	"sync"
)

// MemStore is an in-memory Store for tests and the lightweight/dev mode.
type MemStore struct {
	mu      sync.RWMutex
	objects map[string]Object
}

// NewMemory returns an empty in-memory store.
func NewMemory() *MemStore {
	return &MemStore{objects: make(map[string]Object)}
}

func (m *MemStore) Put(_ context.Context, key, contentType string, data []byte) error {
	if err := validKey(key); err != nil {
		return err
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key] = Object{Data: cp, ContentType: contentType, Size: int64(len(cp))}
	return nil
}

func (m *MemStore) Get(_ context.Context, key string) (Object, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	o, ok := m.objects[key]
	if !ok {
		return Object{}, ErrNotFound
	}
	cp := make([]byte, len(o.Data))
	copy(cp, o.Data)
	return Object{Data: cp, ContentType: o.ContentType, Size: o.Size}, nil
}

func (m *MemStore) GetLimited(_ context.Context, key string, maxBytes int64) (Object, error) {
	if maxBytes < 0 {
		return Object{}, errors.New("objectstore: maxBytes must be non-negative")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	o, ok := m.objects[key]
	if !ok {
		return Object{}, ErrNotFound
	}
	if int64(len(o.Data)) > maxBytes {
		return Object{}, ErrTooLarge
	}
	cp := make([]byte, len(o.Data))
	copy(cp, o.Data)
	return Object{Data: cp, ContentType: o.ContentType, Size: o.Size}, nil
}

func (m *MemStore) Stat(_ context.Context, key string) (int64, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	o, ok := m.objects[key]
	if !ok {
		return 0, false, nil
	}
	return o.Size, true, nil
}

// List returns the keys under prefix, sorted.
func (m *MemStore) List(ctx context.Context, prefix string) ([]string, error) {
	return m.list(ctx, prefix, -1)
}

// ListLimited returns a context-aware, aggregate-bounded prefix listing.
func (m *MemStore) ListLimited(ctx context.Context, prefix string, maxKeys int) ([]string, error) {
	if maxKeys < 0 {
		return nil, errors.New("objectstore: maxKeys must be non-negative")
	}
	return m.list(ctx, prefix, maxKeys)
}

func (m *MemStore) list(ctx context.Context, prefix string, maxKeys int) ([]string, error) {
	if err := validListPrefix(prefix); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var keys []string
	for k := range m.objects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if strings.HasPrefix(k, prefix) {
			if maxKeys >= 0 && len(keys) >= maxKeys {
				return nil, ErrTooMany
			}
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// DeletePrefix removes every object under prefix (S-T5 verifiable deletion).
func (m *MemStore) DeletePrefix(_ context.Context, prefix string) (int, error) {
	if prefix == "" {
		return 0, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			delete(m.objects, k)
			n++
		}
	}
	return n, nil
}

// Len reports the number of stored objects (test inspection).
func (m *MemStore) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.objects)
}
