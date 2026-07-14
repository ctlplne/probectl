// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package objectstore

import (
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
func (m *MemStore) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var keys []string
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
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
