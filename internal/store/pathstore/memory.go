package pathstore

import (
	"context"
	"sync"

	"github.com/imfeelingtheagi/netctl/internal/path"
)

// Memory is an in-process Store that retains saved paths for query (lightweight
// mode and tests).
type Memory struct {
	mu    sync.Mutex
	saved map[string][]*path.Path // tenant_id -> paths
}

// NewMemory returns an in-memory path store.
func NewMemory() *Memory { return &Memory{saved: map[string][]*path.Path{}} }

// Save retains a copy of the path under its tenant.
func (m *Memory) Save(_ context.Context, tenantID string, p *path.Path) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saved[tenantID] = append(m.saved[tenantID], p)
	return nil
}

// Close is a no-op.
func (m *Memory) Close() error { return nil }

// ForTenant returns the paths saved for a tenant (test/lightweight query).
func (m *Memory) ForTenant(tenantID string) []*path.Path {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*path.Path, len(m.saved[tenantID]))
	copy(out, m.saved[tenantID])
	return out
}
