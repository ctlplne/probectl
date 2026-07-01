// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"log/slog"
	"sync/atomic"
)

const l7ScopeSyncDegradeAfterFailures = uint64(3)

type l7ScopeHealthReporter interface {
	L7ScopeSyncDegraded() bool
}

type l7ScopeSyncMonitor struct {
	cfg          *Config
	log          *slog.Logger
	scopeKind    string
	degradeAfter uint64

	failures    atomic.Uint64
	consecutive atomic.Uint64
	degraded    atomic.Bool
	lastErr     atomic.Value // string
}

func newL7ScopeSyncMonitor(cfg *Config, log *slog.Logger, scopeKind string) *l7ScopeSyncMonitor {
	if log == nil {
		log = slog.Default()
	}
	if scopeKind == "" {
		scopeKind = "unknown"
	}
	return &l7ScopeSyncMonitor{
		cfg:          cfg,
		log:          log,
		scopeKind:    scopeKind,
		degradeAfter: l7ScopeSyncDegradeAfterFailures,
	}
}

func (m *l7ScopeSyncMonitor) Refresh(syncScope func() error) bool {
	if m == nil {
		return syncScope() == nil
	}
	if err := syncScope(); err != nil {
		m.recordFailure(err)
		return false
	}
	m.recordSuccess()
	return true
}

func (m *l7ScopeSyncMonitor) recordFailure(err error) {
	if m == nil || err == nil {
		return
	}
	total := m.failures.Add(1)
	consecutive := m.consecutive.Add(1)
	m.lastErr.Store(err.Error())
	if consecutive >= m.degradeAfter {
		m.degraded.Store(true)
	}
	tenantID, host := "", ""
	if m.cfg != nil {
		tenantID = m.cfg.TenantID
		host = m.cfg.Host
	}
	m.log.Warn("ebpf L7 scope refresh failed",
		"tenant_id", tenantID,
		"host", host,
		"scope_kind", m.scopeKind,
		"error", err,
		"l7_scope_sync_failures_total", total,
		"consecutive_failures", consecutive,
		"degraded", m.degraded.Load())
}

func (m *l7ScopeSyncMonitor) recordSuccess() {
	if m == nil {
		return
	}
	m.consecutive.Store(0)
	m.degraded.Store(false)
}

func (m *l7ScopeSyncMonitor) Failures() uint64 {
	if m == nil {
		return 0
	}
	return m.failures.Load()
}

func (m *l7ScopeSyncMonitor) Degraded() bool {
	if m == nil {
		return false
	}
	return m.degraded.Load()
}

func (m *l7ScopeSyncMonitor) LastError() string {
	if m == nil {
		return ""
	}
	if v := m.lastErr.Load(); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
