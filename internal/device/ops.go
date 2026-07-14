// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package device

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

const defaultOpsLimit = 100

// SyslogEvent is one authenticated, tenant-scoped device syslog line.
type SyslogEvent struct {
	ID            string            `json:"id"`
	TenantID      string            `json:"tenant_id"`
	Device        string            `json:"device"`
	SourceAddress string            `json:"source_address,omitempty"`
	Facility      int               `json:"facility,omitempty"`
	Severity      int               `json:"severity"`
	SeverityText  string            `json:"severity_text"`
	Hostname      string            `json:"hostname,omitempty"`
	AppName       string            `json:"app_name,omitempty"`
	Message       string            `json:"message"`
	Raw           string            `json:"raw,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	ObservedAt    time.Time         `json:"observed_at"`
}

// ConfigVersion is a redacted, tenant-scoped network-device config snapshot.
type ConfigVersion struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Device       string    `json:"device"`
	Source       string    `json:"source,omitempty"`
	Version      int       `json:"version"`
	Content      string    `json:"content,omitempty"`
	ContentHash  string    `json:"content_hash"`
	PreviousHash string    `json:"previous_hash,omitempty"`
	Drifted      bool      `json:"drifted"`
	ObservedAt   time.Time `json:"observed_at"`
	ArchivedAt   time.Time `json:"archived_at"`
}

// OpsStore stores device-management table-stakes rows behind a tenant-first API.
type OpsStore interface {
	RecordSyslog(context.Context, SyslogEvent) (SyslogEvent, error)
	ListSyslog(context.Context, string, OpsFilter) ([]SyslogEvent, error)
	ArchiveConfig(context.Context, ConfigVersion) (ConfigVersion, error)
	ListConfigs(context.Context, string, OpsFilter) ([]ConfigVersion, error)
}

// OpsFilter bounds tenant-scoped reads.
type OpsFilter struct {
	Device string
	Limit  int
}

// MemoryOpsStore is a tenant-keyed store for lightweight deployments and tests.
type MemoryOpsStore struct {
	mu      sync.RWMutex
	syslog  map[string][]SyslogEvent
	configs map[string][]ConfigVersion
	next    uint64
	now     func() time.Time
}

func NewMemoryOpsStore() *MemoryOpsStore {
	return &MemoryOpsStore{
		syslog:  map[string][]SyslogEvent{},
		configs: map[string][]ConfigVersion{},
		now:     time.Now,
	}
}

func (m *MemoryOpsStore) RecordSyslog(_ context.Context, ev SyslogEvent) (SyslogEvent, error) {
	if ev.TenantID == "" {
		return SyslogEvent{}, errors.New("device ops: tenant_id is required")
	}
	if strings.TrimSpace(ev.Device) == "" {
		return SyslogEvent{}, errors.New("device ops: device is required")
	}
	if strings.TrimSpace(ev.Message) == "" {
		return SyslogEvent{}, errors.New("device ops: message is required")
	}
	if ev.ObservedAt.IsZero() {
		ev.ObservedAt = m.now()
	}
	ev.ObservedAt = ev.ObservedAt.UTC()
	if ev.SeverityText == "" {
		ev.SeverityText = SyslogSeverityText(ev.Severity)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	ev.ID = fmt.Sprintf("syslog-%d", m.next)
	m.syslog[ev.TenantID] = append(m.syslog[ev.TenantID], ev)
	return ev, nil
}

func (m *MemoryOpsStore) ListSyslog(_ context.Context, tenant string, f OpsFilter) ([]SyslogEvent, error) {
	if tenant == "" {
		return nil, errors.New("device ops: tenant_id is required")
	}
	limit := normalizeOpsLimit(f.Limit)
	m.mu.RLock()
	rows := append([]SyslogEvent(nil), m.syslog[tenant]...)
	m.mu.RUnlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].ObservedAt.After(rows[j].ObservedAt) })
	out := make([]SyslogEvent, 0, min(limit, len(rows)))
	for _, row := range rows {
		if f.Device != "" && row.Device != f.Device {
			continue
		}
		out = append(out, row)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *MemoryOpsStore) ArchiveConfig(_ context.Context, cfg ConfigVersion) (ConfigVersion, error) {
	if cfg.TenantID == "" {
		return ConfigVersion{}, errors.New("device ops: tenant_id is required")
	}
	if strings.TrimSpace(cfg.Device) == "" {
		return ConfigVersion{}, errors.New("device ops: device is required")
	}
	cfg.Device = strings.TrimSpace(cfg.Device)
	cfg.Content = RedactConfig(cfg.Content)
	cfg.ContentHash = hashConfig(cfg.Content)
	if cfg.ObservedAt.IsZero() {
		cfg.ObservedAt = m.now()
	}
	cfg.ObservedAt = cfg.ObservedAt.UTC()
	cfg.ArchivedAt = m.now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	var previous *ConfigVersion
	for i := len(m.configs[cfg.TenantID]) - 1; i >= 0; i-- {
		row := m.configs[cfg.TenantID][i]
		if row.Device == cfg.Device {
			previous = &row
			break
		}
	}
	if previous != nil {
		cfg.PreviousHash = previous.ContentHash
		cfg.Version = previous.Version + 1
		cfg.Drifted = previous.ContentHash != cfg.ContentHash
	} else {
		cfg.Version = 1
	}
	m.next++
	cfg.ID = fmt.Sprintf("config-%d", m.next)
	m.configs[cfg.TenantID] = append(m.configs[cfg.TenantID], cfg)
	return cfg, nil
}

func (m *MemoryOpsStore) ListConfigs(_ context.Context, tenant string, f OpsFilter) ([]ConfigVersion, error) {
	if tenant == "" {
		return nil, errors.New("device ops: tenant_id is required")
	}
	limit := normalizeOpsLimit(f.Limit)
	m.mu.RLock()
	rows := append([]ConfigVersion(nil), m.configs[tenant]...)
	m.mu.RUnlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].ArchivedAt.After(rows[j].ArchivedAt) })
	out := make([]ConfigVersion, 0, min(limit, len(rows)))
	for _, row := range rows {
		if f.Device != "" && row.Device != f.Device {
			continue
		}
		out = append(out, row)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// ParseSyslogLine normalizes common RFC3164/RFC5424-ish syslog lines. It is
// intentionally conservative: authentication and tenant binding happen outside
// the parser, and unparsable prefixes still preserve the message body.
func ParseSyslogLine(raw, fallbackDevice string, observedAt time.Time) SyslogEvent {
	msg := strings.TrimSpace(raw)
	ev := SyslogEvent{Raw: msg, Message: msg, Device: strings.TrimSpace(fallbackDevice), ObservedAt: observedAt.UTC()}
	if pri, rest, ok := parsePriority(msg); ok {
		ev.Facility = pri / 8
		ev.Severity = pri % 8
		ev.SeverityText = SyslogSeverityText(ev.Severity)
		msg = strings.TrimSpace(rest)
		ev.Message = msg
	}
	fields := strings.Fields(msg)
	if len(fields) >= 4 && looksRFC3164Timestamp(fields[:3]) {
		ev.Hostname = fields[3]
		ev.Message = strings.TrimSpace(strings.TrimPrefix(msg, strings.Join(fields[:4], " ")))
	} else if len(fields) >= 3 && strings.Contains(fields[0], "T") {
		ev.Hostname = fields[1]
		ev.AppName = strings.TrimSuffix(fields[2], ":")
		ev.Message = strings.TrimSpace(strings.TrimPrefix(msg, strings.Join(fields[:3], " ")))
	}
	if ev.Device == "" {
		ev.Device = ev.Hostname
	}
	if ev.Device == "" {
		ev.Device = "unknown"
	}
	if ev.SeverityText == "" {
		ev.SeverityText = SyslogSeverityText(ev.Severity)
	}
	return ev
}

func parsePriority(s string) (int, string, bool) {
	if !strings.HasPrefix(s, "<") {
		return 0, s, false
	}
	end := strings.IndexByte(s, '>')
	if end < 2 || end > 5 {
		return 0, s, false
	}
	pri, err := strconv.Atoi(s[1:end])
	if err != nil || pri < 0 || pri > 191 {
		return 0, s, false
	}
	return pri, s[end+1:], true
}

func looksRFC3164Timestamp(fields []string) bool {
	if len(fields) != 3 {
		return false
	}
	if len(fields[0]) != 3 || !strings.Contains(fields[2], ":") {
		return false
	}
	_, err := strconv.Atoi(fields[1])
	return err == nil
}

func SyslogSeverityText(sev int) string {
	switch sev {
	case 0:
		return "emergency"
	case 1:
		return "alert"
	case 2:
		return "critical"
	case 3:
		return "error"
	case 4:
		return "warning"
	case 5:
		return "notice"
	case 6:
		return "info"
	default:
		return "debug"
	}
}

var sensitiveConfigLine = regexp.MustCompile(`(?i)\b(password|secret|community|private-key|api[_-]?key|token)\b`)

func RedactConfig(content string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if sensitiveConfigLine.MatchString(line) {
			prefix := strings.TrimRight(line[:len(line)-len(strings.TrimLeft(line, " \t"))], " \t")
			key := strings.Fields(strings.TrimSpace(line))
			if len(key) > 0 {
				lines[i] = prefix + key[0] + " [redacted]"
			} else {
				lines[i] = prefix + "[redacted]"
			}
		}
	}
	return strings.Join(lines, "\n")
}

func hashConfig(content string) string {
	return hex.EncodeToString(crypto.Hash([]byte(content)))
}

func normalizeOpsLimit(limit int) int {
	if limit <= 0 {
		return defaultOpsLimit
	}
	if limit > defaultMaxTrapRowsTenant {
		return defaultMaxTrapRowsTenant
	}
	return limit
}
