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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/crypto"
	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
)

const (
	NeighborProtocolLLDP = "lldp"
	NeighborProtocolCDP  = "cdp"

	// MaxNeighborsPerDevice is both the untrusted-SNMP parse cap and the
	// storage replacement cap. A device cannot inflate one poll without bound.
	MaxNeighborsPerDevice  = 256
	MaxNeighborsPerTenant  = 16_384
	MaxNeighborRead        = 500
	NeighborStaleRetention = 24 * time.Hour
)

// NeighborEvidence is one directly observed, read-only physical adjacency.
// It contains no credential material and performs no inference or mutation.
type NeighborEvidence struct {
	TenantID string `json:"-"`
	AgentID  string `json:"agent_id"`

	LocalDeviceAddress string `json:"local_device_address"`
	LocalDeviceName    string `json:"local_device_name,omitempty"`
	LocalIfIndex       uint32 `json:"local_if_index,omitempty"`
	LocalPortID        string `json:"local_port_id"`

	RemoteChassisID         string   `json:"remote_chassis_id,omitempty"`
	RemoteDeviceName        string   `json:"remote_device_name,omitempty"`
	RemotePortID            string   `json:"remote_port_id"`
	RemoteManagementAddress string   `json:"remote_management_address,omitempty"`
	RemotePlatform          string   `json:"remote_platform,omitempty"`
	Capabilities            []string `json:"capabilities,omitempty"`

	Protocol   string    `json:"protocol"`
	Confidence float64   `json:"confidence"`
	ObservedAt time.Time `json:"observed_at"`
	FreshUntil time.Time `json:"fresh_until"`

	ID         string `json:"id,omitempty"`
	Freshness  string `json:"freshness,omitempty"`
	AgeSeconds int64  `json:"age_seconds,omitempty"`
}

// NeighborSnapshot atomically replaces the latest evidence for one configured
// (tenant, agent, device) source.
type NeighborSnapshot struct {
	TenantID      string
	AgentID       string
	DeviceAddress string
	DeviceName    string
	ObservedAt    time.Time
	Neighbors     []NeighborEvidence
}

// NeighborFilter bounds tenant-scoped evidence reads.
type NeighborFilter struct {
	Device   string
	Protocol string
	Limit    int
}

// NeighborStore is the tenant-first current-evidence persistence seam.
type NeighborStore interface {
	ReplaceSnapshot(context.Context, string, NeighborSnapshot) error
	ListNeighbors(context.Context, string, NeighborFilter) ([]NeighborEvidence, bool, error)
}

// EvidenceID returns a bounded opaque identifier without exposing raw ports or
// chassis identifiers in URL-safe row identity.
func (n NeighborEvidence) EvidenceID() string {
	payload := strings.Join([]string{
		n.AgentID, n.LocalDeviceAddress, strconv.FormatUint(uint64(n.LocalIfIndex), 10),
		n.LocalPortID, n.Protocol, n.RemoteChassisID, n.RemoteDeviceName, n.RemotePortID,
	}, "\x00")
	return "neighbor:" + hex.EncodeToString(crypto.Hash([]byte(payload)))[:24]
}

func (n NeighborEvidence) ToProto() *devicev1.DeviceNeighborEvidence {
	return &devicev1.DeviceNeighborEvidence{
		TenantId:                n.TenantID,
		AgentId:                 n.AgentID,
		LocalDeviceAddress:      n.LocalDeviceAddress,
		LocalDeviceName:         n.LocalDeviceName,
		LocalIfIndex:            n.LocalIfIndex,
		LocalPortId:             n.LocalPortID,
		RemoteChassisId:         n.RemoteChassisID,
		RemoteDeviceName:        n.RemoteDeviceName,
		RemotePortId:            n.RemotePortID,
		RemoteManagementAddress: n.RemoteManagementAddress,
		RemotePlatform:          n.RemotePlatform,
		Capabilities:            append([]string(nil), n.Capabilities...),
		Protocol:                n.Protocol,
		Confidence:              n.Confidence,
		ObservedAtUnixNano:      n.ObservedAt.UnixNano(),
		FreshUntilUnixNano:      n.FreshUntil.UnixNano(),
	}
}

func NeighborEvidenceFromProto(n *devicev1.DeviceNeighborEvidence) NeighborEvidence {
	if n == nil {
		return NeighborEvidence{}
	}
	return NeighborEvidence{
		TenantID: n.GetTenantId(), AgentID: n.GetAgentId(),
		LocalDeviceAddress: n.GetLocalDeviceAddress(), LocalDeviceName: n.GetLocalDeviceName(),
		LocalIfIndex: n.GetLocalIfIndex(), LocalPortID: n.GetLocalPortId(),
		RemoteChassisID: n.GetRemoteChassisId(), RemoteDeviceName: n.GetRemoteDeviceName(),
		RemotePortID: n.GetRemotePortId(), RemoteManagementAddress: n.GetRemoteManagementAddress(),
		RemotePlatform: n.GetRemotePlatform(), Capabilities: append([]string(nil), n.GetCapabilities()...),
		Protocol: n.GetProtocol(), Confidence: n.GetConfidence(),
		ObservedAt: time.Unix(0, n.GetObservedAtUnixNano()).UTC(),
		FreshUntil: time.Unix(0, n.GetFreshUntilUnixNano()).UTC(),
	}
}

// ValidateNeighborSnapshot applies the same bounds at the producer and
// consumer edges. SNMP strings are attacker-controlled, so values are trimmed
// and normalized before they become storage keys or topology labels.
func ValidateNeighborSnapshot(s NeighborSnapshot) (NeighborSnapshot, error) {
	s.TenantID = boundedText(s.TenantID, 128)
	s.AgentID = boundedText(s.AgentID, 128)
	s.DeviceAddress = boundedText(s.DeviceAddress, 255)
	s.DeviceName = boundedText(s.DeviceName, 255)
	if s.TenantID == "" || s.AgentID == "" || s.DeviceAddress == "" {
		return NeighborSnapshot{}, errors.New("device neighbors: tenant_id, agent_id, and device address are required")
	}
	if s.ObservedAt.IsZero() {
		return NeighborSnapshot{}, errors.New("device neighbors: observed_at is required")
	}
	s.ObservedAt = s.ObservedAt.UTC()
	if len(s.Neighbors) > MaxNeighborsPerDevice {
		s.Neighbors = s.Neighbors[:MaxNeighborsPerDevice]
	}
	out := s.Neighbors[:0]
	seen := map[string]struct{}{}
	for _, n := range s.Neighbors {
		n.TenantID, n.AgentID = s.TenantID, s.AgentID
		n.LocalDeviceAddress, n.LocalDeviceName = s.DeviceAddress, s.DeviceName
		n.LocalPortID = boundedText(n.LocalPortID, 128)
		n.RemoteChassisID = boundedText(n.RemoteChassisID, 256)
		n.RemoteDeviceName = boundedText(n.RemoteDeviceName, 255)
		n.RemotePortID = boundedText(n.RemotePortID, 128)
		n.RemoteManagementAddress = boundedText(n.RemoteManagementAddress, 255)
		n.RemotePlatform = boundedText(n.RemotePlatform, 255)
		n.Capabilities = boundedStrings(n.Capabilities, 32, 64)
		n.Protocol = strings.ToLower(boundedText(n.Protocol, 8))
		if n.Protocol != NeighborProtocolLLDP && n.Protocol != NeighborProtocolCDP {
			continue
		}
		if n.LocalPortID == "" || n.RemotePortID == "" ||
			(n.RemoteChassisID == "" && n.RemoteDeviceName == "") {
			continue
		}
		if n.Confidence < 0 {
			n.Confidence = 0
		}
		if n.Confidence > 1 {
			n.Confidence = 1
		}
		n.ObservedAt = s.ObservedAt
		if n.FreshUntil.IsZero() || !n.FreshUntil.After(n.ObservedAt) {
			n.FreshUntil = n.ObservedAt.Add(2 * time.Minute)
		}
		if n.FreshUntil.After(n.ObservedAt.Add(time.Hour)) {
			n.FreshUntil = n.ObservedAt.Add(time.Hour)
		}
		n.FreshUntil = n.FreshUntil.UTC()
		key := n.EvidenceID()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		n.ID = key
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EvidenceID() < out[j].EvidenceID() })
	s.Neighbors = out
	return s, nil
}

func boundedText(value string, maxRunes int) string {
	value = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value))
	if utf8.RuneCountInString(value) <= maxRunes {
		return value
	}
	runes := []rune(value)
	return string(runes[:maxRunes])
}

func boundedStrings(values []string, maxItems, maxLen int) []string {
	out := make([]string, 0, min(len(values), maxItems))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = boundedText(value, maxLen)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
		if len(out) == maxItems {
			break
		}
	}
	sort.Strings(out)
	return out
}

// MemoryNeighborStore is a bounded tenant-keyed implementation for tests and
// lightweight control-plane profiles.
type MemoryNeighborStore struct {
	mu   sync.RWMutex
	rows map[string]map[string][]NeighborEvidence
}

func NewMemoryNeighborStore() *MemoryNeighborStore {
	return &MemoryNeighborStore{rows: map[string]map[string][]NeighborEvidence{}}
}

func (m *MemoryNeighborStore) ReplaceSnapshot(_ context.Context, tenant string, snapshot NeighborSnapshot) error {
	if tenant == "" || snapshot.TenantID != tenant {
		return errors.New("device neighbors: tenant scope mismatch")
	}
	valid, err := ValidateNeighborSnapshot(snapshot)
	if err != nil {
		return err
	}
	key := valid.AgentID + "\x00" + valid.DeviceAddress
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rows[tenant] == nil {
		m.rows[tenant] = map[string][]NeighborEvidence{}
	}
	m.rows[tenant][key] = append([]NeighborEvidence(nil), valid.Neighbors...)
	cutoff := valid.ObservedAt.Add(-NeighborStaleRetention)
	all := make([]NeighborEvidence, 0)
	for _, sourceRows := range m.rows[tenant] {
		for _, row := range sourceRows {
			if !row.ObservedAt.Before(cutoff) {
				all = append(all, row)
			}
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].ObservedAt.Equal(all[j].ObservedAt) {
			return all[i].ObservedAt.After(all[j].ObservedAt)
		}
		return all[i].EvidenceID() < all[j].EvidenceID()
	})
	if len(all) > MaxNeighborsPerTenant {
		all = all[:MaxNeighborsPerTenant]
	}
	rebuilt := make(map[string][]NeighborEvidence)
	for _, row := range all {
		source := row.AgentID + "\x00" + row.LocalDeviceAddress
		rebuilt[source] = append(rebuilt[source], row)
	}
	m.rows[tenant] = rebuilt
	return nil
}

func (m *MemoryNeighborStore) ListNeighbors(_ context.Context, tenant string, filter NeighborFilter) ([]NeighborEvidence, bool, error) {
	if tenant == "" {
		return nil, false, errors.New("device neighbors: tenant_id is required")
	}
	filter.Device = strings.TrimSpace(filter.Device)
	filter.Protocol = strings.ToLower(strings.TrimSpace(filter.Protocol))
	if filter.Protocol != "" && filter.Protocol != NeighborProtocolLLDP &&
		filter.Protocol != NeighborProtocolCDP {
		return nil, false, errors.New("device neighbors: protocol must be lldp or cdp")
	}
	limit := filter.Limit
	if limit < 1 {
		limit = 100
	}
	if limit > MaxNeighborRead {
		limit = MaxNeighborRead
	}
	m.mu.RLock()
	var rows []NeighborEvidence
	cutoff := time.Now().Add(-NeighborStaleRetention)
	for _, bySource := range m.rows[tenant] {
		for _, row := range bySource {
			if row.ObservedAt.Before(cutoff) {
				continue
			}
			if filter.Device != "" && row.LocalDeviceAddress != filter.Device {
				continue
			}
			if filter.Protocol != "" && row.Protocol != filter.Protocol {
				continue
			}
			rows = append(rows, row)
		}
	}
	m.mu.RUnlock()
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].ObservedAt.Equal(rows[j].ObservedAt) {
			return rows[i].ObservedAt.After(rows[j].ObservedAt)
		}
		return rows[i].EvidenceID() < rows[j].EvidenceID()
	})
	truncated := len(rows) > limit
	if truncated {
		rows = rows[:limit]
	}
	return rows, truncated, nil
}
