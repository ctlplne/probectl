// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"encoding/hex"
	"net/netip"
	"sort"
	"time"

	"github.com/google/uuid"
)

// ICMPMeasurement is optional, untrusted collector metadata on existing
// sender-bound evidence. Neither a digest nor these counts grants tenant,
// agent, current-test, context, canonical identity or notification authority.
type ICMPMeasurement struct {
	Version        int                `json:"version"`
	DefinitionHash string             `json:"definition_hash"`
	StartedAt      time.Time          `json:"started_at"`
	CompletedAt    time.Time          `json:"completed_at"`
	Requested      uint32             `json:"requested"`
	Attempted      uint32             `json:"attempted"`
	Transmitted    uint32             `json:"transmitted"`
	Replies        uint32             `json:"replies"`
	SendErrors     uint32             `json:"send_errors"`
	ReadComplete   bool               `json:"read_complete"`
	Canceled       bool               `json:"canceled"`
	IOFailed       bool               `json:"io_failed"`
	Responders     []string           `json:"responders"`
	NetworkErrors  []ICMPNetworkError `json:"network_errors,omitempty"`
	RoundTrips     *ICMPRoundTrips    `json:"round_trips,omitempty"`
}

// Present empty samples attest zero replies. Absence on older receipt versions
// is unknown latency; timestamps or ordinary bus metrics never fill it in.
type ICMPRoundTrips struct {
	Nanos          []uint64 `json:"nanos"`
	ExecutionNanos uint64   `json:"execution_nanos"`
}

func normalizeICMPMeasurement(o Observation) (*ICMPMeasurement, error) {
	if o.ICMP == nil {
		return nil, nil
	}
	id, err := uuid.Parse(o.Source.SourceRef)
	if err != nil || id == uuid.Nil || id.String() != o.Source.SourceRef ||
		o.Source.Kind != PathAgent || o.Alias.Kind != AddressAlias || o.SourceRef != "icmp:configured-test" {
		return nil, ErrInvalidClaim
	}
	m := *o.ICMP
	if len(m.DefinitionHash) != 64 {
		return nil, ErrInvalidClaim
	}
	digest, err := hex.DecodeString(m.DefinitionHash)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != m.DefinitionHash || (m.Version != 1 && m.Version != 2 && m.Version != 3) ||
		m.Requested == 0 || m.Attempted > m.Requested || m.Transmitted > m.Attempted ||
		m.Replies > m.Transmitted || m.SendErrors != m.Attempted-m.Transmitted {
		return nil, ErrInvalidClaim
	}
	if m.StartedAt.IsZero() || m.CompletedAt.IsZero() || m.CompletedAt.Before(m.StartedAt) ||
		!m.CompletedAt.UTC().Truncate(time.Microsecond).Equal(o.ObservedAt.UTC().Truncate(time.Microsecond)) ||
		uint64(len(m.Responders)) > uint64(m.Replies) || m.Replies > 0 && len(m.Responders) == 0 && !m.IOFailed {
		return nil, ErrInvalidClaim
	}
	if m.Version == 3 {
		// Keep original execution clocks inside the receipt; only the indexed
		// observation header is quantized to PostgreSQL's microseconds.
		m.StartedAt = m.StartedAt.UTC()
		m.CompletedAt = m.CompletedAt.UTC()
	} else {
		m.StartedAt = m.StartedAt.UTC().Truncate(time.Microsecond)
		m.CompletedAt = m.CompletedAt.UTC().Truncate(time.Microsecond)
	}
	m.Responders = append([]string{}, m.Responders...)
	target, err := netip.ParseAddr(o.Alias.Value)
	if err != nil {
		return nil, ErrInvalidClaim
	}
	seen := make(map[string]bool, len(m.Responders))
	for i, value := range m.Responders {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address.Unmap().Is4() != target.Unmap().Is4() {
			return nil, ErrInvalidClaim
		}
		value = address.Unmap().String()
		if seen[value] {
			return nil, ErrInvalidClaim
		}
		seen[value], m.Responders[i] = true, value
	}
	sort.Strings(m.Responders)
	if m.Version == 3 {
		if m.RoundTrips == nil || m.RoundTrips.Nanos == nil || uint64(len(m.RoundTrips.Nanos)) != uint64(m.Replies) {
			return nil, ErrInvalidClaim
		}
		// RTTs and execution duration share the collector's monotonic clock;
		// wall-clock adjustments cannot shorten an authentic elapsed interval.
		if m.RoundTrips.ExecutionNanos > uint64(1<<63-1) {
			return nil, ErrInvalidClaim
		}
		maximum := m.RoundTrips.ExecutionNanos
		for _, value := range m.RoundTrips.Nanos {
			if value > uint64(1<<63-1) || value > maximum {
				return nil, ErrInvalidClaim
			}
		}
		// Copy original nanoseconds; no floating point conversion or inferred
		// sample is introduced by normalization or later historical readers.
		m.RoundTrips = &ICMPRoundTrips{Nanos: append([]uint64{}, m.RoundTrips.Nanos...), ExecutionNanos: m.RoundTrips.ExecutionNanos}
	} else if m.RoundTrips != nil {
		return nil, ErrInvalidClaim
	}
	m.NetworkErrors, err = normalizeICMPNetworkErrors(m, target)
	if err != nil {
		return nil, err
	}
	return &m, nil
}
