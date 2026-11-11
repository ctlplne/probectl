// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"encoding/json"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
)

// CounterCaptureInput contains observations, never canonical context/router
// identity or a source grant. The complete original wire digest also covers
// each interface, counter name/value/width, clock presence and source field.
type CounterCaptureInput struct {
	ConfiguredTarget string
	PollStartedAt    time.Time
	PollCompletedAt  time.Time
	PointCount       uint32
}

// CounterCaptureReference is a write receipt, not a reusable reader grant.
// Storage readers must independently authorize the current tenant and source.
type CounterCaptureReference struct {
	Key        [32]byte
	CapturedAt time.Time
}

// CounterCaptureKey binds the independently authenticated peer to the whole
// original counter poll. A raw bus sender may use claims to locate a matching
// witness, but only the issued evidence mTLS path may create that witness.
func CounterCaptureKey(tenant, sender string, rawDigest [32]byte, input CounterCaptureInput) ([32]byte, error) {
	id, err := uuid.Parse(tenant)
	if err != nil || id == uuid.Nil || id.String() != tenant || rawDigest == ([32]byte{}) || input.PointCount == 0 || !utf8.ValidString(sender) || !utf8.ValidString(input.ConfiguredTarget) {
		return [32]byte{}, ErrInvalidClaim
	}
	source := SourceKey{AgentID: sender, Kind: DeviceTarget, SourceRef: input.ConfiguredTarget}
	if normalized, err := source.Normalize(); err != nil || normalized != source {
		return [32]byte{}, ErrInvalidClaim
	}
	started, completed := input.PollStartedAt.UnixNano(), input.PollCompletedAt.UnixNano()
	if started <= 0 || completed < started || !time.Unix(0, started).Equal(input.PollStartedAt) || !time.Unix(0, completed).Equal(input.PollCompletedAt) {
		return [32]byte{}, ErrInvalidClaim
	}
	body, err := json.Marshal(struct {
		Version, Tenant, Sender, Target string
		RawDigest                       [32]byte
		Started, Completed              int64
		Count                           uint32
	}{"device_counter_capture_v1", tenant, sender, input.ConfiguredTarget, rawDigest, started, completed, input.PointCount})
	if err != nil {
		return [32]byte{}, err
	}
	hash := crypto.Hash(body)
	if len(hash) != 32 {
		return [32]byte{}, ErrInvalidClaim
	}
	var key [32]byte
	copy(key[:], hash)
	return key, nil
}
