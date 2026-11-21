// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

const (
	bmpInitiation  = 4
	bmpTermination = 5
)

var (
	ErrBMPConnectionEvent  = errors.New("bgp: invalid BMP connection event")
	ErrBMPConnectionBudget = errors.New("bgp: BMP connection event admission exceeded")
)

// BMPConnectionEvent describes an authenticated transport's reported
// initiation or termination. Identity and observation time come from the
// listener. Router-provided text is validated at intake and is not retained.
type BMPConnectionEvent struct {
	Terminated  bool   `json:"terminated"`
	Reason      uint16 `json:"reason"`
	ReasonKnown bool   `json:"reason_known"`
}

// ParseBMPConnectionEvent reads a complete Initiation or Termination frame.
// These message types have no per-peer header.
func ParseBMPConnectionEvent(ctx context.Context, frame []byte, budget PeerMessageBudget) (BMPConnectionEvent, error) {
	none := BMPConnectionEvent{}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || int64(len(frame)) > budget.MemoryBytes || int64(len(frame)) > budget.WorkUnits/4 {
		return none, ErrBMPConnectionBudget
	}
	if len(frame) < bmpCommonHeaderLen+4 || len(frame) > bmpMaxMessageBytes ||
		frame[0] != bmpVersion || binary.BigEndian.Uint32(frame[1:5]) != uint32(len(frame)) {
		return none, ErrBMPConnectionEvent
	}
	payload := frame[bmpCommonHeaderLen:]
	switch frame[5] {
	case bmpInitiation:
		return none, validateBMPInitiation(ctx, payload)
	case bmpTermination:
		return parseBMPTermination(ctx, payload)
	default:
		return none, ErrBMPConnectionEvent
	}
}

func validateBMPInitiation(ctx context.Context, raw []byte) error {
	var found [3]bool
	err := walkBMPInformation(ctx, raw, func(kind uint16, data []byte) error {
		if kind == 0 && !utf8.Valid(data) {
			return ErrBMPConnectionEvent
		}
		if kind != 1 && kind != 2 {
			return nil
		}
		if found[kind] {
			return ErrBMPConnectionEvent
		}
		for _, value := range data {
			if value >= utf8.RuneSelf {
				return ErrBMPConnectionEvent
			}
		}
		found[kind] = true
		return nil
	})
	if err != nil {
		return err
	}
	if !found[1] || !found[2] {
		return ErrBMPConnectionEvent
	}
	return nil
}

func parseBMPTermination(ctx context.Context, raw []byte) (BMPConnectionEvent, error) {
	result := BMPConnectionEvent{Terminated: true}
	seenReason := false
	err := walkBMPInformation(ctx, raw, func(kind uint16, data []byte) error {
		switch kind {
		case 0:
			if !utf8.Valid(data) {
				return ErrBMPConnectionEvent
			}
		case 1:
			if seenReason || len(data) != 2 {
				return ErrBMPConnectionEvent
			}
			seenReason = true
			result.Reason = binary.BigEndian.Uint16(data)
			result.ReasonKnown = result.Reason <= 4
		}
		return nil
	})
	if err != nil {
		return BMPConnectionEvent{}, err
	}
	if !seenReason {
		return BMPConnectionEvent{}, ErrBMPConnectionEvent
	}
	return result, nil
}

func walkBMPInformation(ctx context.Context, raw []byte, take func(uint16, []byte) error) error {
	for len(raw) != 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(raw) < 4 {
			return ErrBMPConnectionEvent
		}
		kind, length := binary.BigEndian.Uint16(raw[:2]), int(binary.BigEndian.Uint16(raw[2:4]))
		raw = raw[4:]
		if length > len(raw) {
			return ErrBMPConnectionEvent
		}
		if err := take(kind, raw[:length]); err != nil {
			return err
		}
		raw = raw[length:]
	}
	return ctx.Err()
}
