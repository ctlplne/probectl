// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package dnstap reduces complete resolver captures to bounded interval
// counters without retaining DNS names, addresses or message payloads.
package dnstap

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/miekg/dns"
)

const (
	MaximumCaptureBytes     = 128 << 20
	MaximumCaptureFrames    = 1 << 20
	MaximumCaptureIntervals = 120
	ResolverInterval        = time.Minute
)

var (
	ErrCaptureLimit  = errors.New("dnstap: closed capture exceeds its finite budget")
	ErrCaptureWindow = errors.New("dnstap: response falls outside the declared closed capture interval")
)

// ResolverIntervalCounts describe received client responses, with no names,
// addresses, DNS IDs, or wire data. They are lower bounds on resolver traffic.
// A valid Frame Streams STOP proves a file was closed. It has no drop counter.
type ResolverIntervalCounts struct {
	From          time.Time `json:"from"`
	To            time.Time `json:"to"`
	Responses     uint32    `json:"client_responses"`
	NameErrors    uint32    `json:"name_errors"`
	ServerFailure uint32    `json:"server_failures"`
	Truncated     uint32    `json:"truncated"`
}

type ClosedCapture struct {
	Frames    uint32
	Selected  uint32
	Outside   uint32
	Intervals []ResolverIntervalCounts
}

// ReduceClosedCapture reads a stopped local file into fixed UTC windows. The
// supplied times bound admission and are never evidence of total traffic.
// A parse failure or canceled read returns no publishable partial counters.
func ReduceClosedCapture(ctx context.Context, reader io.Reader, from, to time.Time) (ClosedCapture, error) {
	if reader == nil || from.IsZero() || !from.Equal(from.Truncate(ResolverInterval)) ||
		!to.Equal(to.Truncate(ResolverInterval)) || !to.After(from) ||
		to.Sub(from) > MaximumCaptureIntervals*ResolverInterval {
		return ClosedCapture{}, ErrCaptureWindow
	}
	from, to = from.UTC(), to.UTC()
	counts := ClosedCapture{Intervals: make([]ResolverIntervalCounts, int(to.Sub(from)/ResolverInterval))}
	for index := range counts.Intervals {
		start := from.Add(time.Duration(index) * ResolverInterval)
		counts.Intervals[index] = ResolverIntervalCounts{From: start, To: start.Add(ResolverInterval)}
	}
	limited := &io.LimitedReader{R: reader, N: MaximumCaptureBytes + 1}
	capture := NewCaptureReader(limited)
	for {
		if err := ctx.Err(); err != nil {
			return ClosedCapture{}, err
		}
		response, err := capture.Next()
		if limited.N <= 0 {
			return ClosedCapture{}, ErrCaptureLimit
		}
		if errors.Is(err, io.EOF) {
			if counts.Outside > 0 && counts.Selected == 0 {
				return ClosedCapture{}, ErrCaptureWindow
			}
			return counts, ctx.Err()
		}
		if err != nil {
			return ClosedCapture{}, err
		}
		if counts.Frames >= MaximumCaptureFrames {
			return ClosedCapture{}, ErrCaptureLimit
		}
		counts.Frames++
		if !response.Selected {
			continue
		}
		if response.ObservedAt.Before(from) || !response.ObservedAt.Before(to) {
			if response.ObservedAt.Before(from.Add(-ResolverInterval)) || !response.ObservedAt.Before(to.Add(ResolverInterval)) {
				return ClosedCapture{}, ErrCaptureWindow
			}
			counts.Outside++
			continue
		}
		index := int(response.ObservedAt.Sub(from) / ResolverInterval)
		counts.Intervals[index].add(response)
		counts.Selected++
	}
}

func (counts *ResolverIntervalCounts) add(response ResolverObservation) {
	counts.Responses++
	switch response.ResponseCode {
	case dns.RcodeNameError:
		counts.NameErrors++
	case dns.RcodeServerFailure:
		counts.ServerFailure++
	}
	if response.Truncated {
		counts.Truncated++
	}
}

var ErrInvalidCapture = errors.New("dnstap: invalid reduced capture")

// Validate checks the same finite counter and clock contract on the sender and
// receiver. A valid closed stream may contain no selected client responses.
func (c ClosedCapture) Validate(now time.Time) error {
	if len(c.Intervals) == 0 || len(c.Intervals) > MaximumCaptureIntervals ||
		c.Frames > MaximumCaptureFrames || uint64(c.Selected)+uint64(c.Outside) > uint64(c.Frames) {
		return ErrInvalidCapture
	}
	var selected uint64
	var previousEnd time.Time
	for _, interval := range c.Intervals {
		if !interval.AsOf(now, 24*time.Hour) || !previousEnd.IsZero() && !interval.From.Equal(previousEnd) {
			return ErrInvalidCapture
		}
		previousEnd = interval.To
		selected += uint64(interval.Responses)
	}
	if selected != uint64(c.Selected) {
		return ErrInvalidCapture
	}
	return nil
}

// ValidSourceRef admits an exact administrator-defined resolver token.
func ValidSourceRef(text string) bool {
	if len(text) < 1 || len(text) > 128 {
		return false
	}
	for index, char := range text {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' ||
			index > 0 && (char == '.' || char == '-' || char == '_') {
			continue
		}
		return false
	}
	return true
}
