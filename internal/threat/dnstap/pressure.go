// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package dnstap

import (
	"errors"
	"time"
)

type PressureKind string

const (
	NameErrorPressure     PressureKind = "name_error_pressure"
	ServerFailurePressure PressureKind = "server_failure_pressure"
)

type PressureRule struct {
	MinResponses          uint32
	MinErrors             uint32
	ErrorShareBasisPoints uint32
}

func DefaultPressureRule() PressureRule {
	return PressureRule{MinResponses: 100, MinErrors: 50, ErrorShareBasisPoints: 5000}
}

type PressurePolicy struct {
	Enabled bool         `json:"enabled"`
	Rule    PressureRule `json:"rule"`
}

type ResolverPressure struct {
	Kind              PressureKind
	Previous, Current ResolverIntervalCounts
}

var ErrPressureRule = errors.New("dnstap: resolver pressure rule has invalid floors")

// Validate requires an explicit positive response, error and observed share
// floor. Counts are finite and share is expressed as an exact integer ratio.
func (r PressureRule) Validate() error {
	if r.MinResponses == 0 || r.MinResponses > MaximumCaptureFrames ||
		r.MinErrors == 0 || r.MinErrors > MaximumCaptureFrames ||
		r.ErrorShareBasisPoints == 0 || r.ErrorShareBasisPoints > 10000 {
		return ErrPressureRule
	}
	return nil
}

func (c ResolverIntervalCounts) valid() bool {
	return !c.From.IsZero() && c.From.Equal(c.From.Truncate(ResolverInterval)) &&
		c.To.Equal(c.From.Add(ResolverInterval)) && c.Responses <= MaximumCaptureFrames &&
		uint64(c.NameErrors)+uint64(c.ServerFailure) <= uint64(c.Responses) && c.Truncated <= c.Responses
}

// AssessResolverPressure compares two consecutive reduced intervals from the
// same verified source and assignment. This represents pressure in captured
// responses. Resolver outages and ordinary heavy traffic have separate
// explanations, and an incomplete interval must be withheld by the caller.
func AssessResolverPressure(rule PressureRule, previous, current ResolverIntervalCounts) ([]ResolverPressure, error) {
	if err := rule.Validate(); err != nil {
		return nil, err
	}
	if !previous.valid() || !current.valid() || !previous.To.Equal(current.From) {
		return nil, ErrCaptureWindow
	}
	var findings []ResolverPressure
	if rule.pressured(previous.Responses, previous.NameErrors) && rule.pressured(current.Responses, current.NameErrors) {
		findings = append(findings, ResolverPressure{Kind: NameErrorPressure, Previous: previous, Current: current})
	}
	if rule.pressured(previous.Responses, previous.ServerFailure) && rule.pressured(current.Responses, current.ServerFailure) {
		findings = append(findings, ResolverPressure{Kind: ServerFailurePressure, Previous: previous, Current: current})
	}
	return findings, nil
}

func (r PressureRule) pressured(responses, failures uint32) bool {
	return responses >= r.MinResponses && failures >= r.MinErrors &&
		uint64(failures)*10000 >= uint64(responses)*uint64(r.ErrorShareBasisPoints)
}

// AsOf distinguishes an archived observation from a recently closed interval.
func (c ResolverIntervalCounts) AsOf(now time.Time, maximumAge time.Duration) bool {
	return c.valid() && maximumAge > 0 && !c.To.After(now) && now.Sub(c.To) <= maximumAge
}
