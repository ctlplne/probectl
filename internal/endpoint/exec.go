// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package endpoint

import (
	"context"
	"os/exec"
)

// execText runs a command and returns its stdout as text. A missing binary or a
// non-zero exit returns the error; callers treat that as "signal unavailable"
// and degrade gracefully (they never panic). This is the single, tiny exec seam
// every platform collector funnels through.
func execText(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

// cmdWiFiCollector runs a command and parses its output into WiFi. The run seam
// makes the exec→parse glue unit-testable with a fixture runner (the real
// platform wiring lives in the build-tagged wifi_*.go files).
type cmdWiFiCollector struct {
	run   func(ctx context.Context) (string, error)
	parse func(string) WiFi
}

func (c cmdWiFiCollector) Collect(ctx context.Context) (WiFi, error) {
	out, err := c.run(ctx)
	if err != nil {
		return WiFi{}, err
	}
	return c.parse(out), nil
}

// cmdLastMileCollector runs a traceroute-style command and parses the hops. Same
// testable seam as cmdWiFiCollector.
type cmdLastMileCollector struct {
	run func(ctx context.Context, target string) (string, error)
}

func (c cmdLastMileCollector) Collect(ctx context.Context, target string) (LastMile, error) {
	out, err := c.run(ctx, target)
	hops, reached := parseTraceHops(out)
	lm := LastMile{Target: target, Hops: hops, Reached: reached}
	if len(hops) == 0 && err != nil {
		return lm, err // nothing parsed and the command failed: unavailable
	}
	return lm, nil // partial output (a trace that died mid-path) is still useful
}
