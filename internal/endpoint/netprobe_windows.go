// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build windows

package endpoint

import (
	"context"
	"strconv"
)

// newPlatformLastMileCollector traces the path with `tracert -d` (numeric; -h max
// hops). tracert always sends three probes per hop, so the probes argument is
// accepted for signature parity but unused.
func newPlatformLastMileCollector(_ int, maxHops int) LastMileCollector {
	return cmdLastMileCollector{run: func(ctx context.Context, target string) (string, error) {
		return execText(ctx, "tracert", "-d", "-h", strconv.Itoa(maxHops), target)
	}}
}
