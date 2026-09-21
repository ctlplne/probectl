// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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
