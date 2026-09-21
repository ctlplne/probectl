// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package browser

import "context"

// RunOutput is a driver's Result plus the optional failure-artifact bytes. The
// Fleet uploads the artifact to the object store and fills Result.Screenshot — the
// driver stays storage-agnostic.
type RunOutput struct {
	Result         Result
	Screenshot     []byte // nil when there's nothing to capture
	ScreenshotType string // e.g. "image/png" (browser) or "text/html" (HTTP)
}

// Driver runs a transaction Script. A driver may hold a heavy resource (a browser
// process); the Fleet owns the lifecycle — it builds drivers from a factory, runs
// at most MaxConcurrency at once, and recycles a driver (Close, if it implements
// Closer) after RecycleAfter runs or on a failed run.
//
// A driver must surface a transaction failure (a bad assertion, a 500) inside the
// Result (Success=false), NOT as a returned error. A returned error is reserved
// for an infrastructure fault (the browser crashed, the run was canceled) and
// triggers a recycle.
type Driver interface {
	Name() string
	Run(ctx context.Context, s Script) (RunOutput, error)
}

// Closer is implemented by drivers that hold resources to release on recycle.
type Closer interface {
	Close() error
}
