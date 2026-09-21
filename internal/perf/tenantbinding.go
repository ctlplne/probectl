// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package perf

import "context"

// harnessBinding satisfies the pipeline's tenant-binding requirement for the
// load harness, which runs against an in-memory stack with NO agent registry to
// verify against.
//
// It deliberately lives here rather than as an exported helper in
// internal/pipeline. The pipeline refuses to open a verifying lane without a
// binding precisely so the endpoint trust tier cannot be skipped by omission
// (threat model B9); shipping an exported "accepts everything" binding beside
// that check would hand back the bypass it exists to remove. A harness-local
// type cannot be reached from the control plane.
type harnessBinding struct{}

func (harnessBinding) Verify(context.Context, string, string) error { return nil }
