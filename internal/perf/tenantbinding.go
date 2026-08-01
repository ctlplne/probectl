// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
