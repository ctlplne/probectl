// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package cipolicy holds policy tests over the CI/release workflows — the in-repo
// backstops that protect main and the release path when server-side settings
// (GitHub branch protection) cannot be asserted from the tree. It has no runtime
// code; all assertions live in the _test.go files (EXC-GATE-02 / EXC-GATE-04).
package cipolicy
