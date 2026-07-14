// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package cipolicy holds policy tests over the CI/release workflows — the in-repo
// backstops that protect main and the release path when server-side settings
// (GitHub branch protection) cannot be asserted from the tree. It has no runtime
// code; all assertions live in the _test.go files (EXC-GATE-02 / EXC-GATE-04).
package cipolicy
