// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package migrations embeds the sequential, idempotent SQL migrations applied
// by internal/store/migrate. Files are named NNNN_description.sql and applied in
// ascending numeric order (CLAUDE.md §6).
package migrations

import "embed"

// FS holds the embedded migration files.
//
//go:embed *.sql
var FS embed.FS
