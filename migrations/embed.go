// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package migrations embeds the sequential, idempotent SQL migrations applied
// by internal/store/migrate. Files are named NNNN_description.sql and applied in
// ascending numeric order (CLAUDE.md §6).
package migrations

import "embed"

// FS holds the embedded migration files.
//
//go:embed *.sql
var FS embed.FS
