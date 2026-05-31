// Package migrations embeds the sequential, idempotent SQL migrations applied
// by internal/store/migrate. Files are named NNNN_description.sql and applied in
// ascending numeric order (CLAUDE.md §6).
package migrations

import "embed"

// FS holds the embedded migration files.
//
//go:embed *.sql
var FS embed.FS
