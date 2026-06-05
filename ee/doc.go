// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).
//
// Source files in the ee/ tree are NOT covered by the repository's
// source-available license. They are provided under the probectl commercial
// license, which will be finalized with counsel before the repository goes
// public. Until then this header is the placeholder every ee/ file carries
// (CLAUDE.md §2, editions decisions — ratified June 2026).
//
// The boundary rules (CI-enforced by the editions gate):
//   - ee/ may import core packages; core may NEVER import ee/.
//   - A core-only build (with ee/ inert) must pass the entire test suite.
//   - Features here activate only through internal/license entitlements,
//     wired at the main.go Build* seams — never via scattered tier checks.

// Package ee is the root of probectl's commercial tree. It is intentionally
// empty at S-T0: the provider plane (S-T1), siloed isolation (S-T2),
// metering (S-T3), white-label (S-T4), BYOK (S-T6), governance (S-EE3), and
// guarded remediation (S-EE5) land here, each gated by its license feature.
package ee
