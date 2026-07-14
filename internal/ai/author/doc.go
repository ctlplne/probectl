// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package author is probectl's AI test authoring + auto-discovery (S26, F45): it
// turns a natural-language request into a synthetic-test config, and mines
// observed telemetry to propose monitorable targets.
//
// Everything here PROPOSES — it never auto-applies (CLAUDE.md §7 guardrail 8:
// observe/propose, human-gated). A proposal is always validated against the
// canonical test schema (internal/testspec) before it is returned, so an invalid
// config is never surfaced for confirmation. The default authoring path is a
// deterministic, air-gapped heuristic; a model-backed author plugs into the same
// interface for richer requests (the model output is still schema-checked).
package author
