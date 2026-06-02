// Package author is netctl's AI test authoring + auto-discovery (S26, F45): it
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
