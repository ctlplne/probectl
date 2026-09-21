# AGENTS.md — probectl

Instructions for coding agents (Codex, Claude Code, Cowork, or any other) working in this repo.

1. **Read `CLAUDE.md` first.** It is the engineering contract.
   `probectl-PRD-v1.1.md` is the current steering contract;
   `probectl-PRD-v1.0.md` remains the detailed feature/evidence inventory. The §7
   guardrails are non-negotiable under any level of autonomy; §6 conventions bind
   every commit.

2. **If your task is programme work** (anything like "work the backlog" or "continue the
   programme"): the one live programme is **`../design-partner-readiness/`** — start at
   `../design-partner-readiness/PLAN.md`, then
   `../design-partner-readiness/RUN_PROMPT.md`,
   `../design-partner-readiness/FINDINGS.md` and
   `../design-partner-readiness/decisions-needed.md`. It lives outside this repo so programme
   state never ships with the product. Its standing rules: fix everything found (no backlog),
   §7 guardrails never relaxed, commit on `main` as the owner, never push. The 2026-08-08
   comprehensive backlog (`../probectl-comprehensive-backlog-2026-08-08.html`) and every
   earlier harness are RETIRED read-only reference, and the root backlog file they used no
   longer exists — do not resurrect either, and do not invent a missing program/playbook
   path. The retired harness proofs E2/E3/E4/L4 remain documented in
   `probectl-PRD-v1.1.md` §4.

3. **If your task is ordinary feature/bug work:** follow `CLAUDE.md` §6–§9 (smallest
   coherent change; OpenAPI + docs + idempotent migration in the same commit; conventional
   commits; cross-tenant isolation test with any data-path change).

4. Licensing & business model: the core is BUSL-1.1 (source-available; each version
   converts to MPL-2.0 four years after publication); `pkg/`, `proto/` and `examples/` are
   MPL-2.0; `ee/` is commercial. Enterprise licenses open all ee gates for one self-hosted
   deployment; MSP licenses open the ee gates for every tenant the MSP hosts, resold under
   the probectl banner. No price list or pricing model is published. There is no
   white-label. New core files carry the BSL header, new client-tree files the MPL header,
   and new `ee/` files the commercial header. Core never imports `ee/` — CI blocks it.

5. Verification (from the repo root): `bash scripts/verify_all.sh` is the executed-proof
   umbrella; individual gates are listed by `make help`. Contract-file references are
   themselves gated: `scripts/check_contract_links.sh` fails on any reference in this
   file or `CLAUDE.md` whose target does not exist.
