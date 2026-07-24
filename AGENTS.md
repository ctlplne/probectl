# AGENTS.md — probectl

Instructions for coding agents (Codex, Claude Code, Cowork, or any other) working in this repo.

1. **Read `CLAUDE.md` first.** It is the engineering contract. The §7 guardrails are
   non-negotiable under any level of autonomy; §6 conventions bind every commit.

2. **If your task is the remediation program** (anything like "continue the harness",
   "work the backlog", "bring the platform to GA/F500"): read **`../harness/HARNESS.md`** —
   the harness lives OUTSIDE this repo, as a sibling folder at the workspace root
   (`ctlplne-probectl/harness/`). State lives in `../harness/backlog.json` — never in your
   session. Repo commits carry the trailer `Harness-Task: <id>`; record each commit sha in
   the backlog's evidence_log.

3. **If your task is ordinary feature/bug work:** follow `CLAUDE.md` §6–§9 (smallest
   coherent change; OpenAPI + docs + idempotent migration in the same commit; conventional
   commits; cross-tenant isolation test with any data-path change).

4. Licensing & business model: core is MPL-2.0; `ee/` is commercial — Enterprise licenses
   are flat-rate for self-hosters (all ee gates open); MSP licenses are consumption-based and
   open the ee gates for every tenant the MSP hosts, resold under the probectl banner. There
   is no white-label. New core files carry the MPL header; new `ee/` files carry the
   commercial header. Core never imports `ee/` — CI blocks it.

5. Verification helpers (from the workspace root): `bash harness/harness.sh status | next | validate | endgate`.
