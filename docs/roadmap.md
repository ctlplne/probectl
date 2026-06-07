# Roadmap (U-089)

Two quarters, directional. **Not a committed delivery schedule** — solo
founder + AI agents; ordering reflects diligence priority (the unified
register) and the BLOCKED-ON-HUMAN items already staged in-repo. Updated
quarterly; history stays in git.

## Q3 2026 — evidence completion & GA hardening

The harnesses exist; this quarter runs them on real iron and signs off.

- **L/XL full-stack load runs on reference hardware** → fill the
  `docs/scale-gate.md` results table, flip SLOs from PROVISIONAL (U-005;
  `make load-test TIER=L|XL` is ready).
- **Representative DR drill + RTO/RPO sign-off** → fill `docs/ops/dr.md`,
  remove the PROVISIONAL banner (U-053).
- **Reference-host agent overhead row** (live ring buffer) → complete
  `docs/agent-overhead.md` + finalize the agent whitepaper numbers
  (U-051/U-034; `scripts/bench/agent_overhead.sh`).
- **LICENSE + commercial texts via counsel** (BSL parameters, `ee/`
  header, reseller terms) — replaces the TBD placeholder (CLAUDE.md §2).
- **Procurement pack through counsel** → DPA/subprocessors finalized; CAIQ
  generated from the SOC 2 mapping (U-065).
- **Fleet rollout surface**: wire the `internal/agent/rollout.go` engine
  into the CLI/console (the engine + operator flow shipped in U-031).
- **OTLP traces/logs ingest** — scoped design + decision per the U-020
  roadmap note (`docs/otlp.md`): ingest-for-correlation with conformance
  tests, or defer with re-scoped claims standing.
- Backup CronJobs folded into the Helm chart behind `backup.enabled`
  (follow-up noted in `deploy/backup/README.md`).

## Q4 2026 — trust packaging & multi-tenant scale-out

- **SOC 2 readiness assessment** once the org gaps in
  `docs/compliance/soc2-mapping.md` (SoD, formal policies) close with the
  first hires.
- **Multi-region validated runbooks** (the Enterprise `ha_support`
  entitlement) on top of the Q3 drill evidence.
- **Siloed ClickHouse migrations per tenant database** (extend the U-046
  ledger to per-tenant DB routing — follow-up noted in
  `internal/store/flowstore`).
- **eBPF L7 productionization**: fd→socket correlation for precise edges;
  Go-TLS strategy decision (U-074 — disclosed limitation,
  `docs/ebpf-feasibility.md` §7; the disassemble-RET-offsets + goroutine-ABI
  path).
- **eBPF IPv6 capture (U-073)**: extend l4flow to the 16-byte address path
  (the non-IPv4 blind spot is already counted as `filtered_non_ipv4_total`).
- **Design-led surfaces**: path map + topology/what-if as the hero UI
  views (PRD §6), white-label token QA at MSP scale.
- **GA milestone gate**: surface-coverage + cross-plane correlation gates
  green at GA scope (CLAUDE.md §8), nightly e2e (U-054) expanded to the
  canary-agent mTLS path.

## Standing (every quarter)

Dependency/action pin freshness (U-007/U-069), drill cadence (backup,
failover, IR tabletop), threat-model review on any boundary change
(U-033), CHANGELOG via `scripts/release_notes.sh` at each tag (U-087).
