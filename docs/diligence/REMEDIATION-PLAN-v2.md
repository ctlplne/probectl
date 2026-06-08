# probectl — Remediation Plan v2 (post-verification, fact-checked)

*Built from the third-party diligence audit (`probectl-audit/outputs/*`) **after** an independent
verification pass (`probectl-audit/outputs/00-AUDIT-VERIFICATION.html`). Every sprint below is grounded
in a finding I re-confirmed against the code at `HEAD` — the 8 verified-FALSE audit findings are NOT
work items (they live in Appendix C, document-only). Severities are my **corrected** severities, not the
audit's raw labels. This plan supersedes the v1 `REMEDIATION-SPRINT-PLAN.md` for everything still open.*

---

## §0 — OPERATING PROTOCOL (read first; this is how an autonomous session runs this plan)

You (the executing agent) run this plan **continuously, sprint by sprint, without waiting for the human**.
The human reviews the whole commit stack and pushes at the end. Follow these rules exactly.

1. **Read first:** `CLAUDE.md` (§7 guardrails, §9 operating model) and this file. The repo is the ground
   truth; this plan's Evidence lines are pre-verification snapshots — **re-confirm current state with
   `grep`/`sed`/tests before changing anything** (audit evidence can drift by a few lines).
2. **One sprint → one commit.** Smallest coherent change that satisfies the sprint. No drive-by refactors,
   no scope creep. Conventional commit message (the sprint gives one). **Never `git push`** — the human pushes.
3. **Resume by checkbox.** The overview table (§2) has a `[ ]` per sprint. Do the **first unchecked**
   sprint, flip it to `[x]` in the same commit, then **immediately continue to the next** unchecked sprint.
   A fresh/continued session re-reads this file and picks up at the first `[ ]`. Do not re-do `[x]` sprints.
4. **Verify gates before committing** (the green-build bar from `make verify-all`):
   - `gofmt -l` clean on touched dirs; `go build ./...`; `go vet ./<pkg>/`.
   - `go test ./<changed-pkgs>/` pass (use `-race` where the sprint says so).
   - The repo guards still pass: `scripts/check_crypto_imports.sh`, `check_tls_configs.sh`,
     `check_editions_imports.sh`, `check_stringbuilt_sql.sh`, `check_supply_pins.sh`.
   - If the change touches Helm: `helm lint` + the `check_helm_hardening.sh` gate.
   - **Crypto only via `internal/crypto`** (guardrail 3) — the import guard will catch `crypto/*` in app code.
5. **Decision forks → take the pre-authorized default (§1) and proceed.** Do NOT stop to ask. If a fork is
   not covered by §1 and is a genuine CLAUDE.md-§9 trigger (architecture/guardrail/new-dependency), pick the
   smallest reversible option, **document the decision in the commit + register**, and continue.
6. **Genuinely-blocked items → skip-and-flag, keep going.** If a sprint cannot be completed in this
   environment (needs reference hardware, a live PG/CH/Kafka stack, a real kernel matrix, or a human/counsel
   decision), do the **stageable** part (harness/CI wiring/docs), record a precise TODO in the register, leave
   the sprint `[~]` (partial) with a note, and move to the next. **Never fabricate** a number, a benchmark, a
   passing drill, or a legal decision.
7. **Each sprint also updates:** `docs/diligence/known-risks.md` (flip the row) and `CHANGELOG.md`
   (one entry under "Unreleased"). These are part of the sprint, not optional.
8. **Sandbox notes:** Go toolchain via `GOTOOLCHAIN=auto` (downloads go1.26.4), `GOWORK=off`,
   `CGO_ENABLED=0` for plain builds (`=1` only for `-race`). If you hit "too many open files," `ulimit -n
   65535` and `-p 2`/`-p 1`. `rm -f .git/index.lock` if a stale lock blocks a commit. `clang`/live stacks are
   absent — `[needs-infra]` items ride CI.

**Definition of a "medium" sprint:** one coherent theme, ~2–8 files, one commit, completable inside one
session before context pressure. If a sprint feels large, split it and renumber the tail — but keep one
commit per delivered unit.

---

## §1 — Pre-authorized founder decisions (so the run never blocks on "ask the human")

These resolve the design forks in the sprints below. They are deliberate defaults; the human reviews them in
the diffs. If you disagree with one at runtime, still implement it (reversible) and note the concern.

- **D1 — otelstore erasure:** wire the OTLP trace/log store into the tenant-erasure engine via a
  `WithOtel(...)` seam, exactly mirroring `WithPaths`/`WithTopology`. The attestation gains an `"otel"`
  `StoreResult`; `EraseTenant` is verified-zero like the other stores. (No new dependency.)
- **D2 — WORM signing key:** load the Ed25519 signing key from a configured source
  (`PROBECTL_WORM_SIGNING_KEY` / key file, via `internal/crypto`), generate-and-persist on first boot like the
  envelope KEK, and **fail closed** in regulated profiles when audit-export is enabled but no key resolves.
  Do NOT mint an ephemeral key per boot. The public key keeps being published next to segments.
- **D3 — `/metrics` (SEC-002):** keep it pre-auth and tenant-data-free (it is, and a regression test already
  guards `tenant_id=`). Do **not** add auth. The only change: down-rate it in the register to Low and add a
  one-line doc cross-ref to the NetworkPolicy scoping. (Calibration, not code.)
- **D4 — flow / OTLP durability:** match the existing results-plane contract (`internal/control` retry+DLQ).
  Reuse the same `DeadLetter*` topic + retry helper; do not invent a new mechanism.
- **D5 — fairness Gate contention (SCALE-001):** reduce lock scope with the smallest safe change (e.g. shard
  the counter map by tenant or move the hot read off the global mutex). Do **not** introduce a new
  concurrency dependency. If a safe change isn't obvious in one sprint, ship a benchmark + a documented
  TODO and leave it `[~]` rather than risk a correctness regression.
- **D6 — branch protection (TEST-002):** edit `.github/rulesets/main.json` to add the missing required
  contexts (`verify-all`, `rca-eval`, `ebpf-image-live`, `build-images`). Leave `required_approving_review_count`
  at 0 with a documented "solo-founder; raise to 1 when a second maintainer exists" note (a 1-review rule is
  unsatisfiable today and would block the founder's own merges). GitHub-side application is the human's step.
- **D7 — MFA (SEC-005):** parse the `amr` claim from the verified ID token and set `Identity.MFASatisfied`
  accordingly; expose an optional `PROBECTL_REQUIRE_MFA` that 403s sessions without it. Default off (don't
  break existing single-factor deployments).
- **D8 — compliance scaffolding scope:** generate the *mechanical* artifacts only (SPDX headers, `NOTICE`,
  third-party inventory, DCO check, SBOM). The license **choice**, CLA legal text, SOC2 engagement, and DPA
  are **counsel decisions** — list them in Appendix B, do not draft binding legal text.

---

## §2 — Sprint overview (resume at the first `[ ]`)

| # | Phase | Sprint | Closes (verified IDs) | Corrected sev | Size |
|---|---|---|---|---|---|
| [x] 1 | A | Green build: fix the 2 failing tests + close the verify-all coverage hole | CORRECT-002/DOCS-F02/TEST-001, RESIL-006 | High | M |
| [x] 2 | A | Tenant erasure covers the OTLP store (GDPR Art. 17) | TENANT-008 (↑High), correct COMPLY-013 | High | M |
| [x] 3 | A | Persist the WORM audit signing key (cross-restart chain verify) | KEYS-002 / COMPLY-008 (↑High) | High | M |
| [x] 4 | A | Vault AppRole token-cache data race | KEYS-001 | High | M |
| [x] 5 | A | Handle ignored `json.Unmarshal` in store hydration | CODE-005 (miss) + Sprint-2 leftover | Medium | M |
| [x] 6 | B | OTLP consumer retry + DLQ (durability parity) | SCALE-003 / ARCH-002 | High | M |
| [x] 7 | B | Flow store-failure DLQ + drop counter | CORRECT-001 (SCALE-012 reconciled ↑High) | High | M |
| [x] 8 | B | Bound the DNS pending-map (eviction cap) | FUZZ-001 | High | M |
| [x] 9 | B | Reduce fairness Gate lock contention | SCALE-001 | High | M |
| [x] 10 | C | MFA wired end-to-end (amr → MFASatisfied) | SEC-005 | Medium | M |
| [x] 11 | C | CGNAT 100.64/10 internal classification (NDR) | THREAT-001 | Medium | S |
| [x] 12 | C | Branch-protection required-checks + review note | TEST-002 / SUPPLY-005 | Medium | S |
| [ ] 13 | C | Hygiene bundle: security headers, go-version skew, down-migration policy | SEC-006, SUPPLY-007, SCHEMA-001 | Low–Med | M |
| [ ] 14 | D | SPDX headers + NOTICE + third-party license inventory | LICENSE-003, DATAROOM-003 | High(legal-prep) | M |
| [ ] 15 | D | DCO check in CI + CONTRIBUTING IP section | LICENSE-004 / GOV-002 (automatable half) | Medium | S |
| [ ] 16 | D | SBOM generation in CI (+ artifact) | DATAROOM-003 | Medium | S |
| [ ] 17 | C | Frontend AuthProvider → real session identity | SEC-001 (↓Med, product-maturity) | Medium | M |

*Appendix A: `[needs-infra]` deferred. Appendix B: legal/IP founder+counsel tasks. Appendix C: 8 verified-FALSE
findings (document-only). Appendix D: CODE-003 git-history blob cleanup (force-push decision).*

---

## §3 — Sprints

> Format per sprint: **Closes · Verified severity · Evidence (re-confirm first) · Tasks · Acceptance · Verify · Commit.**

### Phase A — green build & confirmed defects

---

#### Sprint 1 — Green build: fix the two failing tests + close the verify-all coverage hole
**Closes:** CORRECT-002 / DOCS-F02 / TEST-001 (flow), RESIL-006 (outage). **Severity:** High (the build is
not green today; a prior "verify-all green" claim was overstated because these packages weren't exercised).

**Evidence (re-confirm):**
- `internal/flow/emit_config_test.go:~49` — `TestBusEmitterTenantTaggedBatch` asserts the bus key equals
  `"t-acme"`, but `internal/flow/emit.go` now emits via `bus.TenantKey(tenant, agentID)` which appends the
  Sprint-15 `|b<bucket>` suffix (`internal/bus/bus.go:~159`). Stale assertion, not a routing bug
  (`tenantFromKey` strips the suffix; routing is correct).
- `internal/outage/feeds_test.go:~173` — `TestRefresherKeepsLastGoodAndReportsHealth` fails because the
  fixture uses a hardcoded date (`2026-06-05`) that falls outside the 48h retention window on the test clock.

**Tasks:**
1. Fix the flow test assertion to expect the bucketed key (use `bus.TenantKey(...)` to build the expected
   value, like the Sprint-15 endpoint emit test) — assert routing/tenant-strip correctness, not the literal.
2. Fix the outage test to use a relative/injected clock or a fixture timestamp inside the retention window
   (prefer `WithClock`-style injection over a moving real-time fixture).
3. Run the FULL suite (`go test ./...`) and fix anything else red.
4. **Close the coverage hole:** ensure `internal/flow` and `internal/outage` are actually exercised by the
   `verify-all`/`test-go` path so this can't silently recur. If `make test` already covers `./...`, add a
   one-line note in `scripts/verify_all.sh` confirming the full-tree run; if any package is skipped, wire it in.

**Acceptance:** `go test ./...` is fully green; no `_test.go` carries a stale `tenant|bucket` assumption.
**Verify:** `go test ./internal/flow/ ./internal/outage/ -v` (both PASS); `go test ./... 2>&1 | grep -c FAIL` → 0.
**Commit:** `fix(test): green the flow + outage suites and close the verify-all coverage hole (CORRECT-002, RESIL-006)`

---

#### Sprint 2 — Tenant erasure covers the OTLP trace/log store (GDPR Art. 17)
**Closes:** TENANT-008 (upgraded High); corrects the over-stated COMPLY-013 "erasure across 5+ stores" claim.
**Severity:** High — a whole tenant-PII telemetry plane is not erased on offboarding, while the attestation
reports "complete." This is the audit's biggest MISS and a real compliance gap. **Decision D1 applies.**

**Evidence (re-confirm):**
- `internal/store/otelstore/clickhouse.go:~274` and `memory.go:~132` — `EraseTenant` exists.
- `internal/tenantlife/tenantlife.go` — `Erase()` iterates flows/objects/tsdb/paths/topology/postgres but
  **never** otelstore (`grep otelstore internal/tenantlife` → no hits); `cmd/probectl-control/main.go:~621`
  builds the engine with `WithPaths/.WithTopology` and no otel seam.

**Tasks:**
1. Add `WithOtel(store otelstore.Store) *Engine` to `tenantlife`, mirroring `WithPaths`.
2. In `Erase()`, call `otelstore.EraseTenant` and append an `"otel"` `StoreResult` (deleted count +
   verified-zero), so the attestation enumerates it (or records "store not deployed" when nil).
3. Wire it in `main.go` (`.WithOtel(otelStore)`).
4. Test: a tenant with spans+logs is erased to zero; the attestation includes the `otel` store and is
   `complete`; a second tenant's OTLP data is untouched.
5. Update `known-risks.md` (TENANT-008 → closed) and **correct the COMPLY register's strength claim** by
   noting the gap is now closed (don't leave COMPLY-013 over-stating).

**Acceptance:** offboarding erases OTLP traces+logs and the attestation proves it; neighbor tenant intact.
**Verify:** `go test ./internal/tenantlife/ -run "Eras|Otel|Coverage" -v`.
**Commit:** `fix(tenancy): tenant erasure now covers the OTLP trace/log store + attestation (TENANT-008)`

---

#### Sprint 3 — Persist the WORM audit signing key
**Closes:** KEYS-002 / COMPLY-008 (upgraded High). **Severity:** High — a control-plane restart silently
mints a new Ed25519 key, breaking cross-restart verification of the tamper-evident provider audit WORM chain
(SOC2/forensic blast radius). **Decision D2 applies.**

**Evidence (re-confirm):**
- `internal/audit/worm.go:61-74` — `NewWormExporter` generates a fresh key when `privPEM` is empty.
- `internal/audit/worm.go:79` `NewWormExporterPG(pool, objects, log)` passes no key; `cmd/probectl-control/main.go:~643`
  calls it. No `PROBECTL_WORM_SIGNING_KEY` anywhere.

**Tasks:**
1. Add a configured key source (env base64 / key file) loaded via `internal/crypto`
   (`LoadOrGenerateKeyFile`-style: generate-and-persist on first boot, reuse thereafter).
2. Thread it through `NewWormExporterPG` → `NewWormExporter`.
3. Fail closed in regulated profiles: if audit-export is enabled (`RequireAtRestEncryption`/equivalent) and no
   signing key resolves, refuse to start (don't silently ephemeral-key).
4. Test: two exporter constructions from the same configured key produce the **same** public key and a chain
   signed across a simulated restart verifies; a missing key in regulated mode errors.
5. Document the new key in `docs/configuration.md` + hardening ("back this up like the envelope key").

**Acceptance:** WORM chain verifies across restarts with a configured key; ephemeral-per-boot is gone.
**Verify:** `go test ./internal/audit/ -run "Worm|Sign|Verify" -v`.
**Commit:** `fix(audit): persist the WORM signing key so the export chain verifies across restarts (KEYS-002)`

---

#### Sprint 4 — Vault AppRole token-cache data race
**Closes:** KEYS-001. **Severity:** High — a real, `-race`-reproducible data race in the secret backend.

**Evidence (re-confirm):**
- `internal/secrets/backends.go` — `VaultSource.Fetch` (~line 149) reads/writes the AppRole token cache;
  `internal/secrets/secrets.go` (~line 191) releases `mu` before calling `src.Fetch`, so concurrent
  `Resolve` calls race the cache map. `go test -race ./internal/secrets/` reproduces (DATA RACE at the
  cache read/write sites).

**Tasks:**
1. Guard the Vault token cache with its own mutex (or `sync.RWMutex`) inside `VaultSource` — the cache is the
   backend's own state; don't rely on the resolver's released lock.
2. Keep the lock scope minimal (don't hold it across the network fetch; double-checked or single-flight is fine).
3. Add a `-race` test that hammers `Fetch`/`Resolve` concurrently and must be clean.

**Acceptance:** `go test -race ./internal/secrets/` is clean; concurrent resolves don't corrupt the cache.
**Verify:** `CGO_ENABLED=1 go test -race ./internal/secrets/ -run "Vault|Cache|Resolve" -v`.
**Commit:** `fix(secrets): lock the Vault AppRole token cache (data race under concurrent resolve) (KEYS-001)`

---

#### Sprint 5 — Handle ignored `json.Unmarshal` in store hydration
**Closes:** the CODE-005 miss (audit enumerated 4 InTenant sites, never the JSON-decode ones) + the never-done
Sprint-2 safe-error-handling item. **Severity:** Medium — a corrupt JSON column silently yields empty ABAC
subject/resource maps, which could mis-evaluate a deny-override policy.

**Evidence (re-confirm):**
- `internal/store/abac.go:27,30` — `_ = json.Unmarshal(subj, &p.Subject)` / `_ = json.Unmarshal(res, &p.Resource)`.
- `internal/store/users.go:~32`, `internal/store/changes.go:~29` — same pattern hydrating attributes.

**Tasks:**
1. Capture and surface the decode errors (return a wrapped error / fail the row read) rather than dropping
   them — a malformed policy must not silently become an empty (permissive-input) policy.
2. Apply to `abac.go`, `users.go`, `changes.go` (grep for `_ = json.Unmarshal` under `internal/store`).
3. Tests: a corrupt JSON column makes the read fail loudly (not return an empty struct); valid rows still load.

**Acceptance:** no `_ = json.Unmarshal` remains in `internal/store` hydration paths; corrupt input errors.
**Verify:** `go test ./internal/store/ -run "ABAC|Abac|User|Change|Unmarshal" -v`; `grep -rn "_ = json.Unmarshal" internal/store` → none in hydration.
**Commit:** `fix(store): surface JSON decode errors in ABAC/user/change hydration (CODE-005)`

### Phase B — durability & robustness

---

#### Sprint 6 — OTLP consumer retry + DLQ
**Closes:** SCALE-003 / ARCH-002. **Severity:** High — externally-ingested OTLP metrics/traces/logs are
dropped best-effort on a store-write failure (`return nil`), unlike the results plane which has retry+DLQ.
**Decision D4 applies (reuse the existing DeadLetter/retry contract).**

**Evidence (re-confirm):**
- `internal/pipeline/otlp.go:69-71` — `return nil // best-effort`; `internal/pipeline/otlpsignals.go:~71-74,
  ~152-155` (traces/logs handlers) same best-effort drop.

**Tasks:**
1. Wrap the OTLP store writes with the same retry+DLQ helper the device/results plane uses (don't invent a
   new mechanism — reuse `writeWithRetry`/`deadLetter`-style code from the consumer).
2. Add a dropped/dead-lettered counter surfaced in `internal/metrics` (so drops are observable, not silent).
3. Test: a failing store write retries then dead-letters (with the original bytes), and increments the counter.

**Acceptance:** OTLP write failures retry + dead-letter + count; parity with the results-plane durability contract.
**Verify:** `go test ./internal/pipeline/ -run "OTLP|DLQ|Retry" -v`.
**Commit:** `feat(pipeline): retry + DLQ for OTLP metrics/traces/logs consumers (SCALE-003, ARCH-002)`

---

#### Sprint 7 — Flow store-failure DLQ + drop counter
**Closes:** CORRECT-001 (reconciling SCALE-012's under-rated Low to High — the flow plane is the
highest-volume, billing-relevant plane). **Severity:** High. **Decision D4 applies.**

**Evidence (re-confirm):** `internal/flow/flow.go:~192-193` — on insert/store failure the batch is dropped
with no DLQ and no counter.

**Tasks:**
1. Route store-write failures through retry+DLQ (same contract as Sprint 6) or, if the flow ingest path can't
   reach the bus DLQ, at minimum a bounded local retry + a dropped-records counter + a structured error log.
2. Surface the drop counter in `internal/metrics`.
3. Test: store failure does not silently lose the batch; counter increments; success path unchanged.

**Acceptance:** flow store failures are retried/dead-lettered/counted, not silently dropped.
**Verify:** `go test ./internal/flow/ -run "Drop|DLQ|Retry|Store" -v`.
**Commit:** `fix(flow): DLQ + drop counter on store-write failure (CORRECT-001)`

---

#### Sprint 8 — Bound the DNS pending-map
**Closes:** FUZZ-001. **Severity:** High — `internal/ebpf/l7/dns.go:~34` adds to `p.pending[msg.Id]` on every
query and only deletes on a matched response; an attacker (or lossy network) of unanswered queries grows it
unbounded (the 16-bit ID space self-caps at 65k entries/parser, but that's still unbounded per-connection churn).

**Tasks:**
1. Add a bound + eviction to the pending map (max entries and/or TTL on entries; evict oldest on overflow).
2. Keep correctness: a normal query→response still matches within the window.
3. Test: flooding unanswered queries keeps the map bounded; legitimate matches still resolve.

**Acceptance:** the DNS pending map is bounded under unanswered-query flood; matching still works.
**Verify:** `go test ./internal/ebpf/l7/ -run "DNS|Pending|Evict" -v`.
**Commit:** `fix(ebpf/l7): bound the DNS pending-query map with eviction (FUZZ-001)`

---

#### Sprint 9 — Reduce fairness Gate lock contention
**Closes:** SCALE-001. **Severity:** High (throughput hot-path). **Decision D5 applies — prefer a benchmark +
documented partial over a risky correctness change.**

**Evidence (re-confirm):** `internal/fairness/fairness.go` — the Gate takes a global `g.mu.Lock()` on the
admit hot path (lock sites ~279/291/298). Under high fan-in this serializes all tenants.

**Tasks:**
1. Add a benchmark capturing current contention (parallel admits across N tenants).
2. Reduce lock scope with the smallest safe change: shard the per-tenant counters (e.g. striped maps keyed by
   tenant hash) or move the read-mostly path to `RWMutex`/atomics — **without** changing admit semantics.
3. If no change is provably safe in one sprint, ship the benchmark + a documented TODO and leave the sprint
   `[~]`. Do NOT risk a fairness-correctness regression for throughput.

**Acceptance:** measurable contention reduction with identical admit decisions, or a benchmark + honest TODO.
**Verify:** `go test ./internal/fairness/ -run Fairness -v`; `go test -bench=. ./internal/fairness/`.
**Commit:** `perf(fairness): reduce admit-path lock contention (SCALE-001)`  *(or `[~]` partial with TODO)*

### Phase C — security / ops hardening

---

#### Sprint 10 — MFA wired end-to-end
**Closes:** SEC-005. **Severity:** Medium — `Identity.MFASatisfied` exists and is plumbed through
session/middleware/audit (`internal/auth/auth.go:34,47`; `middleware.go:64`; `control/auth.go:212,428`) but
the OIDC callback never parses the `amr` claim, so it is always false. **Decision D7 applies.**

**Tasks:**
1. Parse `amr` from the verified ID token in `internal/auth/oidc.go` and set `Identity.MFASatisfied` when it
   indicates a second factor (`mfa`/`hwk`/`otp`/`phr`...).
2. Optional `PROBECTL_REQUIRE_MFA` (default off): when on, sessions without `MFASatisfied` get 403.
3. Tests: an `amr`-bearing token sets the flag; require-MFA rejects sessions without it; default unchanged.
4. Document the env key.

**Acceptance:** MFA state flows from the IdP to the session and can be enforced; default behavior preserved.
**Verify:** `go test ./internal/auth/ ./internal/control/ -run "MFA|OIDC|Amr|Callback" -v`.
**Commit:** `feat(auth): parse amr and enforce MFA end-to-end (optional) (SEC-005)`

---

#### Sprint 11 — CGNAT 100.64/10 internal classification (NDR)
**Closes:** THREAT-001. **Severity:** Medium — `internal/threat/ndr.go:720 isInternal()` returns
`ip.IsPrivate() || IsLoopback() || IsLinkLocalUnicast()`; `netip.IsPrivate` is **false** for CGNAT
`100.64.0.0/10`, so carrier/cloud-NAT internal hosts are misclassified external (lateral-movement blind spot).

**Tasks:**
1. Add `100.64.0.0/10` (and consider IPv6 ULA `fc00::/7` if not already covered) to `isInternal`.
2. Make the internal-range set configurable/overridable if the package already has a config seam; otherwise a
   documented constant is fine.
3. Test: 100.64.x.x classifies internal; public IPs still external.

**Acceptance:** CGNAT addresses classify as internal; no public-range regressions.
**Verify:** `go test ./internal/threat/ -run "Internal|CGNAT|Classif" -v`.
**Commit:** `fix(threat): classify CGNAT 100.64/10 as internal in NDR (THREAT-001)`

---

#### Sprint 12 — Branch-protection required checks + review note
**Closes:** TEST-002 / SUPPLY-005. **Severity:** Medium. **Decision D6 applies.**

**Evidence (re-confirm):** `.github/rulesets/main.json` — `required_approving_review_count: 0`,
`require_code_owner_review: false`; `cross-tenant-isolation` **is** present (line ~44), but
`verify-all` / `rca-eval` / `ebpf-image-live` / `build-images` are **absent** from required contexts (they
exist as CI jobs but don't block merge — so "fixed" findings can silently regress).

**Tasks:**
1. Add the missing required contexts to `rulesets/main.json` (`verify-all`, `rca-eval`, `ebpf-image-live`,
   `build-images` — confirm exact job names against `ci.yml`).
2. Leave `required_approving_review_count: 0` with an inline comment: "solo-founder; raise to 1 when a second
   maintainer exists" (a 1-review rule is unsatisfiable today). Note in the register that GitHub-side
   application is the human's step (the file is the source of truth, not the live setting).
3. No code; this is config + register.

**Acceptance:** the verify-all umbrella + key gates are in the required-checks list; review-count documented.
**Verify:** `python3 -c "import json;d=json.load(open('.github/rulesets/main.json'));print([c['context'] for r in d.get('rules',[]) for c in r.get('parameters',{}).get('required_status_checks',[])])"` shows the added contexts.
**Commit:** `ci(governance): require verify-all + scanner gates in branch protection (TEST-002)`

---

#### Sprint 13 — Hygiene bundle
**Closes:** SEC-006 (missing Referrer-Policy/Permissions-Policy), SUPPLY-007 (`go.work` 1.26 vs `go.mod`
1.26.4 skew), SCHEMA-001 (no down-migration policy). **Severity:** Low–Medium. Group into one commit.

**Tasks:**
1. SEC-006: add `Referrer-Policy: no-referrer` (or `strict-origin-when-cross-origin`) and a minimal
   `Permissions-Policy` in `internal/control/middleware.go` security headers; extend the headers test.
2. SUPPLY-007: align `go.work` to `go 1.26.4` (match `go.mod`) so there's no version skew.
   **DONE early** — pulled forward as a standalone build hotfix (it was failing the
   `build-fips` CI job under `GOTOOLCHAIN=local`); see CHANGELOG. This sprint now does
   only SEC-006 + SCHEMA-001.
3. SCHEMA-001: add a documented down-migration / rollback **policy** to `docs/` (probectl uses
   expand-contract forward-only migrations — document that explicitly as the deliberate choice + the manual
   rollback procedure; do not necessarily author `.down.sql` for 43 migrations).

**Acceptance:** new headers present + tested; go.work/go.mod aligned; migration rollback policy documented.
**Verify:** `go test ./internal/control/ -run "Header|Security" -v`; `head -12 go.work go.mod`.
**Commit:** `chore(hardening): security headers, go-version skew, migration rollback policy (SEC-006, SUPPLY-007, SCHEMA-001)`

---

#### Sprint 17 — Frontend AuthProvider → real session identity
**Closes:** SEC-001 (down-rated to Medium — product-maturity, not an auth bypass; backend enforces all access).
**Severity:** Medium. *(Numbered 17 to sit at the end of Phase C; it's `web/` work and larger than the others.)*

**Evidence (re-confirm):** `web/src/auth/AuthProvider.tsx:32` `DEMO_USER = {…demo@probectl.local}`; `:51`
`/* stub: real sign-out arrives with S18 sessions */`. The UI identity context is a demo stub; the backend
OIDC+session+RBAC are real and enforce every `/v1` call.

**Tasks:**
1. Wire `AuthProvider` to the real session: fetch identity from the existing `/v1/me`-style endpoint (confirm
   the route), reflect the logged-in user/tenant, and make `signOut` hit the real logout endpoint.
2. Remove `DEMO_USER`; handle the unauthenticated state (redirect to login).
3. Update/extend the frontend auth test (`web/src/.../security.test.tsx` or equivalent).

**Acceptance:** the UI shows the real authenticated identity and signs out via the backend; no demo creds.
**Verify:** `cd web && npm test` (vitest) for the auth context; `grep -rn "demo@probectl" web/src` → none.
**Commit:** `feat(web): wire AuthProvider to the real session identity (SEC-001)`

### Phase D — automatable compliance scaffolding (Decision D8: mechanical only; no binding legal text)

---

#### Sprint 14 — SPDX headers + NOTICE + third-party license inventory
**Closes:** LICENSE-003 (zero SPDX on ~895 first-party files), part of DATAROOM-003. **Severity:** High as
acquisition-prep (clean provenance), but mechanical. **Decision D8.**

**Evidence (re-confirm):** `grep -rl SPDX --include=*.go internal` → only the eBPF C files carry SPDX; no
`NOTICE` file (`ls NOTICE` → absent).

**Tasks:**
1. Add an `SPDX-License-Identifier:` header to first-party source files. **Blocked sub-decision:** the SPDX
   tag value depends on the license choice, which is a counsel decision (Appendix B). Default per D8: use a
   placeholder tag `SPDX-License-Identifier: LicenseRef-probectl-TBD` for core and the existing commercial
   placeholder for `ee/`, with a script (`scripts/add_spdx_headers.sh`) so a single value-swap finalizes them
   once counsel picks the license. Do NOT invent a real OSI license.
2. Generate a `NOTICE` file enumerating third-party dependencies + their licenses (from `go.mod`/`go.sum`
   via `go-licenses` or a scripted `go list -m -json all` + license lookup; pin the tool per supply-pins).
3. Commit the third-party inventory under `docs/diligence/` (or `licenses/`).

**Acceptance:** every first-party file carries an SPDX tag (placeholder, single-swap-finalizable); `NOTICE`
+ third-party inventory exist and are reproducible by a script.
**Verify:** `grep -rL "SPDX-License-Identifier" --include=*.go internal cmd pkg | wc -l` → 0; `ls NOTICE`.
**Commit:** `chore(legal-prep): SPDX headers (placeholder), NOTICE, third-party license inventory (LICENSE-003)`

---

#### Sprint 15 — DCO check in CI + CONTRIBUTING IP section
**Closes:** the automatable half of LICENSE-004 / GOV-002 (the binding CLA text is counsel — Appendix B).
**Severity:** Medium. **Decision D8.**

**Tasks:**
1. Add a DCO sign-off check to CI (a `Signed-off-by:` trailer gate on PR commits — a small, dependency-free
   workflow or the standard DCO action, SHA-pinned per supply-pins).
2. Add an IP/contributor section to `CONTRIBUTING.md`: require `git commit -s`, state the DCO 1.1 terms,
   and flag that a CLA may be required pending counsel.
3. Document (don't fix) the existing 230 unsigned commits + the `dev@netctl.local` provenance as a
   retroactive item for counsel (Appendix B) — the DCO gate applies going forward.

**Acceptance:** new commits must be signed-off; CONTRIBUTING states the IP/DCO policy.
**Verify:** the DCO workflow rejects an unsigned commit in a test PR (or `act`/dry-run); CONTRIBUTING updated.
**Commit:** `ci(governance): DCO sign-off gate + CONTRIBUTING IP policy (LICENSE-004)`

---

#### Sprint 16 — SBOM generation in CI
**Closes:** part of DATAROOM-003. **Severity:** Medium. **Decision D8.**

**Tasks:**
1. Add an SBOM job (CycloneDX or SPDX-JSON) to CI using a SHA-pinned tool (e.g. `syft` / `cyclonedx-gomod`),
   producing an SBOM artifact for Go (and optionally the web bundle).
2. Retain it as a CI artifact (data-room receipt), like the existing scan receipts.
3. Document where the SBOM lives.

**Acceptance:** every CI run produces a retained SBOM artifact covering the Go module graph.
**Verify:** `python3 -c "import yaml;yaml.safe_load(open('.github/workflows/ci.yml'))"`; the SBOM step + upload present.
**Commit:** `ci(supply): generate + retain an SBOM artifact (DATAROOM-003)`

---

## Appendix A — `[needs-infra]` deferred (stage-only; never fabricate)

These cannot be completed in this environment (no reference hardware, no live PG/CH/Kafka, no real kernel
matrix). Most are already staged by v1 sprints; the executor should leave them and not invent results:

- **L/XL scale run + numeric SLOs** (SCALE-004) — harness + `scale-gate` exist; the run is `make scale-gate
  TIER=L/XL` on reference hardware. Owner: human/iron.
- **Multi-region RTO/RPO drill** (RESIL-003 / OPS-007 / DATAROOM-008) — runbooks + CI dev-drill exist; the
  representative drill needs multi-region infra. PROVISIONAL banners stay until then. Owner: human/iron.
- **Live OTel-Collector exercise** (ARCH-006) — reference config + round-trip test exist; live exercise needs
  a running Collector + stack.
- **eBPF kernel-matrix LIVE load** (EBPF/FUZZ C-path) — `clang` absent here; runs in the QEMU CI job.
- **ClickHouse backup-volume encryption verification** (RED-008 residual) — server-side `BACKUP TO File` is
  encrypted by the volume (documented §0c); verifying it needs a live CH + encrypted volume.
- **ClickHouse replication / SPOF** (RESIL-004) — a deployment-topology change; document the recommended
  replicated topology, but standing it up is an ops/infra task.

## Appendix B — Legal / IP founder + counsel tasks (NOT code; the actual deal-blocker)

The dominant diligence blocker is legal, not engineering. These need the founder + counsel; the executor must
**not** draft binding legal text or pick a license:

- **Choose + commit the actual `LICENSE`** (currently `TBD`) — BSL/SSPL/Apache/etc. Once chosen, swap the SPDX
  placeholder from Sprint 14 in one pass.
- **Finalize the `ee/` commercial license text** (currently PLACEHOLDER) with counsel.
- **CLA + retroactive chain-of-title:** decide CLA-vs-DCO-only; obtain assignment/signoff covering the 230
  historical commits and the `dev@netctl.local` contributions.
- **Trademark** "probectl" (the open-core fence relies on it per `editions.md`).
- **SOC2 / ISO engagement** (COMPLY-001) — auditor engagement (6–12 mo), not code.
- **DPA / subprocessor docs** (COMPLY-004) and **data-handling / PII-minimization doc** (COMPLY-005) —
  counsel-reviewed; the drafts exist marked DRAFT.
- **Residency enforcement for pooled tenants** (COMPLY-003) — product decision (enforce vs disclose); siloed
  already region-pins. Scope before building.

## Appendix C — Verified-FALSE audit findings (document-only; do NOT remediate)

My verification (`00-AUDIT-VERIFICATION.html`) found these 8 to be false at `HEAD`; per the founder
decision they are recorded here for the paper trail and require **no work**. If a future re-audit raises any,
point at the evidence below.

| Audit ID | Audit claim | Why it's FALSE (evidence) |
|---|---|---|
| OPS-001 | backup CronJob nil-deref on undefined `backup.encryption` | The committed `ebafb8c` template had 0 `encryption` refs (audit scored the dirty working tree it said it would not score); at HEAD `values.yaml` defines the block. No nil-deref. |
| TENANT-002 | isolation suite not in CI → could regress | `.github/workflows/ci.yml:470` `cross-tenant-isolation` job runs `make test-isolation`; present at the audited commit. |
| AIRCA-002 | RCA eval non-blocking, not CI-gated | `ci.yml:182` "rca-eval (BLOCKING — floors 0.85/0.85)" `sys.exit(1)` on breach; present at audited commit. Audit read a stale test comment. |
| AIRCA-004 | fairness gate not wired to HTTP /v1/ai/ask | `handleAIAsk → beginQuery → fairnessGate.BeginQuery`; `WithFairness` wired in `main.go`. |
| SEC-009 | govulncheck blocked → Go CVEs unscanned | `govulncheck ./...` on go1.26 → "0 vulnerabilities"; was a session-tooling limit, not a code defect. |
| WIRE-008 | revocation list empty in a startup window | `main.go` runs `reload()` synchronously before `grpcSrv.Serve()`; no window. |
| EBPF-004 | `scope_tgids.Put` unhandled if map full | `source_live_l7_linux.go:168` returns a wrapped error on Put failure; cited line wrong. |
| LICENSE-007 | `web/node_modules` tracked in git | `git ls-files web/node_modules` → 0; `.gitignore:37`. Conflated on-disk dir with git tracking. |

*Also down-rate (not remove) these OVERSTATED severities in the registers when next revised: SEC-002 (/metrics
→ Low, D3), WIRE-001/002 (→ Low/Med), TENANT-001/006 (→ Med), AIRCA-001 (→ Low/Med), SCALE-002/006/009 (→
Low), CODE-002/004 (→ Low/Med), SUPPLY-003 (→ Low), DOCS-F01 (→ Med), THREAT-002 (→ Med), EBPF-003 (→ Low).*

## Appendix D — CODE-003 git-history blob cleanup (human decision)

~106 MB of orphaned blobs from a deleted `spike/` tree remain in git history (two ~53 MB objects). Cleaning
them requires rewriting history (`git filter-repo`/BFG) and a **force-push**, which only the human can do and
which invalidates existing clones. The executor must **not** rewrite history autonomously. Recommended: the
human runs the cleanup deliberately before any public-repo cutover; document the procedure but don't execute.

---

## Provenance

Sources: `probectl-audit/outputs/00-INVESTMENT-COMMITTEE-MEMO.html` + 25 domain registers, filtered through
`probectl-audit/outputs/00-AUDIT-VERIFICATION.html` (independent verification at `HEAD`). Severities here are
the verification's **corrected** severities. v1 (`REMEDIATION-SPRINT-PLAN.md`, sprints 0–27) remains the
history of prior work; this v2 covers what verification confirmed still open.
