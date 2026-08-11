# Capability completeness gate

`capabilities.yaml` is probectl's machine-checked wiring ledger. It answers a
simple buyer question: **can an operator actually reach every shipped
capability, or does some engine exist only in source/tests?**

The denominator is exact, not aspirational. The independent
`docs/claims/completeness-denominator.json` policy declares the inclusive
`F1`–`F57` range and the governed `CLM-*` claims. Every declared ID must appear
once as `kind: capability` in the strict-schema
`docs/claims/release-catalog.json`, then once in `capabilities.yaml` with the
same owner. Reclassifying a required catalog row, adding a capability outside
the policy, omitting a row, duplicating an ID, or changing an owner fails the
gate.

## Wiring cells

Each capability declares all of these cells:

| Cell | Evidence checked by the gate |
|---|---|
| `engine` | Repository-relative implementation file or package containing non-test production syntax selected by the default Linux/amd64 build. Comments, fixtures, tests, empty declarations, and excluded build-tag files do not count. |
| `binary` | Shipping `cmd/` assembly or `internal/control/` runtime wiring plus a literal capability-specific constructor/attach/route/consumer anchor. A generic server-entrypoint anchor is not accepted as feature wiring. |
| `api` | An operation in the core or provider OpenAPI document, or a protocol string in live default-build Go dispatch reachable from an exported package entrypoint. Unparsed non-Go file claims are rejected. |
| `cli` | A command in the executable CLI catalog. Generated groups share dispatcher data; explicit handlers are followed for the exact operation; special test/agent commands are intersected with their actual switch cases. The generic delegate must still reach the real HTTP client. |
| `ui` | An exact feature-ID, `native` kind, and route in the executable `SURFACES` array in `web/src/surfaces.ts`. |
| `docs` | A repository document plus a visible literal anchor; HTML/Markdown comments do not count. |
| `config_keys` | Every applicable exact `PROBECTL_*` key in `docs/configuration.md`; prose substrings and HTML comments are rejected. |
| `telemetry` | Non-test production syntax that emits a structured log/metric/signal or declares a substantive telemetry model. Names and strings alone do not count. |
| `real_stack_proof` | An exact Go `Test…` function bound to this capability in `test/real-stack-proofs.json`, assigned to an integration/E2E/live-kernel/live-device profile, and executed by the corresponding CI runner. |
| `migration` | A SQL file under `migrations/` containing executable DDL/DML for state owned by the capability. Keywords inside comments or quoted strings do not count. |

A cell that genuinely does not apply uses `none_by_design` with a precise
reason. A known not-done cell uses `gap` and requires
`evidence_status: partial` on its capability. A gap remains visible, does not
count as spine coverage, and must be replaced by evidence before the final
100% completeness claim. Empty cells, short reasons, and cells containing more
than one of `refs`, `none_by_design`, or `gap` fail. `none_by_design` is a
disposition, not a shortcut: it must explain why an operator does not need that
surface or artifact, and the exact `<capability>.<cell>` key must be present in
`docs/claims/completeness-none-by-design.json`. That policy is bidirectional:
an unapproved registry exclusion and an unused preapproval both fail. `gap` is
the machine-readable form of “not done,” not an excuse to borrow an unrelated
test.

Evidence references are repository-relative and offline. The gate rejects path
escapes and every symlink component, and validates the declared file location,
literal anchor, OpenAPI operation, CLI command, UI route, configuration key, or exact test ID
against the current checkout. The registry is pinned to the canonical release
catalog, while the independent denominator policy prevents that catalog from
silently shrinking or reclassifying required rows. Both policy JSON documents
reject unknown fields, duplicate object keys, and trailing content. Invalid
registries do not render a ledger, so an uploaded artifact can never label
unvalidated references as wired.

A UI reference normally uses the same feature ID as its capability row. The
gate lexes the executable TypeScript array rather than searching source text;
comments, prose strings, nested/dynamic entries, computed fields, and object
spreads cannot impersonate or override evidence. When a
shared native surface genuinely exposes another capability's workflow, that
row must name the other feature ID under `ui_aliases` and give a specific
reason. Undeclared cross-capability reuse fails. The ledger renders approved
aliases and their reasons beside the UI cell and emits them as a feature-ID
sorted `ui_aliases` array in JSON, so shared surfaces cannot silently disguise
a missing operator workflow.

CLI evidence follows the exact first subcommand through every explicit
handler. A branch that shadows only `ai author`, for example, invalidates that
operation even if another `ai` operation still reaches the shared fallback.
The top-level config/flag-parser prelude, special `test`/`agent` entry spines,
and custom `ai ask`, `lifecycle export`, and `test create` request handlers are
bound to canonical executable AST bodies. The shared `cmdSurface` spine is
structurally bound to its exact operation-map lookup, raw-operation delegate,
and tenant-scoped HTTP client call. This rejects early returns, local callee or
catalog shadows, protected config/argument rewrites (including aliases), wrong
endpoints, and unmodelled request-side effects; a live catalog name cannot
conceal a dead implementation body.

Binary reachability checks are intentionally bounded static evidence, not a
runtime execution claim. For a shipping `cmd/` package, the gate builds the
default Linux/amd64 package selected by Go build constraints and follows typed
package-local calls from `main` and `init`. A literal anchor must occur in a
reachable call, assignment, or composite-literal assembly node. The analysis
resolves package constants and excludes compile-time-dead `if`/`switch`
branches, code after terminal return/panic/goto paths, unreachable statements
after unconditional break/continue, and short-circuited operands. Comments,
string literals, unused function values, and excluded build-tag files do not
count. A
`#func Name` anchor must also name the exact reachable top-level declaration in
the referenced file. Selector calls resolve only to a method on the inferred
local receiver type, so an imported or unrelated same-named method cannot make
a seam reachable. `internal/control/` evidence is accepted only after the
control binary reaches `control.New`; the declared assembly node must then be
reachable from that constructor inside `internal/control`. Complete selector
call anchors bind the exact callee and ordered arguments, so passing a named
factory to an unrelated formatter is not registration evidence. Real execution and
other release architectures remain the job of the independently bound
real-stack proof, cross-build gates, and delivery audit.

Real-stack references have an additional anti-gaming boundary. The strict
`test/real-stack-proofs.json` allowlist binds each exact test ID to the
capability it is allowed to prove and to one of four execution profiles:
`integration`, black-box `e2e`, `ebpf-kernel`, or `device-live`. The validator
checks the exact Go test declaration; evaluates profile build constraints both
with and without the required positive tag; verifies executable env guards in
the test AST; rejects empty, immediate-return, and unconditional-skip proof
bodies; associates Make recipes with the required target and root-module
`./...` package scope; and reads the required GitHub Actions job's actual
blocking `steps[].run` command. Comments, negated or misplaced build tags,
disabled/dynamic job or step conditions, `continue-on-error`, early exits,
failure masking, echo-only decoys, narrowed package runs, and commands moved to
an unrelated job/target do not count. Swapping a capability to an unrelated
unit test—or even to another capability's cataloged integration test—fails.
Cataloging is necessary but not sufficient: the independent semantic audit
still turns fixture-, mock-, or component-only tests into explicit gaps when
they do not reproduce the promised operator outcome.
The existing dead-seam, route/OpenAPI, CLI/OpenAPI, surface-coverage, isolation,
and migration gates remain authoritative and are not weakened by this ledger.

## Run it

```sh
make completeness-gate
```

The target performs three checks:

1. runs the completeness package tests;
2. plants both a missing CLI cell and an unapproved `none_by_design` cell and
   proves the production validator rejects them, then confirms a governed
   exclusion remains accepted;
3. validates the live registry and writes deterministic artifacts to
   `dist/completeness/ledger.json` and `dist/completeness/ledger.html`.

CI runs the same target and retains both ledgers as the
`capability-completeness-ledger` artifact. The command is deterministic and
performs no network calls. The inventory gate exits successfully for an honest
`gap` declaration but prints `VALID, INCOMPLETE`; this means the registry is
machine-valid, not that the product has 100% coverage. Final release uses the
strict form, which fails until every gap is replaced:

```sh
make completeness-release-gate
```

For direct debugging:

```sh
go run ./cmd/probectl-completeness -selftest
go run ./cmd/probectl-completeness \
  -ledger-json dist/completeness/ledger.json \
  -ledger-html dist/completeness/ledger.html
```

`-selftest` is deliberately standalone; combining it with `-require-complete`
or either ledger-output flag is a usage error. This prevents a mutation test
from being mistaken for a release validation or from overwriting evidence.

## Updating a capability

Update `capabilities.yaml` in the same change as the feature. Add concrete
evidence for every new surface and keep `docs/configuration.md` synchronized
with configuration keys. A schema change needs its sequential idempotent
migration and real-stack tenant-isolation proof in the same change.

`status` records the product-contract state (`delivered`, `partial`, `future`,
or `removed`). Evidence completeness is deliberately separate:
`evidence_status` defaults to `complete`, while `partial` requires at least one
explicit `gap` cell. This prevents a missing receipt from silently rewriting a
delivered product claim, and prevents an unrelated integration test from making
that claim look proven. `fully_dispositioned` in the JSON summary means every
cell is either wired or genuinely none-by-design; a row with a gap is not fully
dispositioned even though the structural validator accepts its honest,
machine-readable declaration.

The registry proves static reachability. A `VERIFIED` completeness-loop claim
also requires the independent delivery audit: release artifact, real stores,
actual CLI, rendered UI, bidirectional tenant-isolation probes, and an
exact-SHA receipt. A green static ledger alone is never delivery proof.
