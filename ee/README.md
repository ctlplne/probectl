# `ee/` — the probectl commercial tree

Everything under `ee/` is commercial code: the provider/MSP plane, siloed
isolation, metering/billing export, white-label, BYOK/governance, and (after
its policy sign-off) guarded remediation. The legal license text is **TBD
with counsel**; until it lands, every file here carries the placeholder
commercial header from `ee/doc.go`.

The three rules (enforced by `make editions-gate` in CI):

1. **One-way imports.** `ee/` may import core packages. Core may **never**
   import `ee/` — `scripts/check_editions_imports.sh` fails the build on any
   violation.
2. **Core stands alone.** The core-only build (every package except `ee/...`)
   must pass the full suite. Nothing in core may depend on `ee/` existing.
3. **License-gated activation only.** Features here are constructed at the
   `main.go` `Build*` seams when `internal/license` grants the entitlement —
   no tier checks inside handlers or engines, ever (the feature→tier table in
   `internal/license` is the only one in the codebase).

See `docs/editions.md` for the full editions design.
