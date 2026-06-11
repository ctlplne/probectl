# `ee/` — the probectl commercial tree

Everything under `ee/` is commercial code: the provider/MSP plane, siloed
isolation, metering/billing export, white-label, BYOK/governance, and guarded
(human-gated) remediation. The directory name is the "enterprise edition"
convention GitLab and CockroachDB use — one repository, with the paid features
fenced into a single *readable* subtree (the fence is the license, not source
secrecy), never a private fork. The legal license text is still being finalized
with counsel; until it lands, every file here carries the placeholder commercial
header from `ee/doc.go`.

```text
ee/
├── provider/      # provider / management plane (tenant lifecycle, fleet, break-glass)
├── silo/          # siloed / hybrid per-tenant isolation
├── billing/       # per-tenant metering + usage/billing export
├── whitelabel/    # per-tenant white-label
├── tenantkeys/    # per-tenant keys / BYOK (builds on internal/crypto)
├── governance/    # governance controls (e.g. AI egress policy)
├── remediation/   # guarded, human-gated remediation
├── web/           # commercial UI source (aliased @ee in web/)
└── doc.go         # the placeholder commercial-license header
```

The three rules (enforced by `make editions-gate` in CI):

1. **One-way imports.** `ee/` may import core packages. Core may **never**
   import `ee/` — `scripts/check_editions_imports.sh` fails the build on any
   violation.
2. **Core stands alone.** The core-only build (every package except `ee/...`)
   must pass the full suite. Nothing in core may depend on `ee/` existing.
3. **License-gated activation only.** Features here are constructed at the
   `main.go` `Build*` seams — concretely `cmd/probectl-control/ee_attach.go`,
   the one file the import guard allowlists — when `internal/license` grants
   the entitlement. No tier checks inside handlers or engines, ever (the
   feature→tier table in `internal/license` is the only one in the codebase).

The shape to keep in your head is a one-way valve: dependencies flow from core
into `ee/`, never back. If core ever imported `ee/`, the free build would have
a paid-shaped hole in it — so the guard makes the reverse direction a CI
failure, and the core-only build proves the valve holds by compiling with
`ee/` absent from the link entirely (a no-op twin of the attach seam,
`cmd/probectl-control/ee_attach_core.go`, takes its place under
`-tags probectl_core`).

See `docs/editions.md` for the full editions design.
