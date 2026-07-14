# Editions & licensing

probectl is **open-core**: the core platform is open source under MPL-2.0 and
free, while the commercial Enterprise and MSP tiers are gated.
This document is the engineering contract for how that split is enforced in the
codebase.

The one-sentence version: **it is one repo with one binary lineage and no edition
branches — the commercial boundary is a license file plus a directory fence, never
a fork.** Everything below is an elaboration of that sentence.

The source-license boundary is final: first-party core files outside `ee/` are
**MPL-2.0**, while `ee/` is governed by its separate commercial license. MPL's
Exhibit B incompatibility notice is not used. See
[`../LICENSING.md`](../LICENSING.md) for the file-level rules and contributor
expectations; runtime tier checks do not alter either source license.

## The model in one paragraph

Commercial source lives in the top-level **`ee/`** tree under a commercial license
header. When the repo goes public, `ee/` is publicly *readable* — the fence is the
license and trademark, not source secrecy (the same model GitLab and CockroachDB
use). Imports are strictly **one-way**: `ee/` may import core, but **core may never
import `ee/`**. CI enforces that, and a "core-only" build must compile and pass its
tests with `ee/` absent from the link. At runtime, a commercial feature activates
only when an **offline-verifiable, Ed25519-signed license file** grants it
(Ed25519 is a modern public-key signature scheme: the vendor signs the license
with a private key only it holds; the binary verifies with a public key it
carries). Verification is local math against public keys baked in at build time
— it **never phones home**.

Why this shape? Three goals at once: keep the platform genuinely open and
auditable; let a single binary serve both the free and paid cases without a
separate "enterprise edition" download; and make "we don't phone home" a claim you
can *check by reading the open code*, not just trust.

## Tiers and the feature→tier table

There is exactly **one** feature→tier table in the whole codebase:
`tierFeatures` in `internal/license/license.go`. Tier knowledge is never
duplicated anywhere else, so there is a single source of truth.

The buyer-facing boundary follows that table. The full five-plane core is free.
Enterprise is a flat-rate self-hosted license: the customer bears its own
infrastructure cost, so one Enterprise entitlement opens every non-resale
`ee/` capability. MSP is consumption-priced for self-hosted resale under the
**probectl** banner. Its usage basis is the existing tenant-scoped meters, which
the operator exports deliberately; no meter is ever transmitted by probectl.
The public plan summary lives in [`pricing.md`](pricing.md).

| Tier | Gated features |
|---|---|
| `core` | None — everything not listed below is core and free forever. |
| `enterprise` | `fips` (a build artifact, see below), `byok`, `governance`, `remediation`, `ha_support` (displayed as HA support/SLA), `siloed_isolation` |
| `msp` | The complete Enterprise set, plus `provider_plane` and `metering` for resale operations. |

`ha_support` is a support/SLA and assurance entitlement, not the high-availability
runtime itself. The control plane can run the documented HA reference deployment
in core; Enterprise buys the validated support path around that operation.

**Read MSP as a strict superset.** Every MSP tenant receives the Enterprise
capabilities, and the MSP additionally gets the separately privileged provider
plane and metering/export surface. Enterprise does **not** get those two resale
operations: a self-hoster administers its own deployment and does not resell a
tenant service. `pricing_model` is descriptive metadata only; all enforcement
still comes from this one tier table and the `Build*` seams.

**Some capabilities are deliberately core (free), even though they sound
commercial:**

- Per-tenant data export and verifiable deletion — a *compliance right*, not a
  product to sell. This is the exit/no-lock-in posture: a tenant can export its
  records and prove deletion in core, while OTLP export remains an
  operator-controlled data portability path.
- Fairness *enforcement* — it protects the shared pooled platform, so everyone
  gets it. (The provider-console *views* of fairness live in `ee/`.)
- Support-bundle *generation* — the tool is core; the support SLA is a contract,
  not a code gate.

And "Starter/Pro" pricing tiers need **no code gating at all**: they are
entitlement (support/SLA) tiers riding the same core binary.

**`fips` is the one exception to runtime gating.** The FIPS 140-3 build is gated by
the **artifact**, not by a `lic.Has(fips)` check — there is *no* runtime license
gate for FIPS anywhere in the binary. The validated distribution is what you build
with `make build-fips` (which sets `GOFIPS140` and the `probectl_fips` tag); that
build embeds the FIPS 140-3-validated Go Cryptographic Module, and *being that
build* is the entitlement. The `fips` row in the table simply documents which tier
that distribution belongs to. A running binary reports its FIPS posture on
`/v1/editions` (build tag, live module state, self-test result) purely as a status
indicator. The exact validation claim boundary is in [`hardening.md`](hardening.md).

## The license file

A license is a small JSON envelope: base64 of the exact signed payload bytes
plus a detached Ed25519 signature (no JSON canonicalization games — the same
JSON can be serialized many byte-different ways, so probectl signs and verifies
the *encoded bytes themselves*: the bytes that were signed are the bytes that
are verified).

```json
{
  "payload": "<base64 of the claims JSON>",
  "signature": "<base64 Ed25519 signature over those exact bytes>"
}
```

The claims inside:

```json
{
  "v": 1,
  "id": "lic_2026_0001",
  "customer": "Reseller GmbH",
  "tier": "msp",
  "pricing_model": "consumption",
  "tenant_band": 25,
  "issued_at": "2026-06-05T00:00:00Z",
  "expires_at": "2027-06-05T23:59:59Z"
}
```

- `tier` implies its feature set from the one table; `features` lists explicit
  bespoke extras on top.
- `pricing_model` is informational and accepts `flat` or `consumption`. When it
  is absent, Enterprise implies `flat` and MSP implies `consumption`. It never
  grants a capability. Existing signed v1 development licenses using the old
  `provider` tier continue to verify and normalize in memory to `msp`.
- `tenant_band` is the licensed tenant-count band (`0` or absent = unlimited).
  It is enforced at tenant *provisioning* time (the provider plane refuses to
  create a tenant past the band, with `tenant_band_exhausted`), and is **never**
  a kill-switch on already-running telemetry.
- Verification rejects: an unknown payload version, an unknown or `core` tier
  (core needs no license at all), an invalid pricing model, a signature that fails against every
  trusted key, and an inverted validity window (expiry before issue). An
  **expired license still loads** — expiry is a *state*, not a parse error (see
  the ladder below).

## Trust anchor: build-time only

Trusted public keys are **baked at build time** via ldflags — the Go linker's
`-X` flag, which stamps a string value into a variable as the binary is linked —
into `internal/license.builtinPubKeysB64` (comma-separated base64 PEMs, so keys
can rotate by baking two). The trust anchor is **never** an env var, config key,
or file — otherwise anyone could point a build at their own key. The lock is
cast into the door at the factory; a key slot the operator could swap would let
anyone bring their own lock.

```sh
go build -ldflags "-X github.com/imfeelingtheagi/probectl/internal/license.builtinPubKeysB64=<base64 PEM>[,<base64 PEM>]" ./cmd/probectl-control
```

Dev builds bake no keys: unconfigured deployments run Core; a
*configured* license file against a keyless build fails startup loudly
(fail closed — a license you cannot verify is a misconfiguration, not a
shrug).

## Signing CLI (`cmd/probectl-license`)

Vendor-side tooling; never shipped in customer images.

```sh
# 1) Generate the signing pair (private key 0600; prints the ldflags bake line)
probectl-license gen-key -out-priv signing.key -out-pub signing.pub

# 2) Sign a license (expiry = end-of-day UTC)
probectl-license sign -key signing.key -customer "Reseller GmbH" \
  -tier msp -pricing-model consumption -tenant-band 25 \
  -expires 2027-06-05 -out license.json

# 3) Verify against a public key (what the control plane does at startup)
probectl-license verify -file license.json -pub signing.pub

# 4) Inspect WITHOUT verifying (clearly labeled as unverified)
probectl-license inspect -file license.json
```

## Runtime states: the expiry ladder

The guiding principle here: **an expired license must never break your
observability.** A monitoring tool that goes dark the day a contract lapses is a
liability during exactly the kind of incident you bought it for. So expiry
degrades commercial *write* paths gradually and leaves the telemetry pipeline
untouched.

`PROBECTL_LICENSE_FILE` points the control plane at the license (see
[`configuration.md`](configuration.md)). The states, in order:

| State | When | Behavior |
|---|---|---|
| `community` | No license configured | Tier is `core`; commercial features are hidden. |
| `active` | Within validity | Granted features `enabled`. |
| `grace` | 0–30 days past expiry | Features stay `enabled`; the UI banners the deadline. |
| `read_only` | >30 days past expiry | Granted features degrade to `read_only`: existing views still render, but **no new tenants or config**; **telemetry pipelines never break**. Expired is not the same as broken observability. |

In code, this is why there are two methods: `Manager.Has(f)` stays true in
`read_only` (so read paths still construct and serve), while `Manager.Mode(f)`
distinguishes `enabled` / `read_only` / `off` for *write* gating.

## Gating pattern (the only sanctioned shape)

Tier checks are wired **only at the `main.go` `Build*` seams** — never inside
handlers, engines, or stores. The concrete seam is one file:
**`cmd/probectl-control/ee_attach.go`** (the only file the editions guard
allowlists for importing `ee/`), which **must** carry the `//go:build
!probectl_core` tag:

```go
// ee_attach.go (build !probectl_core) — the ONE place core meets ee/.
func attachEE(srv *control.Server, ..., lic *license.Manager, ...) error {
    if lic.Has(license.FeatureProviderPlane) {   // one Has() per feature
        h, err := provider.Build(cfg, provider.Deps{...})
        if err != nil { return err }
        srv.WithProviderPlane(h)                 // core sees an opaque http.Handler
    }
    // ... one more `if lic.Has(...)` block per commercial feature ...
    return nil
}
```

The trick that makes "core stands alone" literally true: there is a no-op twin,
`ee_attach_core.go`, tagged `//go:build probectl_core`, whose `attachEE` does
nothing. The core-only build (`-tags probectl_core`, which is what `make
editions-gate` compiles) links that twin and therefore pulls in **zero** `ee/`
packages — you can verify it directly with `go list -tags probectl_core -deps
./cmd/probectl-control | grep /ee` (the output is empty). One binary lineage, two
link sets; in the default build, activation stays license-gated.

Scattering `if licensed` checks through business logic is a review-blocking
defect, because every such check is one more place a bug could become a licensing
*bypass* or — worse — a *core regression*. Keeping all the checks at one seam
keeps that surface tiny. (A licensed feature may still consult `Mode(feature)`
internally to implement its *own* read-only degrade — that is the feature's
behavior, not gating.)

## Unlicensed UX

Commercial features are **hidden** when unlicensed — no lockware (features
rendered visibly locked mainly to advertise an upgrade), no upsell
chrome. The single exception is **Admin → Editions** (`/v1/editions`, the
`EditionsCard`): it renders the license state and the full feature→tier map
so an operator can see what exists and what their file grants.

## CI: the editions gate

`make editions-gate` is a standing CI job. It does two things:

1. `scripts/check_editions_imports.sh` — greps for any core import of
   `…/probectl/ee/…`, allowing ONLY the `ee_attach.go` seam (and only when it
   carries `//go:build !probectl_core`); runs its own `SELFTEST=1` (plants
   violations, asserts detection) so the guard can never silently rot.
2. Builds and tests the **core-only package set with `-tags probectl_core`**
   (everything except `ee/...`, linking the no-op attach twin) — proving core
   stands alone with `ee/` truly absent from the link.

## Auditability

`internal/license` is **core** (not `ee/`) on purpose: "verification is
offline, there is no phone-home" is a checkable claim only if the code that
makes it is in the open part of the tree. The verify path does file reads and
Ed25519 math — no sockets.

## What this is not

- Not DRM: a determined fork can delete the checks. The fence is the
  commercial license + trademark; the gate is for honest customers.
- Not a kill-switch: no state in the ladder ever stops ingestion, probing,
  alerting, or dashboards that already exist.
- Not finalized commercial legal text: the core [`LICENSE`](../LICENSE) is the
  final, unmodified MPL-2.0 text. The bespoke `ee/LICENSE`, commercial headers,
  reseller terms, DPA/MSA, and open-data resale review remain counsel work. The
  enforcement mechanics above are complete independently of that review.
