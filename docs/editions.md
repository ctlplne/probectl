# Editions & licensing (S-T0)

probectl ships as **one repo, one binary lineage, no edition branches**. The
commercial boundary is a license file plus a directory fence — never a fork.
This document is the engineering contract for that boundary: the rules every
later sprint (S-T1+, S-EE1+) builds against.

## The model in one paragraph

Commercial source lives in the top-level **`ee/`** tree under a commercial
license header; when the repo goes public, `ee/` is publicly readable (the
GitLab/CockroachDB model — the fence is the license + trademark, not source
secrecy). Imports are **one-way**: `ee/` may import core, **core may never
import `ee/`** — CI enforces this and the core-only build must stay green with
`ee/` absent or inert. At runtime, commercial features activate only when an
**offline-verifiable Ed25519-signed license file** grants them. Verification
is local math against build-time-baked public keys — **never phone-home**.

## Tiers and the feature→tier table

There is exactly **one** feature→tier table, in `internal/license`
(`tierFeatures`). Never duplicate tier knowledge anywhere else.

| Tier | Features |
|---|---|
| `community` | Everything not listed below — the full core, free forever. |
| `enterprise` | `fips` (distribution-gated build), `byok`, `governance`, `remediation` (S-EE5, still policy-sign-off-gated), `ha_support` |
| `provider` | All enterprise features, plus `provider_plane`, `siloed_isolation`, `metering`, `white_label` |

**Deliberately core (free), per the ratified decisions:** per-tenant export /
verifiable deletion (S-T5 — a compliance right, not a product), fairness
*enforcement* (S-T7 — protects the pooled platform; provider-console *views*
are `ee/`), and support-bundle *generation* (S-EE4 — the tool is core, the
support entitlement is contract). **Starter/Pro pricing tiers need no code
gating at all** — they are entitlement (support/SLA) tiers on the same core
binary.

**`fips` is the exception to runtime gating (S-EE1).** The FIPS 140-3 build is
gated by the **artifact**, not a `lic.Has(fips)` check — there is no runtime
license gate for FIPS anywhere in the binary. The validated distribution
(`make build-fips`, `GOFIPS140` + the `probectl_fips` tag) is the Enterprise
deliverable; the `fips` table row documents that entitlement. A running binary
reports its FIPS posture on `/v1/editions` under `fips` (build tag, live module
state, self-test result) as a status indicator only. See `docs/hardening.md`.

## The license file

A license is a small JSON envelope: base64 of the exact signed payload bytes
plus a detached Ed25519 signature (no JSON canonicalization games — the bytes
that were signed are the bytes that are verified).

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
  "tier": "provider",
  "features": ["byok"],
  "tenant_band": 25,
  "issued_at": "2026-06-05T00:00:00Z",
  "expires_at": "2027-06-05T23:59:59Z"
}
```

- `tier` implies its feature set from the one table; `features` lists
  *explicit extras* on top (e.g. a one-off grant).
- `tenant_band` is the licensed tenant count band (informational until S-T1
  consumes it; never an enforcement kill-switch on running telemetry).
- Verification rejects: unknown payload version, unknown or `community` tier
  (community needs no license), a signature that fails against every trusted
  key, and an inverted validity window. An **expired license still loads** —
  expiry is a *state*, not a parse error (see the ladder below).

## Trust anchor: build-time only

Trusted public keys are **baked at build time** via ldflags into
`internal/license.builtinPubKeysB64` (comma-separated base64 PEMs, so keys can
rotate by baking two). The trust anchor is **never** an env var, config key,
or file — otherwise anyone could point a build at their own key.

```
go build -ldflags "-X github.com/imfeelingtheagi/probectl/internal/license.builtinPubKeysB64=<base64 PEM>[,<base64 PEM>]" ./cmd/probectl-control
```

Dev builds bake no keys: unconfigured deployments run Community; a
*configured* license file against a keyless build fails startup loudly
(fail closed — a license you cannot verify is a misconfiguration, not a
shrug).

## Signing CLI (`cmd/probectl-license`)

Vendor-side tooling; never shipped in customer images.

```
# 1) Generate the signing pair (private key 0600; prints the ldflags bake line)
probectl-license gen-key -out-priv signing.key -out-pub signing.pub

# 2) Sign a license (expiry = end-of-day UTC)
probectl-license sign -key signing.key -customer "Reseller GmbH" \
  -tier provider -tenant-band 25 -expires 2027-06-05 -out license.json

# 3) Verify against a public key (what the control plane does at startup)
probectl-license verify -file license.json -pub signing.pub

# 4) Inspect WITHOUT verifying (clearly labeled as unverified)
probectl-license inspect -file license.json
```

## Runtime states: the expiry ladder

`PROBECTL_LICENSE_FILE` points the control plane at the license (see
`docs/configuration.md`). States, in order:

| State | When | Behavior |
|---|---|---|
| `community` | No license configured | Default-open core; commercial features hidden. |
| `active` | Within validity | Granted features `enabled`. |
| `grace` | 0–30 days past expiry | Features stay `enabled`; the UI banners the deadline. |
| `read_only` | >30 days past expiry | Granted features degrade to `read_only`: existing views render, **no new tenants/config**; branding persists; **telemetry pipelines never break**. Expired ≠ broken observability. |

`Manager.Has(f)` stays true in `read_only` (read paths still construct);
`Manager.Mode(f)` distinguishes `enabled` / `read_only` / `off` for write
gating.

## Gating pattern (the only sanctioned shape)

Tier checks are wired **only at the `main.go` `Build*` seams** — never inside
handlers, engines, or stores. Since S-T1 the seam is concrete:
**`cmd/probectl-control/ee_attach.go`** (the one file allowlisted by the
editions guard), which MUST carry `//go:build !probectl_core`:

```go
// ee_attach.go (build !probectl_core) — the ONE place core meets ee/.
func attachEE(srv *control.Server, ..., lic *license.Manager, ...) error {
    if lic.Has(license.FeatureProviderPlane) {   // one Has() per feature
        h, err := provider.Build(cfg, provider.Deps{...})
        if err != nil { return err }
        srv.WithProviderPlane(h)                 // core sees an opaque http.Handler
    }
    return nil
}
```

`ee_attach_core.go` (`//go:build probectl_core`) is the no-op twin: the
core-only build (`-tags probectl_core`, what `make editions-gate` builds)
links **zero** `ee/` packages — verifiable with
`go list -tags probectl_core -deps ./cmd/probectl-control | grep /ee` (empty).
One binary lineage, two link sets; runtime activation stays license-gated in
the default build.

Scattering `if licensed` checks through business logic is a review-blocking
defect: it multiplies the surface where a bug becomes a licensing bypass or,
worse, a core regression. (A licensed feature may still consult
`Mode(feature)` internally to implement its OWN read-only degrade — that is
behavior of the feature, not gating.)

## Unlicensed UX

Commercial features are **hidden** when unlicensed — no lockware, no upsell
chrome. The single exception is **Admin → Editions** (`/v1/editions`, the
`EditionsCard`): it renders the license state and the full feature→tier map
so an operator can see what exists and what their file grants.

## CI: the editions gate

`make editions-gate` (a standing CI job from S-T0 on):

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
- Not finalized legal text: `LICENSE` stays a TBD placeholder and `ee/` files
  carry a commercial-header *placeholder* until counsel delivers the real
  texts (human-owned decision).
