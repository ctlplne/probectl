# Go toolchain provenance

## What this is

When you run `go build`, *something* has to be the Go compiler. This page is
about **which Go that is, where it comes from, and how we know it wasn't
tampered with**. The short version: probectl builds with the **official upstream
Go release**, pinned to one exact patch version, downloaded and cryptographically
verified the same way any Go dependency is. There is no custom, forked, or
vendored compiler hiding in this repo.

The version is named in two places that are kept in lockstep:

- [`go.mod`](../../go.mod) — `go 1.26.4`. This is the language/version floor for
  the main module.
- [`go.work`](../../go.work) — `go 1.26.4` **and** an explicit `toolchain go1.26.4`
  line. (See "Why the explicit toolchain line" below — it is not redundant.)

## How it works

- **Acquisition.** A `go` directive that names a version newer than the running
  Go triggers Go's *toolchain management*: it downloads the named toolchain from
  the canonical module mirror (`proxy.golang.org`) exactly like it fetches any
  module, then verifies it against the **public Go checksum database**
  (`sum.golang.org`) before it ever runs. A swapped, corrupted, or
  man-in-the-middled toolchain fails that checksum and refuses to execute — the
  build stops instead of silently using an untrusted compiler.

- **Pinning.** Because the directive names the *exact patch* (`1.26.4`, not a
  loose `1.26`), every developer machine and every CI runner resolves to the
  same compiler. CI's `setup-go` step is pinned to the same `1.26.4`
  (`.github/workflows/ci.yml`, `GO_VERSION: "1.26.4"`), so there is literally one
  toolchain everywhere, by construction.

- **Why this patch level.** `1.26.4` is pinned *forward* deliberately: it carries
  upstream **standard-library security fixes** (the `crypto/x509` and
  `net/textproto` advisories) that `govulncheck` would otherwise flag. Bumps land
  through the normal pull-request + green-CI path, never out of band.

## Why it's built this way

- **Exact-patch pinning keeps `govulncheck` honest.** `govulncheck` attributes
  standard-library vulnerabilities by Go version. A bare `go 1.26` scans as
  `1.26.0` and would false-flag every already-patched stdlib CVE; naming `1.26.4`
  makes the scan reflect the real, patched toolchain. (This is also why `go.mod`
  carries the patch version — see the comment at the top of `go.mod`.)

- **Why the explicit `toolchain` line in `go.work`.** The patched stdlib is the
  *minimum* every build must use. `go.work` must not name an older Go than the
  modules' `go.mod`, or Go rejects the workspace whenever it cannot auto-resolve
  a newer toolchain — which is exactly the case under `GOTOOLCHAIN=local`, the
  mode the FIPS distribution build runs in (`make build-fips`). Keeping the
  `go.work` `go` line and `toolchain` line in sync with `go.mod` is what stops
  that build from breaking.

- **No vendored or forked toolchain exists in this repository.** Provenance is
  upstream-official plus checksum-database-verified — full stop. That is the
  point: anyone auditing the build can reproduce it from a public, signed
  toolchain rather than trusting a binary we shipped.
