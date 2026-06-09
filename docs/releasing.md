# Releasing probectl

## What a release is

A probectl release is **one git tag** that triggers an automated pipeline to
build, sign, and publish the shipping artifacts: multi-arch container images,
cross-compiled binaries with checksums, software bills of materials (SBOMs), and a
GitHub Release. You do not build or upload anything by hand — you push a tag, and
[`.github/workflows/release.yml`](../.github/workflows/release.yml) does the rest.

## Versioning scheme

probectl uses **Semantic Versioning** with a `v` prefix: `vMAJOR.MINOR.PATCH`.

- **MAJOR** — incompatible API / config / migration changes.
- **MINOR** — backward-compatible features.
- **PATCH** — backward-compatible fixes.

While the project is pre-1.0, the major stays `0` and the **MINOR** carries the
feature weight (so a breaking change before 1.0 bumps the MINOR). Pre-releases use
a suffix, e.g. `v0.2.0-rc.1`.

The version is stamped into every binary at build time
(`internal/version`, via `-ldflags`) and surfaced at the `/version` HTTP endpoint
and via `probectl-control version`. So a running binary can always tell you
exactly which tag it was cut from.

## What a release publishes

Pushing a `v*` tag runs `release.yml`, which publishes:

- **Multi-arch container images** (`linux/amd64`, `linux/arm64`) for five
  components — `probectl-control`, `probectl-agent`, `probectl-ebpf-agent`,
  `probectl-endpoint`, and `probectl` (the CLI) — to
  `ghcr.io/imfeelingtheagi/<component>`, tagged with the exact version and
  `latest`. Each image carries **SLSA provenance and an SBOM** attestation
  (Buildx `provenance: true` + `sbom: true`). The `probectl-ebpf-agent` image is
  built from `deploy/docker/Dockerfile.ebpf` so it ships the *live* eBPF loader,
  not the fixture replayer.
- **Cross-compiled binaries** for `linux/{amd64,arm64}` plus a `checksums.txt`
  (SHA-256), attached to the GitHub Release.
- A **source SBOM** in SPDX JSON (`probectl_<tag>_sbom.spdx.json`), generated over
  the source tree and lockfiles and shipped as a signed release asset.
- **Keyless cosign signatures** (`.sig` + `.pem`) over every binary, the checksum
  manifest, and the SBOM. The signing identity is this repository's release
  workflow (Sigstore/Fulcio, GitHub OIDC); the same job re-verifies its own
  signatures before finishing, so a release that cannot be verified fails the
  build. Verifiers pin the workflow identity — see
  [`ops/verify-artifacts.md`](ops/verify-artifacts.md).
- An auto-generated **release notes** entry on the GitHub Release.

Image tags follow `ghcr.io/imfeelingtheagi/probectl-control:<version>` (and
`:latest`). **Pin the exact version in production deploys** — compose
`PROBECTL_IMAGE`, Helm `image.tag` — and digest-pin for full immutability (see
[`dependency-policy.md`](dependency-policy.md)).

## Cutting a release

The release pipeline will not build anything unless the **full CI workflow already
concluded green on the exact commit you are tagging** (the `require-green-ci`
gate). Tag pushes do not trigger CI, so this gate looks up the CI run for the
tagged commit and refuses to publish on an untested or red commit. Practically,
that means: get the commit green on `main` first, *then* tag it.

1. Confirm CI is green on the commit you intend to tag — that single CI run
   includes every gate (`cross-tenant-isolation`, `openapi-gate`, `migration-gate`,
   `helm-gate`, `perf-smoke`, and the rest; see
   [`development.md`](development.md) for the full job list).
2. Tag and push:

   ```sh
   git tag -a v0.1.0 -m "Phase 1 GA"
   git push origin v0.1.0
   ```

3. The `release` workflow builds and publishes the images, binaries, SBOMs, and
   GitHub Release. Confirm the images and their attestations appear under the
   repository's Packages, and that the release assets include the `.sig`/`.pem`
   signatures.

## Provenance & supply chain

Every released artifact is **verifiable end to end**: images ship build provenance
and an SBOM attestation; binaries, checksums, and the source SBOM are
cosign-signed (keyless / OIDC) and self-verified inside the release job.
Dependency and image vulnerability scanning run in CI on every PR
(`dependency-scan`, `image-scan`) and weekly on a schedule
([`.github/workflows/security-scan.yml`](../.github/workflows/security-scan.yml)),
so a vulnerable pin surfaces even when no release is in flight. For how to verify
a downloaded artifact, see [`ops/verify-artifacts.md`](ops/verify-artifacts.md).
