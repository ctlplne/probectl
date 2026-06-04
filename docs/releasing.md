# Releasing probectl

## Versioning scheme

probectl uses **Semantic Versioning** with a `v` prefix: `vMAJOR.MINOR.PATCH`.

- **MAJOR** — incompatible API / config / migration changes.
- **MINOR** — backward-compatible features.
- **PATCH** — backward-compatible fixes.

While the project is pre-1.0 the major stays `0` and the MINOR carries feature
weight (so a breaking change before 1.0 bumps the MINOR). **Phase 1 GA is
`v0.1.0`.** Pre-releases use a suffix, e.g. `v0.2.0-rc.1`.

The version is stamped into every binary at build time
(`internal/version`, via `-ldflags`) and surfaced at `/version` and
`probectl-control version`.

## What a release publishes

Pushing a `v*` tag triggers [`.github/workflows/release.yml`](../.github/workflows/release.yml),
which publishes:

- **Multi-arch container images** (`linux/amd64`, `linux/arm64`) for all five
  components — `probectl-control`, `probectl-agent`, `probectl-ebpf-agent`,
  `probectl-endpoint`, `probectl` — to `ghcr.io/imfeelingtheagi/<component>`, tagged
  with the exact version and `latest`. Each image carries **SLSA provenance and
  an SBOM** attestation (Buildx `provenance` + `sbom`).
- **Cross-compiled binaries** for `linux/{amd64,arm64}` plus a `checksums.txt`
  (SHA-256), attached to the GitHub release.
- An auto-generated **release notes** entry.

Image tags follow `ghcr.io/imfeelingtheagi/probectl-control:v0.1.0` (and `:latest`).
Pin the exact version in production deploys (compose `PROBECTL_IMAGE`, Helm
`image.tag`).

## Cutting a release

1. Ensure `main` is green (all CI gates, including `openapi-gate`,
   `cross-tenant-isolation`, `perf-smoke`, and `helm-lint`).
2. Tag and push:

   ```sh
   git tag -a v0.1.0 -m "Phase 1 GA"
   git push origin v0.1.0
   ```

3. The `release` workflow builds and publishes the images, binaries, and GitHub
   release. Verify the images and attestations appear under Packages.

## Provenance & supply chain

Images ship with build provenance and an SBOM attestation. Dependency and image
vulnerability scanning run in CI (`dependency-scan`, `image-scan`). Signing the
release artifacts with cosign (keyless / OIDC) is a planned hardening step layered
on the existing `id-token` permission.
