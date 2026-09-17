# Releasing probectl

## What a release is

A probectl release is **one git tag** — a named, immutable pointer to one
exact commit — that triggers an automated pipeline to
build, sign, and publish the shipping artifacts: multi-arch container images
(one image name carrying variants for both CPU architectures), cross-compiled
binaries (built on one machine *for* other platforms) with checksums (SHA-256
fingerprints a downloader can recompute to prove the bytes arrived unaltered),
software bills of materials (**SBOMs** — machine-readable parts lists of every
dependency baked into an artifact), and a
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
(`internal/version`, via `-ldflags` — linker flags that write values into the
binary's variables as it is linked) and surfaced at the `/version` HTTP endpoint
and via each binary's local `version` command (the Terraform provider answers
this before starting its plugin handshake). So a running artifact can always
tell you exactly which tag or untagged source version it was cut from.

The core OpenAPI artifact follows the same product version: `info.version` in
`internal/control/openapi.json` must match the repo-root `VERSION` exactly. The
REST API major is carried by the URL namespace (`/v1/...`), so a client can read
`info.version` as "which probectl release produced this schema" while using the
path prefix to reason about API-major compatibility. `make openapi-gate` rejects
release/spec drift before code generation or publishing.

`scripts/check_version_consistency.sh` also compares `VERSION` numerically with
the greatest stable `vMAJOR.MINOR.PATCH` tag reachable from `HEAD`. It rejects a
source version older than an existing release, even when all files agree on the
same stale value. The CI checkout for this gate fetches full tag history so a
shallow clone cannot hide that release floor.

`make print-version` shows the exact validated version that `make build` will
stamp. On an untagged source commit, Make reads the repo-root `VERSION`; on an
exact `v...` release tag, the normalized tag is authoritative. Resolution is
fail-closed: an empty or malformed file/tag/override stops Make before a binary
can be linked. The consistency gate runs planted untagged, exact-tag, empty, and
malformed cases against this real Make resolver, so the fallback cannot silently
regress to an empty stamp.

## What a release publishes

Pushing a `v*` tag runs `release.yml`, which publishes:

- **Multi-arch container images** (`linux/amd64`, `linux/arm64`) for all nine
  components — `probectl-control`, `probectl-agent`, `probectl-ebpf-agent`,
  `probectl-endpoint`, `probectl-flow-agent`, `probectl-device-agent`,
  `probectl-cloud-metrics`, `terraform-provider-probectl`, and `probectl` (the
  CLI) — to
  `ghcr.io/ctlplne/<component>`, tagged with the exact version and
  `latest`. Each image is **cosign-keyless signed by immutable digest** and
  carries **SLSA provenance and an SBOM** attestation (Buildx
  `provenance: true` + `sbom: true`). **SLSA provenance** is a signed build
  receipt — *which* workflow, on *which* commit, with *which* inputs, produced
  these bytes — and an **attestation** is such a statement cryptographically
  attached to the image, so a cluster or auditor can demand it before trusting
  the artifact. The `probectl-ebpf-agent` image is built from
  `deploy/docker/Dockerfile.ebpf` so it ships the *live* eBPF loader, not the
  fixture replayer.
- **Cross-compiled binaries** for `linux/{amd64,arm64}` plus a `checksums.txt`
  (SHA-256), attached to the GitHub Release. `probectl-ebpf-agent` is not built
  by the plain cross-compile loop: the release builder regenerates `vmlinux.h`,
  runs `internal/ebpf/gen_bpf.sh` + `gendigests`, builds with `-tags ebpf`, and
  fails before signing unless `go version -m` records the `ebpf` build tag.
- A **source SBOM** in SPDX JSON (`probectl_<tag>_sbom.spdx.json`), generated over
  the source tree and lockfiles and shipped as a signed release asset.
- **Keyless cosign signatures** (`.sig` + `.pem`) over every binary, the checksum
  manifest, and the SBOM. **cosign** is the Sigstore signing tool, and
  **keyless** means no long-lived private key exists to steal or leak: the
  workflow proves who it is via GitHub **OIDC** (the same short-lived identity
  tokens cloud logins use), Sigstore's certificate authority (**Fulcio**)
  issues it a minutes-lived signing certificate, and that certificate (the
  `.pem`) ships alongside the signature (the `.sig`). Image signatures use the
  same keyless identity but are attached to the image digest in the registry. It
  works like a notary who checks your government ID at the desk and stamps the
  document right there — verification later trusts the recorded identity, not a
  house key that could have been copied years ago. The signing identity is this
  repository's release workflow (Sigstore/Fulcio, GitHub OIDC); the same job
  re-verifies its own signatures before finishing, so a release that cannot be
  verified fails the build. Verifiers pin the workflow identity — see
  [`ops/verify-artifacts.md`](ops/verify-artifacts.md).
- An auto-generated **release notes** entry on the GitHub Release.
- A **license trust anchor** in every control-plane artifact: the committed
  `internal/license/trusted_keys/*.pub` keys (plus the optional
  `PROBECTL_LICENSE_PUBKEYS_B64` repository variable) are what let a shipped
  binary accept a commercial license file. The `license-trust-anchor` job
  refuses to build anything from a keyless tree, and the binaries job runs the
  built `probectl-control version` and requires `license trust anchors: N` with
  `N ≥ 1` (see [`editions.md`](editions.md), "Trust anchor: build-time only").

Image tags follow `ghcr.io/ctlplne/probectl-control:<version>` (and
`:latest`) for discovery. Production deploys use immutable references: Compose
requires digest-pinned `PROBECTL_IMAGE`, and Helm requires the signed digest in
`image.digest` (see [`dependency-policy.md`](dependency-policy.md)).
GHCR package visibility is an operator-facing install contract, not something
Compose can repair at startup: if a release image is not public, the install docs
must say to authenticate (`docker login ghcr.io` with `read:packages`) or use a
mirrored `PROBECTL_IMAGE`. If the repository setting
`PROBECTL_COMPOSE_IMAGE_PUBLIC=true` is enabled, `release.yml` runs an
anonymous-pull smoke against the exact image pinned in
[`deploy/compose/probectl.yml`](../deploy/compose/probectl.yml) after publishing.

## Cutting a release

The release pipeline will not build anything unless the **full CI workflow already
concluded green on the exact commit you are tagging** (the `require-green-ci`
gate). Tag pushes do not trigger CI, so this gate looks up the CI run for the
tagged commit and refuses to publish on an untested or red commit — it holds even
for a tag cut off a side branch or by an admin who bypassed branch protection
(branch protection guards the *merge*; this gate independently guards the
*release* — two locks on two different doors, so picking one still leaves the
other shut; see [`ops/branch-protection.md`](ops/branch-protection.md)).
After that check, `completeness-release-gate` runs at the tagged SHA and refuses
to build images or binaries while the capability ledger contains any declared
not-done gap. Ordinary CI can retain an honest incomplete ledger; publishing
requires 100% coverage.
Practically, that means: get the commit green on `main` first, *then* tag it.
A release also needs a **license trust anchor**: at least one
`internal/license/trusted_keys/*.pub` committed (or the
`PROBECTL_LICENSE_PUBKEYS_B64` repository variable set). Check locally with
`bash scripts/check_license_trust_anchor.sh --release` before tagging; a keyless
tree is refused before any artifact is built.

1. Preview the notes from the previous release and review the visible
   `Other changes` section for any commit that does not use a recognized
   Conventional Commit type:

   ```sh
   bash scripts/release_notes.sh "$(git describe --tags --abbrev=0)" HEAD
   ```

   The preview accounts for every non-merge commit exactly once; it never
   silently drops an unconventional subject.
2. Confirm CI is green on the commit you intend to tag — that single CI run
   includes every gate (`cross-tenant-isolation`, `openapi-gate`, `migration-gate`,
   `helm-gate`, `perf-smoke`, and the rest; see
   [`development.md`](development.md) for the full job list).
3. Tag and push:

   ```sh
   git tag -a v0.1.0 -m "probectl v0.1.0"
   git push origin v0.1.0
   ```

4. The `release` workflow builds and publishes the images, binaries, SBOMs, and
   GitHub Release. Confirm the images and their attestations appear under the
   repository's Packages, and that the release assets include the `.sig`/`.pem`
   signatures.

## Provenance & supply chain

Every released artifact is **verifiable end to end**: images are cosign-signed
by digest and ship build provenance plus an SBOM attestation; binaries,
checksums, and the source SBOM are cosign-signed (keyless / OIDC) and
self-verified inside the release job. The deb/rpm package job repeats the
`go version -m` check for `probectl-ebpf-agent` before wrapping the binary, so a
package cannot accidentally ship the fixture-only loader.
Dependency and image vulnerability scanning run in CI on every PR
(`dependency-scan`, `image-scan`) and weekly on a schedule
([`.github/workflows/security-scan.yml`](../.github/workflows/security-scan.yml)),
so a vulnerable pin surfaces even when no release is in flight. For how to verify
a downloaded artifact, see [`ops/verify-artifacts.md`](ops/verify-artifacts.md).
