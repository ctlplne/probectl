# Verifying release artifacts

## What this is

Before you run a probectl binary or trust a release, you want proof that *this
repository's release workflow* built it — not a fork, not a tampered copy. This
page is how you check that proof. An **artifact** is anything a release ships —
a binary, a checksum manifest, an SBOM — and a **signature** is the
cryptographic mark that lets you verify who produced it.

Releases from **v0.5.0** onward sign every binary and the `checksums.txt`
manifest with **cosign keyless** (Sigstore); earlier releases predate signing and
carry no `.sig`/`.pem` at all. Check *What each published release carries* below
before you run a recipe — a recipe cannot verify a signature the release does not
ship. "Keyless" means there is no long-lived private key to
leak: the release workflow signs using its GitHub OIDC identity (the
machine-checkable "who am I" token GitHub issues to a running workflow),
Sigstore's Fulcio issues a **short-lived certificate** bound to that identity
(the `.pem` next to each artifact), and the signature is recorded in the public
**Rekor** transparency log. Fulcio is a notary who checks the workflow's ID and
stamps a certificate valid for minutes; Rekor is the public ledger every stamp
lands in, so a stamp can't be quietly forged or backdated later. What you
verify, then, is the *identity that signed* — that the artifact came from
`ctlplne/probectl`'s `release.yml` running on a release tag — and
nothing else. The distinction matters: any seal proves a letter was sealed; the
crest on the wax tells you *whose hand* sealed it, and the crest is what you
check here.

Each release ships, per artifact: the artifact itself, `<artifact>.sig`,
`<artifact>.pem`, plus one `checksums.txt` (a manifest of every artifact's
SHA-256 **checksum** — a fingerprint that changes if even one byte changes —
itself signed the same way).

## What each published release carries

What the GitHub releases and GHCR hold **today** — not what the release workflow
is capable of. The two are different, and only this table is safe to plan
against.

| Release | Binaries + `checksums.txt` | Helm chart | Container images |
|---|---|---|---|
| v0.1, v0.1.0, v0.2.1, v0.3.0, v0.4.0 | published, **unsigned** (no `.sig`/`.pem` assets) | not published | published, **no cosign signature** |
| v0.5.0 | published and **cosign-signed** — 48 assets: 16 artifacts, 16 `.sig`, 16 `.pem` | not published | published, **no cosign signature** |
| v0.6.0 … v0.6.5 | **not published** | not published | not published |

Nothing published so far carries a signed Helm chart, a signed deb/rpm, or a
cosign-signed image. Those three are wired into the release workflow and
self-verified there, but `publish helm chart (OCI)` and `deb/rpm packages` have
never completed successfully, and image signing was added to the release
workflow after v0.5.0 — the images that exist were pushed before it, and carry
buildx SLSA provenance + SBOM attestations instead of a cosign signature. The
v0.6.x tags exist as source milestones; their release runs stop at the
capability-ledger gate, so they publish nothing.

Treat a missing `.sig` as **"this is not signed"**, never as "the signature is
somewhere else, proceed anyway".

## Verify (copy-paste)

```sh
# 0. Install cosign: https://docs.sigstore.dev/cosign/system_config/installation/
TAG=v0.5.0   # a release that ships .sig/.pem — see the table above
BIN=probectl-agent_${TAG}_linux_amd64
BASE=https://github.com/ctlplne/probectl/releases/download/${TAG}

curl -fsSLO ${BASE}/${BIN} -O ${BASE}/${BIN}.sig -O ${BASE}/${BIN}.pem \
     -O ${BASE}/checksums.txt -O ${BASE}/checksums.txt.sig -O ${BASE}/checksums.txt.pem

# 1. The signature must chain to THIS repo's release workflow on a release tag.
cosign verify-blob \
  --certificate ${BIN}.pem \
  --signature   ${BIN}.sig \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp \
    "^https://github.com/ctlplne/probectl/\.github/workflows/release\.yml@refs/tags/" \
  ${BIN}

# 2. Same check for the manifest, then verify the binary's checksum against it.
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature   checksums.txt.sig \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp \
    "^https://github.com/ctlplne/probectl/\.github/workflows/release\.yml@refs/tags/" \
  checksums.txt
sha256sum --ignore-missing -c checksums.txt
```

Both `cosign verify-blob` calls print `Verified OK`, and `sha256sum -c` prints
`<artifact>: OK`. **Anything else: do not run the binary.**

For `probectl-ebpf-agent`, also inspect the Go build metadata after signature and
checksum verification:

```sh
go version -m ${BIN} | grep -E 'build[[:space:]]+-tags=.*ebpf'
```

The release workflow performs the same check before signing the download and
before wrapping it into deb/rpm packages; no match means the binary is the
fixture-only build and must not be installed as the live host agent.

### What the identity pin actually proves

The `--certificate-identity-regexp` says: Fulcio bound this signing certificate
to the workflow `release.yml` in `ctlplne/probectl`, running for a
`refs/tags/...` ref, authenticated by GitHub's OIDC issuer. A fork, a different
workflow in the same repo, or a re-signed binary all fail that regexp match —
which is exactly the guarantee you want.

## License trust anchor

A control plane can only accept a commercial license file if the build carries
the vendor's public key. Confirm it on the binary you are about to deploy:

```sh
./probectl-control version      # whichever control-plane binary you are deploying
# probectl-control <version> (commit …)
# license trust anchors: 1      ← 0 means a keyless build: Community only
```

The same number is served as `trust_anchors` by `GET /v1/editions` once the
control plane is running (Admin → Editions in the UI).

## Helm chart

The release also signs the packaged Helm chart as a blob and signs the pushed OCI
chart artifact by immutable digest. No release has published a signed chart yet (see the table above), so set `TAG`
to the first release whose assets include `probectl-<version>.tgz`. The recipe is
then exactly the binary one:

```sh
TAG="${TAG:?set this to a release whose assets include the chart package}"
CHART=probectl-${TAG#v}.tgz
BASE=https://github.com/ctlplne/probectl/releases/download/${TAG}

curl -fsSLO ${BASE}/${CHART} -O ${BASE}/${CHART}.sig -O ${BASE}/${CHART}.pem
cosign verify-blob \
  --certificate ${CHART}.pem \
  --signature   ${CHART}.sig \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp \
    "^https://github.com/ctlplne/probectl/\.github/workflows/release\.yml@refs/tags/" \
  ${CHART}
```

For the OCI chart, verify the digest the release recorded:

```sh
curl -fsSLO ${BASE}/probectl-${TAG#v}.chart-digest.txt
CHART_REF="$(cat probectl-${TAG#v}.chart-digest.txt)"
cosign verify \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp \
    "^https://github.com/ctlplne/probectl/\.github/workflows/release\.yml@refs/tags/" \
  "${CHART_REF}"
```

Both checks must verify before you install from the chart. The air-gap bundle
uses the same signed chart package bytes and refuses to build when the `.sig` or
`.pem` files are absent.

## SBOM

Each release also publishes `probectl_<tag>_sbom.spdx.json` — an SPDX-JSON
**software bill of materials** (an ingredients list for the software: every Go
and npm dependency plus the source tree, so when the next library vulnerability
is announced you grep the list instead of guessing what's inside), generated by
syft at release time. It ships with its own `.sig` and `.pem` and verifies with
the **same** `cosign verify-blob` invocation as any binary above. Feed it
straight into your SCA / license tooling.

The release workflow also signs container images by immutable digest, and every
image it pushes is verified there before the release publishes. **No image in
GHCR carries that signature yet** — the images that exist were pushed before
image signing was added (see the table above), so `cosign verify` on them will
not find a signature; they carry buildx SLSA provenance + SBOM attestations,
which you inspect with `docker buildx imagetools inspect`. From the first
release that publishes signed images, resolve the digest you will deploy and
verify that exact reference:

```sh
IMG=ghcr.io/ctlplne/probectl-ebpf-agent:${VERSION:?set this to the image version you are deploying}
DIGEST="$(docker buildx imagetools inspect "$IMG" --format '{{.Manifest.Digest}}')"
cosign verify \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp \
    "^https://github.com/ctlplne/probectl/\.github/workflows/release\.yml@refs/tags/" \
  "ghcr.io/ctlplne/probectl-ebpf-agent@${DIGEST}"
```

Images also carry SLSA provenance + SBOM attestations — an **attestation** is a
signed statement attached to the image, and **provenance** is the one that says
*how and where* it was built (`docker buildx` with `provenance: true,
sbom: true`). Inspect them with `docker buildx imagetools inspect`.

## The release self-checks too

After signing, the release workflow runs `cosign verify-blob` on its **own**
artifacts, including the packaged Helm chart, and `cosign verify` on every
pushed image and chart digest before publishing. A release whose artifacts do not
verify simply does not publish — so from v0.5.0 onward, a published asset that
ships a `.sig` is one the workflow already verified itself. That is a statement
about the assets a signing release publishes, not about every release ever cut:
the pre-v0.5.0 releases published nothing to verify. This is why the copy-paste
block above can be trusted to work:
it isn't parallel documentation that could drift from the release process; it
*is* the release's own exit gate, run from your side.

## The installers verify for you (SUPPLY-002)

You don't have to run `cosign verify-blob` by hand — the installers do it,
fail-closed, before anything lands on the host:

- **`install.sh`**: before copying the eBPF agent binary into place it runs the
  exact `cosign verify-blob` check above, pinned to the probectl release-workflow
  identity. It looks for `<binary>.sig` + `<binary>.pem` next to the binary
  (override with `PROBECTL_COSIGN_SIG` / `PROBECTL_COSIGN_CERT`). If cosign is
  missing, the signature/cert are absent, or verification fails, it refuses to
  install — an unsigned or tampered binary never reaches `/usr/local/bin`.
  `--no-verify` is break-glass only and requires
  `PROBECTL_UNVERIFIED_INSTALL_ACK=allow-unsigned-cap-bpf-code`.

- **The Ansible role** (`probectl_agents`), `package_url` install method: when
  `probectl_verify_cosign: true` (the default) it downloads the package's `.sig`
  and `.pem`, runs `cosign verify-blob` (identity pinned via
  `probectl_cosign_identity_regexp`), and only installs if it passes. A
  tampered package fails the play *before* the install task runs.

- **The Ansible role**, `airgap` install method: it verifies the copied local
  package with the bundled `<package>.sig` and `<package>.pem` before invoking
  the package manager. This is the offline equivalent of the `package_url`
  verifier: a tampered USB/mirror copy stops before install.

`apt`/`yum` repo installs rely instead on the repository's own signed-metadata
trust (the `signed-by=` keyring), which apt/dnf enforce on every fetch.

For Kubernetes, the privileged eBPF-agent Helm chart renders the Kyverno
image-integrity policy by default. In clusters that manage admission separately,
apply the standalone GitOps form at
`deploy/admission/probectl-agent-image-integrity.kyverno.yaml`. Either path
enforces digest references plus the same keyless release workflow identity for
the privileged eBPF-agent image at admission time.
