# Air-gapped install (OPS-003)

probectl is built to run in networks with no internet egress (the sovereignty
posture — telemetry never leaves the operator's network, and there is no
phone-home). Each release publishes one signed tarball you carry across the air
gap; everything installs from it offline.

## Acquiring the bundle (connected side)

```sh
version=0.6.0
gh release download "v${version}" --repo ctlplne/probectl \
  --pattern "probectl-airgap-${version}.tar.gz*"
cosign verify-blob \
  --certificate "probectl-airgap-${version}.tar.gz.pem" \
  --signature "probectl-airgap-${version}.tar.gz.sig" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp '^https://github.com/ctlplne/probectl/\.github/workflows/release\.yml@refs/tags/' \
  "probectl-airgap-${version}.tar.gz"
```

The release workflow waits for every signed image, chart, Linux binary, deb, and
rpm job, downloads those release assets, and runs the builder. The builder
verifies before it bundles. By default it requires `cosign` and
refuses to package the Helm chart, release binaries, packages, or images unless
their signatures chain to the probectl release workflow. A break-glass bundle is
possible only with `PROBECTL_AIRGAP_VERIFY_COSIGN=0` plus
`PROBECTL_AIRGAP_UNVERIFIED_ACK=allow-unverified-airgap-artifacts`; record that
as an operator exception because those bytes can install privileged agents.

Maintainers can reproduce the assembly from the tagged checkout. An empty
checkout is not enough: first acquire the release inputs into `dist/`, then run
the builder, which also pulls the tagged images from GHCR:

```sh
version=0.6.0
git checkout "v${version}"
mkdir -p dist
gh release download "v${version}" --repo ctlplne/probectl --dir dist
docker login ghcr.io
DIST=dist make airgap-bundle VERSION="${version}"
# → probectl-airgap-0.6.0.tar.gz
```

The bundle contains:

- `images/` — every component image, `docker save`d from the cosign-verified
  immutable digest.
- `IMAGE-VERIFICATION.txt` — the component → digest ledger verified before the
  image tarballs were written.
- `charts/` — the signed, packaged, versioned Helm chart plus `.sig`/`.pem`
  evidence (appVersion == the release tag, OPS-001). When present, the
  `*.chart-digest.txt` file records the cosign-verified OCI chart digest that was
  pushed by the release workflow.
- `bin/` — the cross-compiled static agent/control binaries plus their `.sig`
  and `.pem` files.
- `packages/` — signed `.deb`/`.rpm` packages plus their `.sig` and `.pem`
  files.
- `packaging/` — the deb/rpm, systemd units, and Ansible role (OPS-004) for
  host installs.
- `MANIFEST.txt` — image, chart, binary, and package digests so the far side can
  confirm nothing was swapped in transit.
- `INSTALL.md` — this file.

## Installing (air-gapped side)

1. **Verify the manifest** against your expected digests. The connected-side
   bundle builder already ran `cosign verify` / `cosign verify-blob`; rerun the
   chart, package, and binary checks from docs/ops/verify-artifacts.md if your
   policy requires verification after transfer too.
2. **Load the images** into your in-cluster registry (or each node's runtime):
   ```
   for t in images/*.tar; do docker load -i "$t"; done
   # then docker tag + push to your internal registry, and set image.repository
   ```
3. **Install the control plane** from the bundled chart, pointing image
   repositories at your internal registry:
   ```
   helm install probectl charts/probectl-0.6.0.tgz \
     -f your-values.yaml \
     --set image.repository=registry.internal/probectl \
     --set-string image.digest='sha256:<internal-mirror-digest>'
   ```
   Use the digest produced by the internal registry after the verified image is
   pushed. The chart rejects a tag-only or missing digest.

   **What `your-values.yaml` must contain.** The chart fails closed on every
   security-critical value, so an install missing one refuses rather than
   starting weakened — and on the far side of an air gap you cannot look the list
   up. This is the minimum (DPR-142):

   ```yaml
   database:
     url: postgres://probectl@postgres.internal:5432/probectl?sslmode=verify-full
   control:
     tls:
       existingSecret: probectl-tls        # tls.crt / tls.key / ca.crt
   ingress:
     backendTLS:
       serverName: probectl.internal       # must match a SAN on that certificate
       trustSecret: probectl-internal-ca
   secrets:
     existingSecret: probectl-secrets      # or secrets.envelopeKey, a base64 32-byte KEK
   ```

   With those plus the two `--set` flags above, the chart renders and installs
   with **no network access at all** — verified by rendering it inside a
   container with no route to anywhere.
4. **Install agents** from `packaging/` (deb/rpm via the Ansible role, or the
   binaries in `bin/`), then enroll them against the control plane. The Ansible
   `airgap` method verifies the local package's `.sig` and `.pem` before the
   package manager sees it; a missing or tampered signature fails the play.

Nothing in this procedure reaches the internet. Open-data/threat-intel feeds are
optional and degrade gracefully when unreachable (guardrail 10), so an air-gapped
deployment runs fully without them.
