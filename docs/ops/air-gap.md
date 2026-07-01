# Air-gapped install (OPS-003)

probectl is built to run in networks with no internet egress (the sovereignty
posture — telemetry never leaves the operator's network, and there is no
phone-home). `make airgap-bundle` produces one tarball you carry across the air
gap; everything installs from it offline.

## Building the bundle (connected side)

```
make airgap-bundle VERSION=0.2.0
# → probectl-airgap-0.2.0.tar.gz
```

The builder verifies before it bundles. By default it requires `cosign` and
refuses to package the Helm chart, release binaries, packages, or images unless
their signatures chain to the probectl release workflow. A break-glass bundle is
possible only with `PROBECTL_AIRGAP_VERIFY_COSIGN=0` plus
`PROBECTL_AIRGAP_UNVERIFIED_ACK=allow-unverified-airgap-artifacts`; record that
as an operator exception because those bytes can install privileged agents.

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
   helm install probectl charts/probectl-0.2.0.tgz \
     -f your-values.yaml --set image.repository=registry.internal/probectl
   ```
4. **Install agents** from `packaging/` (deb/rpm via the Ansible role, or the
   binaries in `bin/`), then enroll them against the control plane. The Ansible
   `airgap` method verifies the local package's `.sig` and `.pem` before the
   package manager sees it; a missing or tampered signature fails the play.

Nothing in this procedure reaches the internet. Open-data/threat-intel feeds are
optional and degrade gracefully when unreachable (guardrail 10), so an air-gapped
deployment runs fully without them.
