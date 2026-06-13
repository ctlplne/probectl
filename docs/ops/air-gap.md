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

The bundle contains:

- `images/` — every component image, `docker save`d from its digest-pinned tag
  (reproducible; signature-verifiable on the far side).
- `charts/` — the packaged, versioned Helm chart (appVersion == the release tag,
  OPS-001).
- `bin/` — the cross-compiled static agent/control binaries.
- `packaging/` — the deb/rpm, systemd units, and Ansible role (OPS-004) for
  host installs.
- `MANIFEST.txt` — the image digests, so the far side can confirm nothing was
  swapped in transit.
- `INSTALL.md` — this file.

## Installing (air-gapped side)

1. **Verify the manifest** against your expected digests (and `cosign verify`
   the images/packages against the bundled certs — verification works offline
   with the bundled material; see docs/ops/verify-artifacts.md).
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
   binaries in `bin/`), then enroll them against the control plane.

Nothing in this procedure reaches the internet. Open-data/threat-intel feeds are
optional and degrade gracefully when unreachable (guardrail 10), so an air-gapped
deployment runs fully without them.
