# License trust anchors

Every `*.pub` file in this directory is an **Ed25519 public key** (PEM) that
`internal/license` compiles into every probectl binary with `go:embed`. A
license file signed by the matching private key is accepted by any build made
from this tree — release image, source build, or air-gap bundle — with no
build-time plumbing. The public key is not a secret; the private signing key
is, and it never enters this repository.

- **Issue a keypair (vendor, offline):** `probectl-license gen-key -out-priv
  signing.key -out-pub signing.pub`, keep `signing.key` in the vendor's
  offline vault, then commit `signing.pub` here as `probectl-<year>.pub`.
- **Rotate:** commit the new key beside the old one; retire the old file only
  after every issued license has been re-signed.
- **Verify a build:** `probectl-control version` prints
  `license trust anchors: N`; `GET /v1/editions` reports `trust_anchors`.
- **Release gate:** `scripts/check_license_trust_anchor.sh --release` (the
  `license-trust-anchor` job in `release.yml`) refuses to publish a build that
  carries no anchor — from this directory or from the
  `PROBECTL_LICENSE_PUBKEYS_B64` link-time variable.

A tree with no `.pub` here and nothing linked is a **keyless build**: it runs
the free core, and a configured license file fails startup loudly
(`license: no trusted license keys are baked into this build`). See
`docs/editions.md`, "Trust anchor: build-time only".
