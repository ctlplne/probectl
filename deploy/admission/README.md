# Admission policies

These manifests are optional cluster-side admission controls for regulated or
provider deployments. They do not phone home and they are not required for a
single-node dev stack.

## probectl eBPF agent image integrity

`probectl-agent-image-integrity.kyverno.yaml` makes the privileged eBPF agent
fail closed at admission unless the image is:

- referenced with an immutable digest, and
- signed by the `imfeelingtheagi/probectl` release workflow running on a tag.

The Helm chart already refuses tag-only eBPF-agent images unless
`image.allowTagOnly=true` is set as explicit break-glass. This policy is the
cluster-side second lock: it catches retags or registry mirrors that serve a
different image than the digest/signature the operator approved.
