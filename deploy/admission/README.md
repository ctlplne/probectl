# Admission policies

These manifests are the standalone GitOps form of the cluster-side admission
controls. The privileged eBPF-agent Helm chart renders its image-integrity
policy by default; keep these files for clusters that manage admission policy
separately from workload charts. They do not phone home.

## probectl eBPF agent image integrity

`probectl-agent-image-integrity.kyverno.yaml` is a Kyverno `ClusterPolicy` that
makes the privileged eBPF agent fail closed at admission unless the image is:

- referenced with an immutable digest, and
- signed by the `imfeelingtheagi/probectl` release workflow running on a tag.

The Helm chart already refuses tag-only eBPF-agent images unless
`image.allowTagOnly=true` is set as explicit break-glass, and the chart now
renders this policy unless `admission.imageIntegrity.enabled=false` is paired
with an `acceptedRisk` note. This policy is the cluster-side second lock: it
catches retags or registry mirrors that serve a different image than the
digest/signature the operator approved.
