# Admission policies

These manifests are the standalone GitOps form of the cluster-side admission
controls. The privileged eBPF-agent Helm chart renders its image-integrity
policy by default; keep these files for clusters that manage admission policy
separately from workload charts. They do not phone home.

## probectl eBPF agent image integrity

`probectl-agent-image-integrity.kyverno.yaml` is a Kyverno `ClusterPolicy` that
makes the privileged eBPF agent fail closed at admission unless the image is:

- referenced with an immutable digest, and
- signed by the `ctlplne/probectl` release workflow running on a tag.

The Helm chart already refuses tag-only eBPF-agent images unless
`image.allowTagOnly=true` is set as explicit break-glass, and the chart now
renders this policy unless `admission.imageIntegrity.enabled=false` is paired
with an `acceptedRisk` note. This policy is the cluster-side second lock: it
catches retags or registry mirrors that serve a different image than the
digest/signature the operator approved.

The verifyImages rule enforces per rule (`failureAction: Enforce`; Kyverno's
spec-level `validationFailureAction` is deprecated) and the policy uses
`failurePolicy: Fail`, so an unreachable Kyverno refuses rather than admits.
This static copy only matches `ghcr.io/ctlplne/probectl-ebpf-agent*` and
`*/ctlplne/probectl-ebpf-agent*`; the chart's copy derives its reference from
`image.repository`. For a mirror with a different path, render the policy from
the chart (`helm template ... --show-only templates/image-integrity-policy.yaml`)
or add the mirror's pattern — an unmatched image is not verified at all. Apply
it and wait for `Ready` before the agent DaemonSet exists:
[Image-integrity admission](../../docs/deploying-agents.md#image-integrity-admission-kubernetes).
