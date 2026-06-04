# IaC, GitOps & Helm hardening (S35 · F29)

probectl ships a declarative, secure-by-default deployment stack: a hardened Helm
chart, Terraform modules that wrap it, and ArgoCD/Flux manifests so a `git push`
is the only deploy action. Everything is HTTPS-by-default and refuses to run with
default credentials.

```mermaid
flowchart LR
  subgraph Git
    V[values overlay\nsmall/medium/large]
  end
  V --> TF[Terraform module] --> H[Helm chart]
  V --> GO[ArgoCD / Flux] --> H
  H --> K[Kubernetes:\nDeployment · Service · Ingress(HTTPS)\nNetworkPolicy · PDB · HPA]
```

## Three ways in (one chart)

| Path | Use it when | Where |
| ---- | ----------- | ----- |
| **Helm** | manual / scripted installs | `deploy/helm/probectl` |
| **Terraform** | infra-as-code alongside cluster + DB | `deploy/terraform/` |
| **GitOps** (ArgoCD/Flux) | continuous reconcile from Git | `deploy/gitops/` |

All three deploy the **same** hardened chart — Terraform and GitOps just wrap it.

## Hardened Helm chart

`values.schema.json` types every key (Helm validates it on install/upgrade). The
secure defaults (enforced by the CI hardening gate, `make helm-gate`):

| Control | Default |
| ------- | ------- |
| Pod identity | non-root, pinned uid/gid **65532**, `fsGroup` set |
| Container | `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, **drop ALL** caps, seccomp `RuntimeDefault` |
| Service account | token automount **off** (no Kubernetes API access) |
| Ingress | HTTPS-only, **HSTS**, HTTP→HTTPS redirect, ClusterIP service (no plaintext API) |
| Credentials | render **fails** without an envelope key (no default creds); secrets via `existingSecret` |
| Probes | readiness `/readyz` (flips to 503 while draining, S34), liveness `/healthz` |
| Disruption | `PodDisruptionBudget` (medium/large/multitenant) for zero-downtime upgrades |
| Network | default-deny `NetworkPolicy` (large profile; opt-in elsewhere) |
| Scale | `HorizontalPodAutoscaler` (large profile; omits the Deployment's replicas) |

### Reference sizing (S/M/L)

| Profile | File | Replicas | PDB | HPA | NetworkPolicy |
| ------- | ---- | -------- | --- | --- | ------------- |
| small | `values-small.yaml` | 1 | – | – | – |
| medium | `values-medium.yaml` | 3 | minAvailable 2 | – | available (opt-in) |
| large | `values-large.yaml` | 4 → HPA 4–12 | minAvailable 3 | on | on |
| provider | `values-multitenant.yaml` | 3 + anti-affinity | minAvailable 2 | – | – |

```bash
helm install probectl deploy/helm/probectl -f deploy/helm/probectl/values-medium.yaml \
  --set ingress.host=probectl.example.com --set ingress.tlsSecretName=probectl-tls \
  --set secrets.envelopeKey="$(openssl rand -base64 32)"
```

## Config-as-code

The declarative config IS the Helm values: `control.*`, `oidc.*`, `database.url`,
and `control.extraEnv` map to `PROBECTL_*` env via the chart's ConfigMap; the size
overlays are the reference config. Commit your overlay, point Terraform or
Argo/Flux at it, and the cluster converges.

## Terraform

`deploy/terraform/modules/probectl` deploys the chart + a Kubernetes Secret for the
sensitive config (so credentials never land in the ConfigMap/release values). It's
cloud-agnostic — point the providers at any kubeconfig. Module interface (inputs /
outputs / secret handling): [`deploy/terraform/README.md`](../deploy/terraform/README.md).
`make terraform-gate` runs `terraform fmt` + `validate`.

## GitOps

`deploy/gitops/` has an ArgoCD `Application` and Flux `GitRepository` +
`HelmRelease`. Both reference `secrets.existingSecret` rather than inlining
credentials — manage that Secret with **Sealed Secrets** or the **External Secrets
Operator**. ArgoCD `automated` sync (`prune` + `selfHeal`) and Flux install/upgrade
`remediation.retries` give a self-correcting, auto-rolling-back deployment. See
[`deploy/gitops/README.md`](../deploy/gitops/README.md). `make gitops-gate`
structurally validates the manifests.

## CI gates

- `helm-gate` — lint every profile + assert the hardening invariants above.
- `terraform-gate` — `terraform fmt -check` + `validate` the module via the example root.
- `gitops-gate` — the ArgoCD/Flux manifests are well-formed (apiVersion + kind).

## Out of scope

Multi-region active-active topology + DR is **S-EE2**; the FIPS build variant +
STIG/CIS hardening guides are **S-EE1**. This sprint is single-cluster IaC/GitOps
with a secure-by-default chart.
