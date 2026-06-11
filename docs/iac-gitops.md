# IaC, GitOps & Helm hardening

## What this is

**Infrastructure as code** (IaC) means your deployment is a reviewed, versioned
file instead of a sequence of console clicks; **GitOps** runs that idea on a
loop — a controller inside the cluster watches a Git repository and continually
**reconciles** the cluster to match the file. Like a thermostat: you set the
temperature in Git, the controller keeps nudging the room until it matches, and
a hand-edit on the live cluster is an opened window the controller quietly
closes again. probectl ships that whole stack, **declarative** (you state the
desired end state; the tooling works out the steps) and secure-by-default: a
hardened Helm chart, Terraform modules that wrap it, and ArgoCD/Flux manifests
so that a `git push` is the only deploy action you take. Everything is
HTTPS-by-default and **refuses to run with default credentials**.

```mermaid
%%{init: {'theme':'base','themeVariables':{'background':'#0d1117','primaryColor':'#161b22','primaryTextColor':'#e6edf3','primaryBorderColor':'#3b82f6','lineColor':'#8b949e','secondaryColor':'#21262d','tertiaryColor':'#0d1117','clusterBkg':'#161b22','clusterBorder':'#30363d','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'},'flowchart':{'curve':'basis','nodeSpacing':55,'rankSpacing':55,'padding':12}}}%%
flowchart LR
  subgraph Git
    V[values overlay\nsmall/medium/large/multitenant]
  end
  V --> TF[Terraform module] --> H[Helm chart]
  V --> GO[ArgoCD / Flux] --> H
  H --> K[Kubernetes:\nDeployment · Service · Ingress(HTTPS)\nNetworkPolicy · PDB · HPA]
```

## Three ways in (one chart)

| Path | Use it when | Where |
| ---- | ----------- | ----- |
| **Helm** | manual / scripted installs | `deploy/helm/probectl` |
| **Terraform** | infra-as-code alongside the cluster + DB | `deploy/terraform/` |
| **GitOps** (ArgoCD/Flux) | continuous reconcile from Git | `deploy/gitops/` |

All three deploy the **same** hardened chart — Terraform and GitOps just wrap it.

## Hardened Helm chart

`values.schema.json` types every key (Helm validates input against it on
install/upgrade). Three Kubernetes objects in the table deserve a one-line
introduction: a **NetworkPolicy** is the pod's firewall (which traffic may come
in, where traffic may go out); a **PodDisruptionBudget** (PDB) is the floor on
how many replicas voluntary maintenance — a node drain, an upgrade — may take
down at once; a **HorizontalPodAutoscaler** (HPA) adds and removes replicas to
follow load. The secure defaults below are enforced by the CI hardening gate
(`make helm-gate`), which renders the chart and greps for each invariant — a
regression here fails the build:

| Control | Default |
| ------- | ------- |
| Pod identity | non-root (`runAsNonRoot: true`), uid pinned to **65532**, `fsGroup` set |
| Container | `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, capabilities **drop ALL**, seccomp `RuntimeDefault` |
| Service account | token automount **off** (`automountServiceAccountToken: false`) — no Kubernetes API access |
| Ingress | HTTPS-only, **HSTS**, HTTP→HTTPS redirect, ClusterIP service (no plaintext API) |
| Credentials | render **fails** without an envelope key (no default creds); secrets supplied via `existingSecret` |
| Probes | readiness `/readyz` (flips to 503 while draining, for zero-downtime rollouts), liveness `/healthz` |
| Network | `NetworkPolicy` is **on by default** in every profile (see the note below) |
| Disruption | `PodDisruptionBudget` (medium / large / multitenant) for zero-downtime upgrades |
| Scale | `HorizontalPodAutoscaler` (large profile; it then owns the replica count instead of the Deployment) |

**About the default NetworkPolicy.** It is on in every profile, but as shipped it
has two deliberately open "holes": it allows in-cluster ingress to the API port,
and allows all egress. Think of a new house delivered with every door fitted
but propped open — the frames are in (so closing is a values change, not a
retrofit), and they stay open only because the builder cannot know which keys
to cut for *your* cluster. You close them by setting the
allow-lists (`networkPolicy.ingressFrom` / `networkPolicy.egressTo`) for your
cluster. `values-large.yaml` ships the filled-in reference shape (ingress from
the ingress-controller namespace, egress to the database CIDR/port); copy that
pattern. The hardening gate checks the strict profile actually narrows these.

### Reference sizing

The size overlays differ only in runtime sizing — every one of them gets the same
HTTPS-by-default, hardened-pod, NetworkPolicy-on posture above.

| Profile | File | Replicas | PDB | HPA | NetworkPolicy |
| ------- | ---- | -------- | --- | --- | ------------- |
| small | `values-small.yaml` | 1 | – | – | on (holes open; close them) |
| medium | `values-medium.yaml` | 3 | minAvailable 2 | – | on (holes open; close them) |
| large | `values-large.yaml` | 4 → HPA 4–12 | minAvailable 3 | on | on (filled allow-lists) |
| multitenant | `values-multitenant.yaml` | 3 + anti-affinity | minAvailable 2 | – | on (holes open; close them) |

Two more overlays ship for specialized profiles: `values-strict.yaml` (the
regulated/hardened profile the gate renders) and `values-multiregion.yaml`
(active-active HA — see [multi-region.md](multi-region.md)).

```bash
helm install probectl deploy/helm/probectl -f deploy/helm/probectl/values-medium.yaml \
  --set ingress.host=probectl.example.com --set ingress.tlsSecretName=probectl-tls \
  --set secrets.envelopeKey="$(openssl rand -base64 32)"
```

## Config-as-code

The declarative config **is** the Helm values: `control.*`, `oidc.*`,
`database.url`, and `control.extraEnv` map to `PROBECTL_*` environment variables
via the chart's ConfigMap; the size overlays are the reference config. Commit
your overlay, point Terraform or Argo/Flux at it, and the cluster converges to it.

## Terraform

`deploy/terraform/modules/probectl` deploys the chart **plus** a Kubernetes
Secret for the sensitive config — so credentials never land in the ConfigMap or
release values. It's cloud-agnostic: point the providers at any kubeconfig. The
module interface (inputs / outputs / secret handling) is documented in
[deploy/terraform/README.md](../deploy/terraform/README.md). `make terraform-gate`
runs `terraform fmt -check` and `terraform validate` against the example root in
`deploy/terraform/examples/kubernetes`.

## GitOps

`deploy/gitops/` has an ArgoCD `Application` (`argocd/application.yaml`) and a
Flux `GitRepository` + `HelmRelease` (`flux/`). Both reference
`secrets.existingSecret` rather than inlining credentials — Git history is
forever, so a secret must never enter it. Manage that Secret
with **Sealed Secrets** or the **External Secrets Operator** (both keep only an
encrypted or referenced form in Git; a cluster-side controller materializes the
real value). ArgoCD `automated`
sync (`prune` deletes resources removed from Git; `selfHeal` re-applies the
desired state over hand-edits) and Flux's install/upgrade `remediation.retries`
together give a self-correcting, auto-rolling-back deployment. See
[deploy/gitops/README.md](../deploy/gitops/README.md). `make gitops-gate`
structurally validates the manifests (every doc has an `apiVersion` + `kind`).

## CI gates

- `helm-gate` — lints every profile, asserts the hardening invariants above, and
  validates the GitOps manifests and the compose config. (This is the CI job
  name to require in [branch protection](ops/branch-protection.md); `make
  gitops-gate` runs inside it.)
- `terraform-gate` — `terraform fmt -check` + `validate` of the module via the
  example root.
- `gitops-gate` — a `make` target: the ArgoCD/Flux manifests are well-formed
  (`apiVersion` + `kind`).

## Scope

This stack is single-cluster IaC/GitOps with a secure-by-default chart.
Active-active **multi-region topology and DR** is documented separately
([multi-region.md](multi-region.md), [ops/dr.md](ops/dr.md),
[runbooks/region-failover.md](runbooks/region-failover.md)) and is an Enterprise
entitlement (the validated failover runbooks and support, not the fence itself).
The **FIPS build** is likewise the Enterprise-distributed artifact; the
STIG/CIS-style hardening checklist itself is public — see
[hardening.md](hardening.md).
