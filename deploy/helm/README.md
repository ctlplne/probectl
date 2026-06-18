# deploy/helm/

Helm charts for deploying probectl on Kubernetes / OpenShift. **Helm** is
Kubernetes' package manager: a **chart** is a parameterized bundle of
Kubernetes manifests, **values** are the parameters, and `helm install`
renders chart templates + your values into live cluster objects. In these
charts the security hardening is welded into the templates and the values
choose size and wiring — the way trim levels configure the same car without
touching its safety cage. Two charts ship here:

- [`probectl/`](probectl/) — the **control plane**: the API/UI Deployment (the
  controller that keeps N identical pods running), the
  TLS-terminating ingress (the HTTPS front door object), the migration init
  container (a container that must run to completion before the app starts),
  NetworkPolicy (a pod-level firewall object) / PDB (PodDisruptionBudget — a
  floor on how many replicas voluntary disruptions may take down) /
  HPA (HorizontalPodAutoscaler — scales replicas with load), and the sizing
  profiles below.
- [`probectl-agent/`](probectl-agent/) — the **eBPF host agent** DaemonSet
  (the controller that runs exactly one copy per node — right for a per-host
  capture agent; see [its section](#the-agent-chart-probectl-agent)).

The control-plane chart is **HTTPS-by-default**: the API is exposed only through
a TLS-terminating ingress that emits HSTS (the header telling browsers to
refuse plaintext HTTP for this host from then on) and force-redirects
HTTP → HTTPS; the
Service is `ClusterIP` (a cluster-internal virtual IP, unreachable from
outside), so no plaintext API is reachable from outside the
cluster ("TLS on every listener" is a
[non-negotiable](../../CONTRIBUTING.md#non-negotiables)). The in-cluster API pod
hop is plaintext behind that ingress, so the default NetworkPolicy allows it
only from the named ingress-controller namespace and fails closed if that source
list is empty. The database migration runs as an init container; the pod runs
non-root with a read-only root filesystem.

## Install (single-tenant / sovereign)

```sh
helm install probectl deploy/helm/probectl \
  --namespace probectl --create-namespace \
  --set ingress.host=probectl.example.com \
  --set ingress.tlsSecretName=probectl-tls \
  --set database.url='postgres://probectl:...@db:5432/probectl?sslmode=require' \
  --set secrets.envelopeKey="$(openssl rand -base64 32)" \
  --set control.authMode=session \
  --set oidc.issuer=https://idp.example.com \
  --set oidc.clientId=probectl --set oidc.clientSecret=... \
  --set oidc.redirectUrl=https://probectl.example.com/auth/callback
```

Provide the TLS material via cert-manager (add the issuer annotation in
`ingress.annotations`) or a pre-created secret named by `ingress.tlsSecretName`.

> A green `/readyz` is not "done" — **data on screen is**. A control plane with
> no agents shows empty dashboards. Continue with
> [`docs/getting-started.md`](../../docs/getting-started.md) (the zero →
> first-real-data path) and
> [`docs/deploying-agents.md`](../../docs/deploying-agents.md) (which agent or
> collector produces which data plane).

## Install (multi-tenant / provider, MSP)

```sh
helm install probectl deploy/helm/probectl \
  -f deploy/helm/probectl/values-multitenant.yaml \
  --set ingress.host=probectl.msp.example.com \
  --set ingress.tlsSecretName=probectl-msp-tls \
  --set database.url=... --set secrets.envelopeKey="$(openssl rand -base64 32)" \
  --set oidc.issuer=... --set oidc.clientId=... --set oidc.clientSecret=...
```

Tenant isolation is enforced by the control plane (pooled RLS scoping) regardless
of deployment shape; the multi-tenant values only size the runtime and spread
replicas.

## The agent chart (`probectl-agent/`)

[`probectl-agent/`](probectl-agent/) deploys the eBPF host agent as a DaemonSet
with its privilege contract declared **in the artifact**, not implied:
capabilities (the kernel's itemized slices of root privilege) drop ALL and add
back exactly `CAP_BPF` + `CAP_PERFMON`
(`capabilityMode: legacy` swaps in `CAP_SYS_ADMIN` for pre-5.8 kernels, which
predate the two finer-grained capabilities), a
seccomp profile (a kernel-enforced syscall filter on the process), a read-only
root filesystem, and the
`/sys/kernel/btf/vmlinux` host mount (the running kernel's type catalog, which
lets one compiled BPF object adapt to any kernel). It **fails closed**: the
chart refuses to
render without a `tenantID` (every captured flow must belong to a tenant), and
refuses plaintext Kafka unless you set the explicit dev-only
`bus.allowPlaintext=true`.

```sh
helm install probectl-agent deploy/helm/probectl-agent \
  --set tenantID=<tenant> \
  --set 'bus.brokers={kafka.internal.example:9093}' \
  --set-string image.tag='0.4.0@sha256:<digest>'
```

Details: [`docs/ebpf-agent.md`](../../docs/ebpf-agent.md) and the privilege
contract in [`deploy/agent/README.md`](../agent/README.md).

## Reference values

Pick a sizing profile and layer your overrides on top:

| Profile | File | Shape |
| ------- | ---- | ----- |
| single-tenant default | [`probectl/values.yaml`](probectl/values.yaml) | 1 replica |
| small | [`probectl/values-small.yaml`](probectl/values-small.yaml) | lab / pilot |
| medium | [`probectl/values-medium.yaml`](probectl/values-medium.yaml) | 3 replicas + PDB + spread |
| large | [`probectl/values-large.yaml`](probectl/values-large.yaml) | HPA 4–12 + PDB + filled NetworkPolicy egress allow-list |
| provider (MSP) | [`probectl/values-multitenant.yaml`](probectl/values-multitenant.yaml) | 3 replicas + anti-affinity + PDB |
| multi-region | [`probectl/values-multiregion.yaml`](probectl/values-multiregion.yaml) | active-active HA, one release per region ([`docs/multi-region.md`](../../docs/multi-region.md)) |
| strict | [`probectl/values-strict.yaml`](probectl/values-strict.yaml) | regulated/air-gapped: egress hole closed + ServiceMonitor + backup CronJobs |

`values.schema.json` types every key (Helm validates it). The security defaults
(non-root pinned uid, read-only root FS, drop-ALL caps, NetworkPolicy/PDB/HPA,
`/readyz` drain probe, HSTS, no default credentials — the chart refuses to
render without envelope and session-HMAC keys) are enforced by `make helm-gate`, which runs
[`scripts/check_helm_hardening.sh`](../../scripts/check_helm_hardening.sh):
hardening assertions against the rendered default / medium / large /
multitenant / strict profiles, `helm lint` across the default and
small/medium/large/multitenant profiles, **and** the agent chart's privilege
contract + lint. (The strict profile is render-asserted — closed holes,
ServiceMonitor, backup CronJobs — rather than linted; the multiregion profile
reuses the same templates but is not separately exercised by the gate.) CI's
`helm-gate` job runs the same gate plus kubeconform (a schema validator
proving the rendered YAML is well-formed Kubernetes) on the rendered
charts, so a hardening regression fails the build, not a customer install.

Opt-in extras, both off by default and enabled in the strict profile:
`backup.enabled=true` renders the encrypted Postgres + ClickHouse backup
CronJobs ([`docs/ops/backup-restore.md`](../../docs/ops/backup-restore.md));
`metrics.serviceMonitor.enabled=true` renders a Prometheus-Operator
ServiceMonitor.

**NetworkPolicy is ON by default** in every profile. API ingress is already
restricted to the named ingress-controller namespace, so ordinary in-cluster
pods cannot bypass the TLS ingress and hit the plaintext API listener. Adjust
`networkPolicy.ingressFrom` to your ingress controller's labels. The remaining
deliberate hole is egress: empty `egressTo` allows all non-DNS egress until you
name your datastore, bus, IdP, and feed destinations.
`values-large.yaml` ships the filled reference egress allow-list (datastores/
bus/TSDB on private ranges + a clearly-marked HTTPS-anywhere rule for IdP and
open-data feeds — delete that rule when air-gapped); `values-strict.yaml`
closes the egress hole for regulated/air-gapped clusters (and adds the
monitoring namespace ingress selector for /metrics). Enforcement needs a
NetworkPolicy-capable CNI (the cluster's container-network plugin, e.g.
Calico or Cilium — without an enforcing one the object is accepted but inert);
the gate asserts the default ingress selector renders.
Terraform + GitOps wrap this same chart; see
[`docs/iac-gitops.md`](../../docs/iac-gitops.md). Full guide:
[`docs/install.md`](../../docs/install.md).
