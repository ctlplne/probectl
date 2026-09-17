# deploy/helm/

Helm charts for deploying probectl on Kubernetes / OpenShift. **Helm** is
Kubernetes' package manager: a **chart** is a parameterized bundle of
Kubernetes manifests, **values** are the parameters, and `helm install`
renders chart templates + your values into live cluster objects. In these
charts the security hardening is welded into the templates and the values
choose size and wiring — the way trim levels configure the same car without
touching its safety cage. Two charts ship here:

- [`probectl/`](probectl/) — the **control plane**: the TLS-serving API/UI
  Deployment (the controller that keeps N identical pods running), the HTTPS
  ingress (the public front door object), the migration init
  container (a container that must run to completion before the app starts),
  NetworkPolicy (a pod-level firewall object) / PDB (PodDisruptionBudget — a
  floor on how many replicas voluntary disruptions may take down) /
  HPA (HorizontalPodAutoscaler — scales replicas with load), and the sizing
  profiles below.
- [`probectl-agent/`](probectl-agent/) — the **eBPF host agent** DaemonSet
  (the controller that runs exactly one copy per node — right for a per-host
  capture agent; see [its section](#the-agent-chart-probectl-agent)).

The control-plane chart serves **HTTPS on every hop by default**. The control
process terminates TLS directly; the Service, probes, ingress backend, and
optional ServiceMonitor all target that HTTPS listener. The public ingress also
terminates TLS, emits HSTS, and force-redirects HTTP → HTTPS. Supply an
operator-managed Secret through `control.tls.existingSecret`; Helm refuses to
render without it. The built-in Ingress supports only ingress-nginx:
`ingress.className` must be `nginx`, and blank or unsupported classes fail
rendering. This restriction keeps the controller and its security controls on
one contract—the ingress controller authenticates the backend certificate with
`ingress.backendTLS.trustSecret` (a same-namespace ingress-nginx proxy-ssl Secret
containing `tls.crt`, `tls.key`, and `ca.crt`) and
`ingress.backendTLS.serverName` (a DNS SAN on the control listener certificate);
Helm also refuses to render if either is missing. `probectl/values-strict.yaml`
keeps that transport posture and
additionally closes the default egress hole. The database migration runs as an
init container; the pod runs non-root with a read-only root filesystem.

For another ingress controller, set `ingress.enabled=false` and provide an
operator-owned Ingress that independently enforces HTTPS redirect plus complete
backend certificate chain and hostname verification. The chart does not guess
controller-specific annotations because a guessed control can silently do
nothing.

## Install (single-tenant / sovereign)

```sh
helm install probectl deploy/helm/probectl \
  --namespace probectl --create-namespace \
  --set ingress.host=probectl.example.com \
  --set ingress.tlsSecretName=probectl-tls \
  --set ingress.backendTLS.trustSecret=probectl-backend-ca \
  --set ingress.backendTLS.serverName=probectl.example.com \
  --set control.tls.existingSecret=probectl-tls \
  --set-string image.digest='sha256:<release-digest>' \
  --set database.url='postgres://probectl:...@db:5432/probectl?sslmode=require' \
  --set secrets.envelopeKey="$(openssl rand -base64 32)" \
  --set control.authMode=session \
  --set oidc.issuer=https://idp.example.com \
  --set oidc.clientId=probectl --set oidc.clientSecret=... \
  --set oidc.redirectUrl=https://probectl.example.com/auth/callback
```

Provide public/listener TLS material via cert-manager (add the issuer annotation
in `ingress.annotations`) or a pre-created Secret containing `tls.crt` and
`tls.key`. Separately, ingress-nginx's `proxy-ssl-secret` contract requires a
client certificate/key plus the backend trust chain. Create it in the release
namespace from reviewed PEM files:

```sh
kubectl -n probectl create secret generic probectl-backend-ca \
  --from-file=tls.crt=ingress-client.crt \
  --from-file=tls.key=ingress-client.key \
  --from-file=ca.crt=control-listener-ca.crt
```

That Secret is ingress-nginx's outbound TLS identity and trust input; it is not
the public ingress Secret or `control.tls.existingSecret`. The control
certificate must include `probectl.example.com` in its SANs. The example
deliberately reuses the public certificate for the pod listener while keeping
the ingress controller's outbound credentials and trust explicit.
Set `image.digest` to the signed `probectl-control` release digest (or the exact
digest of an approved mirror); the chart rejects ordinary tags.

When upgrading from a chart that used `image.tag`, remove that key from the
operator-owned values file and do not use `--reuse-values`: it would carry the
obsolete key into schema validation. Use `helm upgrade --reset-values`, reapply
the complete reviewed values/Secret references, and set the digest as shown
above. A release that still supplies `image.tag` fails closed even when it also
supplies a digest.

> A green `/readyz` is not "done" — **data on screen is**. A control plane with
> no agents shows empty dashboards. Continue with
> [`docs/getting-started.md`](../../docs/getting-started.md) (the zero →
> first-real-data path) and
> [`docs/deploying-agents.md`](../../docs/deploying-agents.md) (which agent or
> collector produces which data plane).

## Install (multi-tenant / provider, MSP)

Before installing, pre-create two shared resources (three with the license),
and have your SIEM endpoint ready — the multi-tenant profile refuses to render
without `PROBECTL_SIEM_ENABLED=true` and `PROBECTL_SIEM_ENDPOINT` (PRIVACY-001:
tenant audit rows are pruned only below the SIEM delivery watermark):

- `probectl-license`: a Secret holding the offline-signed MSP license file
  (`kubectl -n probectl create secret generic probectl-license
  --from-file=license.json=./license.json`), referenced below as
  `license.existingSecret`. The control plane verifies it locally — never
  phone-home — and Admin → Editions shows the result ([`docs/editions.md`](../../docs/editions.md)).

- `probectl-provider-objects-rwx`: a `ReadWriteMany` PVC backed by encrypted,
  shared storage whose WORM prefix is protected by S3 Object Lock, MinIO
  compliance mode, or an equivalent retention policy. A PVC/CSI mount provides
  the shared filesystem; the backing object store provides immutability.
- `probectl-provider-runtime`: an externally managed Secret containing
  `PROBECTL_ENVELOPE_KEY`, `PROBECTL_SESSION_HMAC_KEY`,
  `PROBECTL_DATABASE_URL`, `PROBECTL_OIDC_CLIENT_SECRET` when OIDC needs one,
  and `PROBECTL_WORM_SIGNING_KEY`. The last value is the base64-encoded PKCS#8
  PEM signing key. Every replica must receive the same value.

The names are the reference defaults below; override
`objectStore.existingClaim` and `secrets.existingSecret` when your operators
create different names.

```sh
helm install probectl deploy/helm/probectl \
  -f deploy/helm/probectl/values-multitenant.yaml \
  --set ingress.host=probectl.msp.example.com \
  --set ingress.tlsSecretName=probectl-msp-tls \
  --set ingress.backendTLS.trustSecret=probectl-backend-ca \
  --set ingress.backendTLS.serverName=probectl.msp.example.com \
  --set control.tls.existingSecret=probectl-msp-tls \
  --set-string image.digest='sha256:<release-digest>' \
  --set secrets.existingSecret=probectl-provider-runtime \
  --set license.existingSecret=probectl-license \
  --set objectStore.existingClaim=probectl-provider-objects-rwx \
  --set database.url='postgres://declaration-only@db:5432/probectl?sslmode=verify-full' \
  --set oidc.issuer=... --set oidc.clientId=... \
  --set-string control.extraEnv.PROBECTL_AUDIT_WORM_DIR=/var/lib/probectl/objects/audit-worm \
  --set-string control.extraEnv.PROBECTL_SIEM_ENABLED=true \
  --set-string control.extraEnv.PROBECTL_SIEM_ENDPOINT=https://siem.example/ingest
```

Tenant isolation is enforced by the control plane (pooled RLS scoping) regardless
of deployment shape; the multi-tenant values only size the runtime and spread
replicas. Provider profiles also need audit-retention watermarks at install time:
tenant audit rows prune only below the SIEM cursor, and provider/break-glass rows
prune only below the signed WORM segment watermark.

`database.url` remains a render-time TLS-posture declaration for the
multi-tenant profile; the actual credential is read from
`PROBECTL_DATABASE_URL` in `secrets.existingSecret`. Keep their endpoint and
`sslmode` consistent. Helm cannot inspect an already-created Secret, and the
control process independently fails closed if the runtime DSN violates the
production TLS policy.

The chart rejects a WORM directory unless it is an absolute, canonical path at
or below `objectStore.mountPath`, and that mount uses a non-empty
`objectStore.existingClaim`. It also rejects
`PROBECTL_WORM_SIGNING_KEY_FILE` whenever more than one replica can run: a file
generated independently by each pod would create competing signing identities.
For a one-replica sovereign install, a stable key file remains supported when
both the WORM directory and key file live on the persistent claim.

### Private CA for the identity provider, database, SIEM or CMDB

Most enterprise IdPs (Keycloak, ADFS, an internal Okta gateway), managed
Postgres endpoints reached with `sslmode=verify-ca`/`verify-full`, SIEM
collectors and CMDBs sit behind a private PKI. Give the control plane that
trust as a typed value (DPR-026): put the PEM bundle in a ConfigMap and name it.
The chart mounts it read-only into the migrate init container and the control
container and points `SSL_CERT_FILE` at it; Go keeps loading the image's system
roots from `/etc/ssl/certs`, so public endpoints stay verifiable. There is no
skip-verify anywhere.

```sh
kubectl -n probectl create configmap probectl-trust-bundle --from-file=ca-bundle.crt=./corp-ca.pem
helm upgrade --install probectl deploy/helm/probectl ... \
  --set control.trustBundle.existingConfigMap=probectl-trust-bundle
# then, e.g. in probectl-provider-runtime:
#   PROBECTL_DATABASE_URL=postgres://...?sslmode=verify-full&sslrootcert=/etc/probectl/trust/ca-bundle.crt
```

### Credential files (Prometheus / ClickHouse basic auth, broker client keys)

The control plane reads datastore credentials from **private, regular,
mode-0600 files** (`PROBECTL_TSDB_BASIC_AUTH_FILE`,
`PROBECTL_CLICKHOUSE_BASIC_AUTH_FILE`, `PROBECTL_BUS_TLS_KEY_FILE`); it refuses
symlinks and group-readable modes, which is exactly what a Kubernetes Secret
volume looks like from inside a non-root pod. `control.credentialFiles` names a
Secret whose keys the chart stages into a memory-backed volume with
`probectl-control stage-credentials` (a shell-free init container, the image
has no `cp`) before `migrate` and `control` start; point the file settings at
`<mountPath>/<key>` (DPR-030):

```sh
kubectl -n probectl create secret generic probectl-store-credentials \
  --from-file=prom-basic-auth.json=./prom-basic-auth.json \
  --from-file=ch-basic-auth.json=./ch-basic-auth.json
helm upgrade --install probectl deploy/helm/probectl ... \
  --set control.credentialFiles.existingSecret=probectl-store-credentials \
  --set-string control.extraEnv.PROBECTL_TSDB_BASIC_AUTH_FILE=/etc/probectl/credentials/prom-basic-auth.json \
  --set-string control.extraEnv.PROBECTL_CLICKHOUSE_BASIC_AUTH_FILE=/etc/probectl/credentials/ch-basic-auth.json
```

`control.extraEnv` is only for settings without a typed chart value. The chart
rejects names it already owns—including listener TLS, authentication, HSTS,
at-rest encryption, database, OIDC, and chart-Secret keys—so a generic map
cannot create duplicate ConfigMap entries or move credentials into that map.
Configure those settings through their documented typed value or Secret. In
particular, inject the offline `PROBECTL_IR_UNLOCK_KEY` only through the
operator-managed `secrets.existingSecret`; the chart rejects attempts to place
that investigation key in `control.extraEnv` or a ConfigMap.

## Optional public-feed BGP analyzer

`bgpAnalyzer.enabled=true` adds one listener-free Deployment containing the
Python analyzer and its tenant-bound Go Kafka bridge. Create a Secret whose
`analyzer.json` key contains exactly one tenant's analyzer config, use an
immutable `probectl-bgp-analyzer` image digest, and set the existing Kafka TLS
variables under `bgpAnalyzer.extraEnv`. Put SASL credentials in the dedicated
`bgpAnalyzer.busSecret`, not in values.

Select `bgpAnalyzer.source` explicitly. The stock image runs MRT files and
recorded RIS replay; a custom live-RIS image must add the analyzer's documented
optional `websockets` package under the same hash-pinning policy.

The analyzer NetworkPolicy is fail-closed: enabling the component also requires
a non-empty `bgpAnalyzer.networkPolicy.egressTo` list covering the Kafka broker
and any explicitly configured RIS/RPKI destination. No Service is rendered,
and the pod receives no Kubernetes API token. See
[`docs/bgp.md`](../../docs/bgp.md) and
[`docs/configuration.md`](../../docs/configuration.md) for the config schema.

## Optional rendered-browser synthetic agent

`browserAgent.enabled=true` adds a listener-free DaemonSet using the dedicated
`probectl-browser-agent` image. The image packages the tenant-bound Go agent and
Playwright child in one pod; no Service is rendered because their control
contract is stdin/stdout, while results still leave over the agent's mTLS gRPC
connection.

Enabling it fails closed unless all three deployment boundaries are explicit:

- `browserAgent.image.digest` pins the immutable release/mirror image;
- `browserAgent.configSecret` names a Secret containing `agent.yml`,
  `cert.pem`, `key.pem`, and `ca.pem`; the config selects
  `browser.driver: browser` and those certificate paths;
- `browserAgent.networkPolicy.egressTo` is non-empty and names the mTLS control
  plane plus the tenant-approved targets. DNS is the only automatically added
  egress rule.

The pod runs as UID/GID 1000 with no API token, a read-only root filesystem,
drop-ALL capabilities, RuntimeDefault seccomp, and memory-backed `/dev/shm` for
Chromium. Example values:

```yaml
browserAgent:
  enabled: true
  image:
    digest: sha256:<64-hex-release-digest>
  configSecret: tenant-a-browser-agent
  networkPolicy:
    enabled: true
    egressTo:
      - to:
          - namespaceSelector:
              matchLabels:
                kubernetes.io/metadata.name: probectl
            podSelector:
              matchLabels:
                app.kubernetes.io/name: probectl
        ports:
          - { protocol: TCP, port: 9443 }
```

See [`docs/browser-synthetic.md`](../../docs/browser-synthetic.md) for test
semantics and the Secret's agent YAML.

## The agent chart (`probectl-agent/`)

[`probectl-agent/`](probectl-agent/) deploys the eBPF host agent as a DaemonSet
with its privilege contract declared **in the artifact**, not implied:
capabilities (the kernel's itemized slices of root privilege) drop ALL and add
back exactly `CAP_BPF` + `CAP_PERFMON`
(`capabilityMode: legacy` swaps in `CAP_SYS_ADMIN` only after the explicit
`legacyKernelRingBufferAck` confirms the runtime probe saw BTF + BPF
ring-buffer support, not as a generic old-kernel escape hatch), a
seccomp profile (a kernel-enforced syscall filter on the process), a read-only
root filesystem, and the
`/sys/kernel/btf/vmlinux` host mount (the running kernel's type catalog, which
lets one compiled BPF object adapt to any kernel). It **fails closed**: the
chart refuses to
render without a `tenantID` (every captured flow must belong to a tenant), and
refuses plaintext Kafka unless you set the explicit dev-only
`bus.allowPlaintext=true`. Liveness/readiness use exec probes by default: the
agent writes small state files in `health.stateDir`, and Kubernetes runs
`probectl-ebpf-agent healthcheck` inside the container. That keeps the default
DaemonSet from opening a plaintext health port. The old HTTP probe listener is
compatibility-only and renders only with both `health.mode=http` and
`health.allowPlaintextHTTP=true`.

The eBPF agent also owns a loopback-only `/metrics` listener by default. Set
`metrics.enabled=true` to make that listener scrapeable on the pod network. The
chart then requires `metrics.tls.existingSecret` (keys `tls.crt` and `tls.key`),
configures the agent's TLS 1.3 listener, opens the named `metrics` container
port, and adds `prometheus.io/{scrape,path,port,scheme}` pod annotations with
`scheme=https`. In other words, enabling fleet scraping cannot accidentally
turn a local HTTP endpoint into a cluster-wide plaintext endpoint.

The chart renders two Kyverno ClusterPolicies by default. The image-integrity
policy enforces digest + keyless signature admission, and
`probectl-agent-capability-posture` (EBPF-007) runs in background Audit mode so
legacy `SYS_ADMIN` or any extra capability creates policy reports. In other
words, the documented break-glass path stays available, but it cannot be
invisible.

```sh
helm install probectl-agent deploy/helm/probectl-agent \
  --set tenantID=<tenant> \
  --set 'bus.brokers={kafka.internal.example:9093}' \
  --set-string image.tag='0.6.0@sha256:<digest>'
```

Because this is a privileged node agent, the chart also renders the Kyverno
`ClusterPolicy` that verifies the eBPF-agent image digest and keyless cosign
signature from the `release.yml` tag workflow before Kubernetes admits a pod.
Kyverno must already be installed in the cluster; regulated installs fail closed
unless that rendered policy is enforcing or an equivalent admission control is
named. Disabling the verifier requires both
`admission.imageIntegrity.enabled=false` and a non-empty
`admission.imageIntegrity.acceptedRisk` note so a tag-only/dev path leaves an
audit-visible footprint in values.

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
| strict | [`probectl/values-strict.yaml`](probectl/values-strict.yaml) | regulated/air-gapped: egress hole closed, monitored HTTPS listener, PrometheusRule self-alerts, backup CronJobs |

`values.schema.json` types every key (Helm validates it). The security defaults
(non-root pinned uid, read-only root FS, drop-ALL caps, NetworkPolicy/PDB/HPA,
`/readyz` drain probe, HTTPS listener, HSTS, no default credentials, immutable
control image — the chart refuses to render without a TLS Secret, image digest,
envelope key, and session-HMAC key) are
enforced by `make helm-gate`, which runs
[`scripts/check_helm_hardening.sh`](../../scripts/check_helm_hardening.sh):
hardening assertions against the rendered default / medium / large /
multitenant / strict profiles, `helm lint` across every values file, **and** the
agent chart's privilege contract + image-integrity admission policy + lint. The
default and strict render checks prove the HTTPS endpoints resolve to an actual
HTTPS Service target and container listener, with the control TLS Secret
mounted into the pod. CI's
`helm-gate` job runs the same gate plus kubeconform (a schema validator
proving the rendered YAML is well-formed Kubernetes) on the rendered
charts, so a hardening regression fails the build, not a customer install.

Opt-in extras, both off by default and enabled in the strict profile:
`backup.enabled=true` renders the encrypted Postgres + ClickHouse + filesystem
object-store/WORM backup CronJobs
([`docs/ops/backup-restore.md`](../../docs/ops/backup-restore.md)). The object
CronJob reads `backup.objectStore.sourceClaim` through a read-only mount and
streams it directly into `.tar.pbk`; the chart carries no object-store
credentials;
`metrics.serviceMonitor.enabled=true` renders a Prometheus-Operator
ServiceMonitor; `metrics.prometheusRule.enabled=true` renders the
PrometheusRule self-alert pack with runbook annotations. Every profile targets
the control process's named `https` listener. The strict profile additionally
supplies a reference Prometheus CA configuration.

**NetworkPolicy is ON by default** in every profile. API ingress is already
restricted to the named ingress-controller namespace, and that path uses TLS
to the pod listener too. Adjust
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
