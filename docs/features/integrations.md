# Ecosystem integrations

## What it is

probectl slots into the tools you already run rather than asking you to replace
them. This page covers five outbound and federated integrations:

- **Security-event export (SIEM).** A **Security Information and Event Management
  (SIEM)** system is the searchable database a security team uses to collect
  events from every tool it runs (Splunk, Microsoft Sentinel, Elastic, Google
  Chronicle). probectl forwards its audit log and threat signals into yours.
- **On-call and ticketing.** probectl mirrors each incident into the tools where
  the work actually happens — PagerDuty or Opsgenie for paging the on-call
  engineer, Slack or Teams for chat, ServiceNow or Jira for tickets (**IT Service
  Management**, or **ITSM**, systems).
- **Infrastructure as code (IaC) and GitOps.** Your whole deployment is a
  reviewed, versioned file, and a controller in the cluster continually keeps the
  running system matching it.
- **Federation with your inventory and metrics stack.** probectl answers
  Grafana and Prometheus directly, and correlates incidents against your
  **Configuration Management Database (CMDB)** — the system of record for your
  asset inventory.
- **Secrets-manager integration.** Anywhere probectl needs a credential — a
  database password, a device login — you hand it a *reference* and it resolves
  the real value from your secret store at the moment of use.

Two rules hold across all of them: every integration is **tenant-routed** (a
connection fires only for the one tenant it is registered against), and probectl
*forwards and mirrors* — it is never a SIEM, never a CMDB, and never an
intrusion-prevention system. Terms of art (SIEM, ITSM, CMDB) are in the
[glossary](../glossary.md).

## Why it exists

A network observability platform that hoards its data is a silo. Your security
operations center already runs a SIEM; your on-call team already carries a pager;
your platform team already deploys from Git; your inventory already lives in a
CMDB. The value is in probectl's signals reaching those places, in their native
shape, without you standing up a parallel world.

- **Security teams need the events, not another console.** A threat finding from
  probectl is a confidence-scored *signal* — exactly the kind of thing a SIEM
  exists to correlate against everything else. Forwarding it (rather than asking
  the security team to watch a separate screen) is what makes it useful.
- **An incident has to reach a human.** probectl correlates faults into
  incidents, but a correlated incident sitting in probectl's own UI at 3 a.m.
  wakes nobody. Mirroring it to the pager and the ticket queue is what turns a
  detection into a response.
- **Console clicks do not survive an audit or a rebuild.** A deployment defined
  as a file is reviewed, versioned, and reproducible; a sequence of console
  clicks is none of those.
- **Secrets do not belong in config files or Git.** Git history is forever, and a
  credential that lands in it is leaked forever. A reference in the config and the
  real value in a vault keeps the secret where it belongs.

Every one of these is **outbound** or **read-only by design**, and the outbound
ones are **off until you configure them** — probectl never opens a surprise
connection out of your network.

## How it works

**SIEM export forwards two streams in a standard wire format.** A **wire format**
is the exact byte layout the receiving SIEM expects. probectl drains its
tamper-evident audit log and its threat-plane signals, maps both onto one
canonical event record, and renders that record in whichever format your SIEM
wants — RFC 5424 syslog, ArcSight Common Event Format, Elastic Common Schema
JSON, or OpenTelemetry-protocol logs. One record, four renderings: the formatter
changes the costume, never the facts. The design rule is **never silently drop an
event**, because a gap in a security record is indistinguishable from an attacker
erasing tracks. The audit path drains from a durable per-tenant **cursor** (a
persisted bookmark — "everything before this point was delivered") and advances
it *only past events the SIEM acknowledged*, like a registered-mail clerk who
crosses an item off the ledger only when the signed receipt is in hand. The
threat path buffers and applies **backpressure** (the pipeline slows down rather
than throwing events away) when the SIEM is slow, retrying with exponential
backoff. Exported audit events are scrubbed of secrets and personally
identifiable information first — the SIEM gets the security record, never a copy
of the credentials inside it.

**Syslog collection brings device events in without becoming a SIEM.** For
network gear that emits syslog, probectl accepts RFC 5424 and RFC 3164 over a
TLS-only listener, authenticates each configured source with an HMAC signature or
TLS client-certificate subject, stamps the tenant from the source credential, and
keeps parser provenance on the normalized event. That gives incidents another
correlation signal while leaving long-term search, retention, and SOC workflows
in the operator's SIEM.

**On-call and ITSM connectors mirror each incident outward.** When a signal opens
a *new* incident, probectl pages, posts, and opens a ticket on each of the
tenant's connectors, and records the external reference (ticket id, page dedup
key). A correlated follow-up signal does **not** re-page. The two boundaries that
matter: probectl stays the **system of record** for the incident — the
connectors are a best-effort mirror, the stadium scoreboard to the referee's
scorecard — and a connector only ever pages, posts, or opens a ticket; it never
auto-blocks or auto-remediates. Operations are **idempotent** (doing it twice has
the same effect as once — a doorbell, not a counter), so a retry or a restart
never double-pages. Resolution syncs both ways: close the ServiceNow ticket and
probectl resolves the incident and syncs the *other* connectors — but never
echoes the resolution back to its origin, which would ping-pong forever.

**Inbound webhooks are authenticated per delivery and treated as untrusted.** A
**webhook** is an HTTP POST another system makes to you when something happens —
which means anyone who can reach the URL can attempt one. So each delivery
carries either a keyed hash of the body (a **hash-based message authentication
code**, or HMAC — only a sender holding the shared secret can produce a valid
one, and it covers the *content*, so a tampered body fails too) or a shared token
compared in constant time. An unsigned, forged, or wrong-token delivery is
rejected before any state change. The delivery is bound to the *credential's*
tenant, never a value from the payload, so one tenant can never resolve another's
incident.

**IaC and GitOps make a `git push` the only deploy action.** **GitOps** runs the
infrastructure-as-code idea on a loop: a controller in the cluster watches a Git
repository and continually **reconciles** the running cluster to match the file —
a thermostat for your deployment, where a hand-edit on the live cluster is an
opened window the controller quietly closes again. probectl ships one hardened
deployment chart, with Terraform modules and ArgoCD/Flux manifests that wrap it.
It is HTTPS-by-default and **refuses to run with default credentials** — the
render fails without a real encryption key supplied. Pods run non-root with a
read-only root filesystem and all capabilities dropped; the network policy is on
in every profile; and credentials are supplied by reference to a Kubernetes
secret, never inlined into Git.

**Metrics federation forces the tenant, never trusts it.** The dangerous part of
exposing a metrics query API is that a query language is powerful enough to ask
for *anyone's* data. probectl closes that hole: it accepts **only plain series
selectors** (a metric name plus label filters), rejecting the rest of the query
language outright, because a query probectl cannot fully parse is one it cannot
tenant-scope. Whatever tenant filter you wrote is **removed** and replaced with
an equality on *your* tenant — the bank teller ignores the account number you
wrote on the slip and uses the one on your ID. Grafana attaches as an ordinary
Prometheus datasource; Prometheus can scrape selected series out (federation) or
push series in (remote-write, with every sample's tenant forced on decode). CMDB
correlation is **read-only** — probectl looks up configuration items and never
writes — and results are cached, so a down CMDB serves stale cache and never
breaks core function.

**Secrets resolve in memory, at use time, and fail closed.** Anywhere probectl
accepts a credential, you can instead hand it a reference like
`vault:kv/netops/snmp#auth`. The config file holds the catalog card, not the
book: stealing the card tells a thief which shelf to look at, but the vault still
checks *probectl's* credentials before handing anything over. Resolved values are
held only briefly, sealed under an ephemeral per-process key, and re-resolved
when their short lease expires — so rotating a secret upstream takes effect with
no restart. An unreachable backend or an unresolvable reference is an **error**,
never a silent empty or stale credential.

## Use it

**Forward to a SIEM** (Splunk shown; the endpoint and token are operator-supplied):

```sh
PROBECTL_SIEM_ENABLED=true
PROBECTL_SIEM_PRESET=splunk
PROBECTL_SIEM_ENDPOINT=https://splunk.example:8088/services/collector/raw
PROBECTL_SIEM_TOKEN=<hec-token>        # inject from your secret manager
```

What you should observe: audit and threat events arriving in your SIEM, each
stamped with the tenant it was drained from, with secret and PII fields shown as
`[redacted]` (the key is kept so the SIEM still sees the *shape* of the event).
The token rides only an auth header, never a URL.

**Route incidents to a pager and a ticket queue.** A connector is registered
against one tenant id and fires only for that tenant:

```text
PROBECTL_NOTIFY_CONNECTORS=<tenant-uuid>|pagerduty|https://events.pagerduty.com/v2/enqueue|<routing-key>,<tenant-uuid>|jira|https://acme.atlassian.net/rest/api/2/issue?project=OPS&resolve_transition=31|alice@acme.com:<api-token>
PROBECTL_NOTIFY_INBOUND=jira1:<tenant-uuid>:jira:<webhook-secret>
```

What you should observe: a new incident pages PagerDuty once and opens one Jira
issue; a correlated follow-up does not re-page; resolving the Jira issue resolves
the incident and syncs PagerDuty, but does not re-close Jira.

**Add probectl to Grafana** as a Prometheus datasource — no plugin needed. Set
the URL to `https://<probectl>/v1/grafana`, the HTTP method to POST, and attach
credentials for a principal holding the metrics-read permission. To let an
existing Prometheus scrape probectl:

```yaml
scrape_configs:
  - job_name: probectl
    honor_labels: true
    metrics_path: /v1/prometheus/federate
    params:
      "match[]": ["{__name__=~\"probectl_.*\"}"]
    scheme: https
    static_configs: [{ targets: ["probectl.example.com"] }]
```

What you should observe: the `probectl_*` series in Grafana and Prometheus,
already filtered to your tenant. An over-broad selector that matches more than
the series cap **fails closed** with an explicit error rather than melting the
scraper — narrow the selector.

**Hand probectl a secret reference instead of the material** (an SNMPv3 device
credential resolved from Vault on every poll cycle):

```sh
export PROBECTL_SECRETS_VAULT_ADDR=https://vault.acme.example:8200
export PROBECTL_DEVICE_CRED_CORE_SW_USERNAME=monitor
export PROBECTL_DEVICE_CRED_CORE_SW_AUTH_PASS='vault:kv/netops/snmp#auth'   # a reference, not the secret
export PROBECTL_DEVICE_CRED_CORE_SW_PRIV_PASS='vault:kv/netops/snmp#priv'
```

What you should observe at `GET /v1/secrets/health`: per-backend counters, live
lease counts, and the last error — all **redacted**, never any secret material.
Rotate the secret in Vault and the new value applies at the next lease expiry
with no restart; a failed re-resolution skips the poll cycle rather than polling
with stale material.

## Pitfalls & limits

- **probectl forwards; it does not become the destination tool.** It is not a
  SIEM (it does not store, search, or correlate the events for you), not a CMDB,
  and never an intrusion-prevention system — a threat finding is a signal, never
  an enforcement action.
- **Outbound integrations are off until configured.** SIEM export, connectors,
  and CMDB lookups all stay dark until you set them, so there is no surprise
  egress. The notification and CMDB connector URLs are validated to be HTTPS
  (loopback excepted); always configure the SIEM endpoint as HTTPS too —
  certificate validation is never disabled for HTTPS connections.
- **The metrics API takes only plain selectors.** Functions and operators of the
  full query language are rejected, because what probectl cannot fully parse it
  cannot tenant-scope. Do client-side math with Grafana transformations. Federate
  with a narrow selector or the cardinality guard rejects it.
- **CMDB correlation is read-only and deployment-level.** One CMDB connection per
  install (correlation *requests* are still tenant-scoped). probectl never writes
  to your CMDB. A down CMDB degrades to stale cache, never an error in core flows.
- **The on-call mirror is best-effort, not authoritative.** probectl is the
  system of record for the incident; connectors are a glanceable copy. probectl
  does not own on-call schedules or escalation policies — those stay in your
  pager. Inbound webhooks must be signed or carry the shared token, or they are
  rejected.
- **A secret reference fails closed.** An unreachable secret backend, an
  unresolvable reference, or a misconfigured backend is an error (often a refused
  startup) — never a silently substituted empty, partial, or stale credential.
  Backend access is configured through the environment only, so those access
  credentials never sit in a file probectl reads.
- **GitOps refuses default credentials.** The deployment chart will not render
  without a real encryption key, and it is HTTPS-only with no plaintext API.
  Manage the Kubernetes secret with a sealed-secrets or external-secrets
  controller so the real value never enters Git history.
- **Single-cluster scope here.** Active-active multi-region topology and disaster
  recovery are documented separately.

## Reference

- **SIEM export:** `PROBECTL_SIEM_ENABLED`, `PROBECTL_SIEM_PRESET` (splunk /
  sentinel / elastic / chronicle / generic), `PROBECTL_SIEM_ENDPOINT`,
  `PROBECTL_SIEM_TOKEN`, `PROBECTL_SIEM_FORMAT` (syslog / cef / ecs / otlp),
  `PROBECTL_SIEM_REDACT_KEYS`. SIEM export runs as a configured background
  forwarder — no request-time permission gates it. The audit log is also pullable
  at `GET /v1/audit?after=<cursor>`.
- **On-call & ITSM:** `PROBECTL_NOTIFY_CONNECTORS` (per-tenant connector list),
  `PROBECTL_NOTIFY_INBOUND` (inbound webhook secrets). Inbound resolution posts to
  `POST /ingest/itsm/{provider}/{id}` with an HMAC signature or shared token.
  Connectors: PagerDuty, Opsgenie, Slack, Teams, ServiceNow, Jira.
- **IaC & GitOps:** one hardened deployment chart, wrapped by Terraform modules
  and ArgoCD/Flux manifests. HTTPS-by-default, non-root pods, network policy on,
  no default credentials. Size overlays (small / medium / large / multitenant)
  differ only in runtime sizing.
- **Federation:** Grafana as a Prometheus datasource at `/v1/grafana`; scrape out
  at `GET /v1/prometheus/federate?match[]=<selector>`; push in at `POST
  /v1/prometheus/write`. CMDB lookups: `GET /v1/cmdb/lookup`, `GET
  /v1/incidents/{id}/cis`, `GET /v1/agents/{id}/ci`. Reads need a metrics-read
  permission; remote-write needs metrics-write; CMDB needs a cmdb-read permission.
- **Secrets:** reference schemes `env:`, `vault:`, `cyberark:`, `aws:`, `azure:`,
  `gcp:`, and a `literal:` escape hatch. Health at `GET /v1/secrets/health`
  (redacted). The same machinery loads agent mutual-TLS identities and picks up
  in-place certificate renewals without a restart.
- **Related capabilities (separate pages):** the audit-log foundation (the stream
  SIEM export drains); alerting and incidents (what the connectors mirror);
  identity and access (the tenant-first checks every surface here sits behind);
  per-tenant keys (which build on the same secret resolver).

**Covers:** F26, F27, F29, F30, F31
