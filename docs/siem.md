# SIEM export

**What this is.** A **SIEM** (Security Information and Event Management system)
is the searchable central database where a **SOC** (security operations center
— the team watching for attacks) collects security events from every tool it
runs. A SOC runs its own SIEM (Splunk, Sentinel, Elastic, Chronicle)
and wants probectl's security-relevant events flowing into it. This feature
forwards two streams — probectl's **audit log** and its **threat-plane signals** —
into that SIEM, rendered in a standard wire format and pushed over hardened TLS.

The important framing: it is a **forwarder, not a SIEM**. probectl does not store,
search, or correlate these events for you, and it never blocks traffic or acts as
an IPS. A threat finding is a confidence-scored *signal* that the SIEM correlates
(detection is a signal, never an enforcement action — one of probectl's
[non-negotiables](../CONTRIBUTING.md#non-negotiables)). The code is `internal/siem`
(pure — formatters, senders, a buffered forwarder), driven by `internal/control`
which maps `audit.Event` + `incident.Signal` onto the canonical `siem.Event`.

**Off by default.** Enabling it opens an *outbound* connection to the operator's
SIEM, so it is explicit and config-gated — off unless `PROBECTL_SIEM_ENABLED=true`
(sovereignty / no-phone-home).

## What is forwarded

| Source | Category | Severity | Notes |
| ------ | -------- | -------- | ----- |
| **Audit log** (config changes, logins, data-access) | `audit` | `info`; `warning` on a failed / denied outcome | drained from the tamper-evident audit chain, tenant-scoped, **PII / secret redacted** |
| **Threat signals** — TLS / cert posture, IOC matches, NDR-lite detections, compliance segmentation violations | `threat` | mapped from the signal's severity | the same confidence-scored signals that build incidents |

Both map onto one canonical `siem.Event`, so every output format carries the same
fields: time, **tenant**, category, action, severity, actor, target, outcome,
message, and attributes. One canonical record, four renderings — the formatters
only change the costume, never the facts.

## Wire formats

A **wire format** is the exact byte layout the receiving SIEM expects.
Selectable via `PROBECTL_SIEM_FORMAT` (or the preset's default):

- **`syslog`** — RFC 5424, the classic line-based log protocol, with structured
  data (`[probectl@32473 tenant="…" …]`).
- **`cef`** — ArcSight CEF (the pipe-delimited Common Event Format:
  `CEF:0|probectl|probectl|…`), tenant in `cs1`.
- **`ecs`** — Elastic Common Schema JSON (Elastic's standard field naming:
  `event.*`, `organization.id` = tenant).
- **`otlp`** — OTLP/HTTP logs JSON (the OpenTelemetry log protocol; resource
  attr `probectl.tenant_id`).

## Presets

`PROBECTL_SIEM_PRESET` adapts the auth header + the default format to a target
SIEM. The **endpoint is operator-supplied** (the HEC / ingest / Elasticsearch
URL — HEC is Splunk's HTTP Event Collector, its token-authenticated ingest
endpoint):

| Preset | Auth header | Default format |
| ------ | ----------- | -------------- |
| `splunk` | `Authorization: Splunk <token>` | cef |
| `sentinel` | `Authorization: Bearer <token>` | cef |
| `elastic` | `Authorization: ApiKey <token>` | ecs |
| `chronicle` | `Authorization: Bearer <token>` | otlp |
| `generic` | `Authorization: Bearer <token>` (if set) | cef |

## Delivery guarantees (no drops)

A SIEM is a security audit destination, so the design rule is: **never silently
drop an event** — a gap in the security record is indistinguishable from an
attacker erasing tracks. The two streams reach that guarantee by different
means.

```mermaid
%%{init: {'theme':'base','themeVariables':{'background':'#0d1117','primaryColor':'#161b22','primaryTextColor':'#e6edf3','primaryBorderColor':'#3b82f6','lineColor':'#8b949e','secondaryColor':'#21262d','tertiaryColor':'#0d1117','clusterBkg':'#161b22','clusterBorder':'#30363d','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'},'flowchart':{'curve':'basis','nodeSpacing':55,'rankSpacing':55,'padding':12}}}%%
flowchart LR
  subgraph control[Control plane]
    A[Audit chain<br/>per tenant] -->|Drain from cursor| P[SIEM audit poller]
    T[Threat consumers<br/>TLS / IOC] -->|Enqueue| B[(bounded buffer)]
    P -->|Deliver| F[Forwarder<br/>format + retry]
    B --> F
    C[(siem_delivery<br/>per-tenant cursor)] <-->|advance only past delivered| P
  end
  F -->|HTTPS + auth| S[Operator SIEM]
```

- **Audit path** — `SIEMAuditPoller` drains each tenant's audit events from a
  **durable per-tenant cursor** (`siem_delivery`, RLS-scoped). A **cursor** is a
  persisted bookmark: "everything before this point was delivered." It drains
  one page per short transaction and advances the committed cursor **only past
  events the SIEM acknowledged** — like a registered-mail clerk who crosses an
  item off the ledger only when the signed receipt is in hand. So a restart
  resumes exactly where it paused — no drops, and (outside a narrow crash
  window) no re-sends.
- **Threat path** — consumers **enqueue** signals into a bounded buffer; when it
  is full, producers **block** (backpressure — the pipeline slows down rather
  than throwing events away) instead of dropping. A worker delivers
  with exponential-backoff retry (each failed attempt waits twice as long, up
  to a ceiling, so a struggling SIEM is never hammered).
- **Outage handling** — a SIEM outage pauses the cursor (the poller commits
  whatever was delivered and resumes next tick); the buffer applies backpressure.
  Nothing is silently discarded.

## Governance & redaction

Exported audit events are scrubbed of secrets / PII before they leave the network
— the SIEM gets the security record, never a copy of the credentials inside it.
A built-in case-insensitive denylist (`password`, `passwd`, `secret`, `token`,
`api_key`, `apikey`, `authorization`, `cookie`, `private_key`, `client_secret`,
`ssn`) plus any keys in `PROBECTL_SIEM_REDACT_KEYS` are matched on the audit
record's `data` keys. A redacted value becomes `[redacted]` — the key is kept, so
the SIEM still sees the *shape* of the event without the sensitive value.
After key redaction, the audit-to-SIEM mapper also runs the core governance
PII scanner over actor, action, target, outcome, and every remaining data value
before any syslog/CEF/ECS/OTLP formatter sees the event. That scanner masks
emails and IPs, strips URL query strings/fragments and path IDs, and blanks
embedded bearer tokens or `token=...` / `password=...`-style secrets.

## Security

- **TLS out** — delivery uses the hardened, certificate-validating HTTP client
  (`crypto.HardenedHTTPClient`); validation is never disabled. The ingest token is
  sent only as an auth header, never in a URL (URLs land in proxy and access
  logs; headers do not).
- **Tenant isolation** — the audit poller drains **inside each tenant's RLS scope**;
  the tenant stamped on every exported record is the drained scope's tenant, never
  a value from the event body. One tenant's data can never be forwarded under
  another's id.
- **Secrets** — the ingest token is runtime config; inject it from a secret
  manager, never commit it, and it is never logged.

## Configuration

See [`configuration.md`](configuration.md#siem-export) for the full key table.
Minimal Splunk HEC example:

```sh
PROBECTL_SIEM_ENABLED=true
PROBECTL_SIEM_PRESET=splunk
PROBECTL_SIEM_ENDPOINT=https://splunk.example:8088/services/collector/raw
PROBECTL_SIEM_TOKEN=<hec-token>
```
