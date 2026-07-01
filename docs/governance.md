# Advanced data governance (Enterprise: `governance`)

**What this is.** One place for a privacy-strict organization to control how a
tenant's data is **classified** (labeled by sensitivity), **redacted** (masked
before it leaves), **retained** (kept, then deleted on schedule), **located**
(pinned to a region), and **encrypted**. This feature adds the new
classification + redaction mechanism and
**composes** it with capabilities that ship elsewhere in probectl, so an operator
sees one coherent governance view per tenant rather than five scattered settings.

| Concern | Where it lives | Edition |
|---|---|---|
| Data classification (IPs-as-PII) | `internal/govern` | core mechanism |
| Redaction / masking | `internal/govern` | core mechanism |
| Configurable retention + cross-store erasure | `internal/tenantlife` | **core** (a compliance right) |
| Residency controls | siloed stores / region topology | provider / core |
| BYOK / HYOK + no-downtime rotation | `ee/tenantkeys` | `byok` (Enterprise) |
| Remote-AI egress consent (enforcement) | `internal/ai` egress gate | core (fail-closed; consent is *set* via the governance policy) |
| **The governance POLICY + composed view** | `ee/governance` | **`governance`** (Enterprise) |

The split that matters: the classification + redaction **mechanism is core** — a
redacted export is useful to anyone, so it works on any deployment with no license.
The per-tenant **policy + operator surface** is the `governance` Enterprise
feature, installed onto the core `govern` seam at the attach seam.

---

## Data classification

Classification is labeling: every sensitive data **category** (a kind of value
— an IP address, an email — not a specific column) gets a sensitivity
**class**, ordered low → high:
`public` < `internal` < `confidential` < `pii` < `restricted`.
Think of folder labels in a filing cabinet — the label, not the clerk's
judgment per page, decides how a folder is handled when it leaves the room.
(**PII** is personally identifiable information — data that can point back to
a human.)

| Category | Default class | Examples |
|---|---|---|
| `ip_address` | **pii** (the headline) | source / dest / exporter / next-hop IPs, probe targets |
| `email` | pii | operator / contact emails |
| `subject_id` | pii | user IDs, user names, display names, account IDs, session IDs, external IDs |
| `free_text` | pii | log bodies, AI questions/answers, JSON payload text, alert/change summaries |
| `attribute_map` | pii | OTLP resource/span/log attrs, nested JSON maps |
| `dns_name` | pii | DNS qname/resource values that may embed host/user identity |
| `url_path` | pii | HTTP paths and route/target values with subject IDs or credentials |
| `object_key` | pii | support/export/browser artifact keys and object-store paths |
| `geo` | pii | city / region / coordinates |
| `mac_address` | confidential | device MACs |
| `workload_name` | confidential | source/destination workload and service names |
| `org_unit` | confidential | department, team, organization-unit attributes |
| `hostname` | internal | device / exporter hostnames |
| `user_agent` | internal | RUM user agents |
| `asn` | public | autonomous-system numbers |
| `credential` | restricted | secrets, tokens, wrapped keys, BYOK refs |

**IPs-as-PII** is the headline. Under GDPR (the EU's privacy law) and similar
regimes an IP address *is*
personal data — it can identify a household or a person — so `ip_address`
defaults to `pii` and is masked by default whenever
redaction is active. A tenant's governance policy can **re-classify** any category
(e.g. treat `hostname` as `pii`).

## Redaction / masking

When redaction is active, every category at or above the policy's **redaction
floor** (default `pii`) is masked — the floor is a water line: everything at
that sensitivity or above goes under, everything below stays readable. The
strategies:

| Strategy | Behavior | Example (`203.0.113.42`) |
|---|---|---|
| `partial` (default) | keep a coarse, non-identifying prefix | `203.0.113.0/24` (IPv4 → /24; IPv6 → /48; email → `a***@domain`; MAC → OUI) |
| `hash` | stable, non-reversible pseudonym (correlatable) | `sha256:1a2b…` (16-hex prefix) |
| `drop` | remove entirely | `` (empty) |
| `none` | leave as-is | unchanged |

`partial` is "blur the house number, keep the street": analytics can still
group by network, but no value points at one host. (A MAC's **OUI** is its
first three octets — the vendor prefix, shared by millions of devices.)
`hash` is pseudonymization: the same input always yields the same token, so
"this address appears in both records" survives while the address itself does
not. `restricted` (credentials) **always drops** in clear — secrets never
leave the
deployment in a governed export, regardless of strategy. All hashing routes
through the FIPS-swappable `internal/crypto` provider — no raw crypto
primitives outside it.

## Redacted export

The tenant-portability export gains a **redacted mode**:

```text
GET /v1/lifecycle/export?redact=true     # mask PII per the tenant's policy
POST /v1/lifecycle/subjects/export       # body: {"subject":"alice@example.com","redact":true}
```

and a tenant whose governance policy sets `redact_export: true` always gets a
redacted tenant or subject export, even when a requester forgets to ask. The
manifest carries `"redacted": true`. Postgres rows, flow records, and OTLP
subject rows are masked column-by-category (IPs, emails, geo, MACs, …) while
non-sensitive fields (counts, protocol, names) survive. Malformed lines pass
through untouched, so the bundle stays well-formed.

The redaction *mechanism* is **core** (the `?redact=true` toggle works on any
deployment with the PII-floor default). The `governance` feature adds **per-tenant
policy** — custom classifications, a custom floor, and forced export redaction.

## The governance policy + composed view

The provider plane exposes one place for a tenant's data governance
(`governance`-gated; the routes 404 when unlicensed — hidden, not locked):

- `GET /provider/v1/tenants/{id}/governance` — the **composed view**: the effective
  classification of every category + the redaction policy + remote-AI egress
  consent + residency + isolation model + retention + BYOK status.
- `PUT /provider/v1/tenants/{id}/governance` — set the policy: classification
  overrides, the redaction floor (`redact_from`), `redact_export`, and the
  tenant's remote-AI egress consent (`ai_remote_egress`). Audited to the
  separate, tamper-evident **provider audit stream**
  (`provider.governance_set`), admin-only, and blocked by the read-only license
  degrade.

The policy persists in `tenant_governance` (migration `0033`; migration `0037`
adds the `ai_remote_egress` consent column): a tenant reads its
own policy under RLS (row-level security — the database enforces the tenant
boundary itself), the provider plane writes it. It is on the silo deny list
(never copied into a per-tenant silo schema) and is erased with the tenant at
offboarding. The resolver installs onto the core `govern` seam, so redacted
exports honor per-tenant overrides.

### Remote-AI egress consent

`ai_remote_egress` is the tenant's opt-in for sending its telemetry summaries to
a **remote** AI model. It defaults to **false**, and the core AI egress gate
refuses remote synthesis for a non-consenting tenant — no consent row, no
database, or a read error all resolve to *denied* (fail closed). The
governance policy is only where the consent is **recorded**; the disclosure of
exactly what a remote call sends, and the other gates in front of it, is
[`ai-egress.md`](ai-egress.md).

## Retention, erasure & residency (composed, not re-implemented)

The governance view **shows these together**; it does not re-enforce them. Each is
owned by its own subsystem — governance is the dashboard, not a second engine:

- **Retention + cross-store erasure** is core (`internal/tenantlife`): configurable
  flow retention plus verifiable deletion across Postgres / ClickHouse / TSDB /
  object storage, with a recomputable attestation (a proof document anyone can
  re-derive to confirm the deletion happened). **Erasure covers all live
  stores**; backups are the operator's documented backup-TTL
  (`PROBECTL_BACKUP_RETENTION_NOTE`) — a governed deletion is not a backup purge.
  The data-class/purpose matrix is [`data-retention.md`](data-retention.md),
  backed by the code-owned `internal/govern.DataInventory()` inventory;
  the operational procedure is [`runbooks/tenant-offboarding.md`](runbooks/tenant-offboarding.md).
- **Subject lifecycle** is also core (`internal/tenantlife`): `POST
  /v1/lifecycle/subjects/export` and `POST /v1/lifecycle/subjects/erase`
  handle a person or identifier inside the caller's tenant. Identity rows,
  persisted AI answers, flow rows, and OTLP spans/logs are filtered by subject
  after tenant scoping. Audit uses an append-only `privacy.subject_erase` marker
  and projects future reads, so the evidence chain stays sealed while the
  person's visible fields are taped over.
- **Residency** is siloed stores pinned to a region, plus the region topology.
  Strict tenants run **siloed** (their own schemas/databases rather than shared
  ones) so their stores stay in the permitted region rather
  than replicating globally. See [`isolation.md`](isolation.md),
  [`multi-region.md`](multi-region.md).
- **BYOK / HYOK + no-downtime rotation** is the `byok` Enterprise feature
  (`ee/tenantkeys`): per-tenant customer-held keys (bring-your-own-key /
  hold-your-own-key — the tenant, not the platform, controls the key material),
  rotation with
  retired-versions-decrypt-only (no downtime), and crypto-offboarding. See
  [`byok.md`](byok.md).

## Watch-outs

- **Erasure must cover all stores, including the backup policy.** Erasure clears
  the live stores and attests it; backups expire per your documented TTL.
- **BYOK key-unavailability fails safe.** An unreachable / destroyed key is an
  error, never a silent fallback to a shared key.
- **Rotation across high-volume stores is deferred-rewrap.** New data uses the new
  key immediately; old data re-seals on write — no downtime.
- **Redaction is best-effort masking, not anonymization.** `partial` keeps a
  network prefix and `hash` is correlatable. For irreversible removal, use erasure
  — you cannot un-mask, but you also cannot promise a masked value identifies
  nobody.
