# Advanced data governance (Enterprise: `governance`)

**What this is.** One place for a privacy-strict organization to control how a
tenant's data is **classified**, **redacted**, **retained**, **located**, and
**encrypted**. This feature adds the new classification + redaction mechanism and
**composes** it with capabilities that ship elsewhere in probectl, so an operator
sees one coherent governance view per tenant rather than five scattered settings.

| Concern | Where it lives | Edition |
|---|---|---|
| Data classification (IPs-as-PII) | `internal/govern` | core mechanism |
| Redaction / masking | `internal/govern` | core mechanism |
| Configurable retention + cross-store erasure | `internal/tenantlife` | **core** (a compliance right) |
| Residency controls | siloed stores / region topology | provider / core |
| BYOK / HYOK + no-downtime rotation | `ee/tenantkeys` | `byok` (Enterprise) |
| **The governance POLICY + composed view** | `ee/governance` | **`governance`** (Enterprise) |

The split that matters: the classification + redaction **mechanism is core** — a
redacted export is useful to anyone, so it works on any deployment with no license.
The per-tenant **policy + operator surface** is the `governance` Enterprise
feature, installed onto the core `govern` seam at the attach seam.

---

## Data classification

Every sensitive data **category** has a sensitivity **class**, ordered low → high:
`public` < `internal` < `confidential` < `pii` < `restricted`.

| Category | Default class | Examples |
|---|---|---|
| `ip_address` | **pii** (the headline) | source / dest / exporter / next-hop IPs, probe targets |
| `email` | pii | operator / contact emails |
| `geo` | pii | city / region / coordinates |
| `mac_address` | confidential | device MACs |
| `hostname` | internal | device / exporter hostnames |
| `user_agent` | internal | RUM user agents |
| `asn` | public | autonomous-system numbers |
| `credential` | restricted | secrets, tokens, wrapped keys, BYOK refs |

**IPs-as-PII** is the headline. Under GDPR and similar regimes an IP address *is*
personal data, so `ip_address` defaults to `pii` and is masked by default whenever
redaction is active. A tenant's governance policy can **re-classify** any category
(e.g. treat `hostname` as `pii`).

## Redaction / masking

When redaction is active, every category at or above the policy's **redaction
floor** (default `pii`) is masked. The strategies:

| Strategy | Behavior | Example (`203.0.113.42`) |
|---|---|---|
| `partial` (default) | keep a coarse, non-identifying prefix | `203.0.113.0/24` (IPv4 → /24; IPv6 → /48; email → `a***@domain`; MAC → OUI) |
| `hash` | stable, non-reversible pseudonym (correlatable) | `sha256:1a2b…` (16-hex prefix) |
| `drop` | remove entirely | `` (empty) |
| `none` | leave as-is | unchanged |

`restricted` (credentials) **always drops** in clear — secrets never leave the
deployment in a governed export, regardless of strategy. All hashing routes
through the FIPS-swappable `internal/crypto` (guardrail 3).

## Redacted export

The tenant-portability export gains a **redacted mode**:

```
GET /v1/lifecycle/export?redact=true     # mask PII per the tenant's policy
```

and a tenant whose governance policy sets `redact_export: true` always gets a
redacted export, even without the query parameter. The manifest carries
`"redacted": true`. Postgres rows and flow records are masked column-by-category
(IPs, emails, geo, MACs, …) while non-sensitive fields (counts, protocol, names)
survive. Malformed lines pass through untouched, so the bundle stays well-formed.

The redaction *mechanism* is **core** (the `?redact=true` toggle works on any
deployment with the PII-floor default). The `governance` feature adds **per-tenant
policy** — custom classifications, a custom floor, and forced export redaction.

## The governance policy + composed view

The provider plane exposes one place for a tenant's data governance
(`governance`-gated; the routes 404 when unlicensed):

- `GET /provider/v1/tenants/{id}/governance` — the **composed view**: the effective
  classification of every category + the redaction policy + residency + isolation
  model + retention + BYOK status.
- `PUT /provider/v1/tenants/{id}/governance` — set the policy: classification
  overrides, the redaction floor (`redact_from`), and `redact_export`. Audited
  (`provider.governance_set`), admin-only, and blocked by the read-only license
  degrade.

The policy persists in `tenant_governance` (migration `0033`): a tenant reads its
own policy under RLS, the provider plane writes it. It is on the silo deny list
(never copied into a per-tenant silo schema) and is erased with the tenant at
offboarding. The resolver installs onto the core `govern` seam, so redacted
exports honor per-tenant overrides.

## Retention, erasure & residency (composed, not re-implemented)

The governance view **shows these together**; it does not re-enforce them. Each is
owned by its own subsystem:

- **Retention + cross-store erasure** is core (`internal/tenantlife`): configurable
  flow retention plus verifiable deletion across Postgres / ClickHouse / TSDB /
  object storage, with a recomputable attestation. **Erasure covers all live
  stores**; backups are the operator's documented backup-TTL
  (`PROBECTL_BACKUP_RETENTION_NOTE`) — a governed deletion is not a backup purge.
  See [`runbooks/tenant-offboarding.md`](runbooks/tenant-offboarding.md).
- **Residency** is siloed stores pinned to a region, plus the region topology.
  Strict tenants run **siloed** so their stores stay in the permitted region rather
  than replicating globally. See [`isolation.md`](isolation.md),
  [`multi-region.md`](multi-region.md).
- **BYOK / HYOK + no-downtime rotation** is the `byok` Enterprise feature
  (`ee/tenantkeys`): per-tenant customer-held keys, rotation with
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
  network prefix and `hash` is correlatable. For irreversible removal, use erasure.
