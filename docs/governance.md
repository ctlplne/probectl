# Advanced data governance (S-EE3, F34)

probectl's data-governance layer gives privacy-strict organizations one place
to set how a tenant's data is **classified**, **redacted**, **retained**,
**located**, and **encrypted**. S-EE3 adds the new classification + redaction
mechanism and composes it with the slices already shipped:

| Concern | Owner | Edition |
|---|---|---|
| Data classification (IPs-as-PII) | S-EE3 (`internal/govern`) | core mechanism |
| Redaction / masking | S-EE3 (`internal/govern`) | core mechanism |
| Configurable retention + cross-store erasure | **S-T5** (`internal/tenantlife`) | **core** (a compliance right) |
| Residency controls | **S-T2** (siloed) / **S-EE2** (region) | provider / core |
| BYOK / HYOK + no-downtime rotation | **S-T6** (`ee/tenantkeys`) | `byok` (Enterprise) |
| **The governance POLICY + composed view** | **S-EE3** (`ee/governance`) | **`governance`** (Enterprise) |

The classification + redaction **mechanism is core** (a redacted export is
useful to anyone); the per-tenant **policy + surface** is the `governance`
Enterprise feature, installed onto the core `govern` seam at the attach seam.

---

## Data classification

Every sensitive data **category** has a sensitivity **class**, ordered low →
high: `public` < `internal` < `confidential` < `pii` < `restricted`.

| Category | Default class | Examples |
|---|---|---|
| `ip_address` | **pii** (the headline) | source/dest/exporter/next-hop IPs, probe targets |
| `email` | pii | operator / contact emails |
| `geo` | pii | city / region / coordinates |
| `mac_address` | confidential | device MACs |
| `hostname` | internal | device / exporter hostnames |
| `user_agent` | internal | RUM user agents |
| `asn` | public | autonomous-system numbers |
| `credential` | restricted | secrets, tokens, wrapped keys, byok refs |

**IPs-as-PII** is the headline: under GDPR and similar regimes an IP address is
personal data, so `ip_address` defaults to `pii` and is masked by default
whenever redaction is active. A tenant's governance policy can **re-classify**
any category (e.g. treat `hostname` as `pii`).

## Redaction / masking

When redaction is active, every category at or above the policy's **redaction
floor** (default `pii`) is masked. Strategies:

| Strategy | Behavior | Example (`203.0.113.42`) |
|---|---|---|
| `partial` (default) | keep a coarse, non-identifying prefix | `203.0.113.0/24` (IPv4 → /24; IPv6 → /48; email → `a***@domain`; MAC → OUI) |
| `hash` | stable, non-reversible pseudonym (correlatable) | `sha256:1a2b…` |
| `drop` | remove entirely | `` (empty) |
| `none` | leave as-is | unchanged |

`restricted` (credentials) **always drops** in clear — secrets never leave the
deployment in a governed export. All hashing routes through the FIPS-swappable
`internal/crypto` (guardrail 3).

## Redacted export

The S-T5 portability export gains a **redacted mode**:

```
GET /v1/lifecycle/export?redact=true     # mask PII per the tenant's policy
```

and a tenant whose governance policy sets `redact_export: true` always gets a
redacted export. The manifest carries `"redacted": true`. Postgres rows and
flow records are masked column-by-category (IPs, emails, geo, MACs, …) while
non-sensitive fields (counts, protocol, names) survive. Malformed lines pass
through untouched, so the bundle stays well-formed.

The redaction mechanism is **core** (the `?redact=true` toggle works on any
deployment with the PII-floor default); the `governance` feature adds
**per-tenant policy** — custom classifications, a custom floor, and forced
export redaction.

## The governance policy + composed view

The provider plane exposes one place for a tenant's data governance
(`governance`-gated):

- `GET /provider/v1/tenants/{id}/governance` — the **composed view**: the
  effective classification of every category + the redaction policy +
  residency (S-T2) + isolation model + retention (S-T5) + BYOK status (S-T6).
- `PUT /provider/v1/tenants/{id}/governance` — set the policy: classification
  overrides, the redaction floor (`redact_from`), and `redact_export`. Audited
  (`provider.governance_set`), admin-only, blocked by the read-only license
  degrade.

The policy persists in `tenant_governance` (migration 0033, tenant-RLS read +
provider write; on the silo deny list; erased with the tenant at offboarding).
The resolver installs onto the core `govern` seam so redacted exports honor
per-tenant overrides.

## Retention, erasure & residency (composed, not re-implemented)

- **Retention + cross-store erasure** is **S-T5** (core): configurable flow
  retention + verifiable deletion across Postgres / ClickHouse / TSDB / object,
  with a recomputable attestation. **Erasure covers all stores**; the backup
  story is the operator's documented backup-TTL (`PROBECTL_BACKUP_RETENTION_NOTE`)
  — a governed deletion is not a backup purge. See
  `docs/runbooks/tenant-offboarding.md`.
- **Residency** is **S-T2** (siloed stores pinned to a region) and **S-EE2**
  (region topology). Strict tenants run **siloed** so their stores stay in the
  permitted region rather than replicating globally. See `docs/isolation.md`,
  `docs/multi-region.md`.
- **BYOK / HYOK + no-downtime rotation** is **S-T6** (`byok`): per-tenant
  customer-held keys, rotation with retired-versions-decrypt-only (no
  downtime), and crypto-offboarding. See `docs/byok.md`.

The governance view simply **shows them together** — it does not re-enforce
them.

## Watch-outs

- **Erasure must cover all stores, including the backup policy.** S-T5 erases
  the live stores and attests it; backups expire per your documented TTL.
- **BYOK key-unavailability fails safe** (S-T6): an unreachable/destroyed key
  is an error, never a shared-key fallback.
- **Rotation across high-volume stores** is deferred-rewrap (S-T6): new data
  uses the new key immediately; old data re-seals on write — no downtime.
- **Redaction is best-effort masking, not anonymization**: `partial` keeps a
  network prefix and `hash` is correlatable. For irreversible removal, use
  erasure (S-T5).
