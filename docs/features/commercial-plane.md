# The provider / MSP plane

## What it is

The provider plane is the operator surface a **managed service provider (MSP)** —
an organization that self-hosts probectl once and serves many customer tenants —
or an internal platform team uses to *run* a multi-tenant deployment: provisioning
and suspending tenants, watching fleet-wide health across all of them, metering
each tenant's usage for billing, applying each customer's own branding, honouring
export and residency obligations, and — under tight controls — reaching into a
single tenant's telemetry.

The single most important thing to understand: **a provider operator is a
different kind of user from a tenant user, in a separate security domain, and
running a tenant gives an operator zero ability to read that tenant's data.** The
operator is the landlord — the master key opens the boiler room and the breaker
panel, never the tenants' filing cabinets. Everything on this page enforces that
line.

Five capabilities live here:

- **The provider plane and its privilege model** — operators with no implicit read
  access to tenant telemetry.
- **Metering & billing export** — count each tenant's usage; export a feed your
  billing system imports.
- **White-label branding** — show each customer its own brand.
- **Export / residency / verifiable deletion** — portability and a recomputable
  deletion proof.
- **Per-tenant keys / BYOK (Bring Your Own Key)** — each tenant's data sealed under
  its own key.

Terms of art ([glossary](../glossary.md)) such as MSP, TOTP, RBAC, RLS, BYOK, and
KEK are defined there.

## Why it exists

If one company is going to operate probectl on behalf of many others, two things
must be true at once, and they pull in opposite directions. The operator needs
enough power to *run* the platform — provision tenants, see fleet health, bill
correctly, brand each customer. And the operator must have *none* of the power to
quietly read a customer's network telemetry. A naive "admin can do anything" model
fails the second test instantly.

So the provider plane is built as a separate privilege domain with a hard, audited
wall in front of tenant data:

- **"Can the MSP read our traffic?"** Not without your explicit, time-bounded,
  separately-audited consent. There is *no* standing read access.
- **"How do we bill each tenant accurately?"** Metering counts usage from the
  streams already flowing and exports a vendor-neutral feed.
- **"Can each of our customers see their own brand?"** Yes — branding is a runtime
  override of design values, per tenant.
- **"Can we honour a customer's deletion or data-residency demand, and prove it?"**
  Yes — export and a recomputable deletion attestation, plus regional pinning for
  strict tenants.
- **"Can a customer hold its own encryption keys?"** Yes — BYOK, where the key
  lives in *their* secret manager and probectl never holds it.

## How it works

### The privilege model: operators are not tenant users

Provider operators are a distinct **privilege domain** — a self-contained
authentication world with its own accounts, sessions, and audit, whose credentials
mean nothing in the tenant world and vice versa:

- **Their own accounts and sessions.** A separate session cookie, scoped so a
  browser refuses to attach it to navigation that starts on another site, with a
  short lifetime held in memory by design — a restart deliberately
  re-authenticates this high-privilege domain.
- **Multi-factor authentication is mandatory.** There is no password-only login;
  every sign-in is email plus password plus a time-based authenticator code
  (TOTP). Login failures are deliberately uniform — nothing distinguishes a wrong
  password from a wrong code from an unknown email, so an attacker can't probe
  which part they got right.
- **Separation of duties.** No single account both grants a power and wields it:
  one role manages operators, another runs tenant lifecycle and break-glass.
  Disabling an operator revokes their live sessions immediately, not at the next
  expiry.
- **No implicit read access to tenant telemetry — enforced in the database, not
  just in handler code.** Every provider query runs as a separate database role
  whose only telemetry-adjacent grant is read access to the fleet inventory (so
  the fleet view works). It has *no grant at all* on tests, results, or any other
  tenant telemetry table — so even a buggy or malicious handler physically cannot
  read tenant telemetry. A standing test proves the role is denied.

When the provider plane is not licensed, its routes return a plain *not found* —
the feature is *hidden*, not locked behind an upsell wall. Think of the door not
existing in that build, rather than a locked door with a sales message behind it.

### Break-glass: the only path to tenant telemetry

Since operators have no standing access, "break-glass" is the one narrow,
heavily-controlled way in. The name is the fire-alarm cover: access exists for
genuine emergencies, but using it means visibly shattering the glass — it cannot
be done quietly, and everyone can see it was done. A grant is **explicit,
time-bounded, tenant-consented, operator-bound, and audited on every single
access**:

1. An operator *requests* access to a tenant with a required reason and a lifetime
   (capped by deployment config). The grant starts *pending*.
2. **The tenant decides — not the operator.** A tenant admin approves or denies it,
   authenticated by the *tenant* session, not an operator session. A tenant can
   only ever see and decide its own grants. This consent is what makes the whole
   mechanism legitimate.
3. Only an *active* grant (consented, unexpired, unrevoked) unlocks the read, and
   only for the operator who requested it.
4. **Every access writes an audit record *before* the data is returned** — an
   access that cannot be audited is simply not allowed to happen. Revocation,
   denial, or expiry ends access immediately, and the grant records exactly how
   many audited reads it carried.

All provider actions write to a *separate*, tamper-evident provider audit stream,
distinct from the tenant audit log.

### Metering & billing export

Metering counts each tenant's usage accurately enough to invoice from. There are
two kinds of meter: a **counter** only ever climbs (you *sum* it over a period —
like an odometer), and a **gauge** is a point-in-time level (you take the *peak* —
like a fuel gauge). probectl meters agents and tests (gauges), and results
ingested, ingest bytes, flow events, and AI calls (counters).

The counters derive from the tenant-tagged streams *already flowing* — there is no
parallel metering pipeline — bucketed by the hour and flushed to durable storage
every minute, with failed flushes merged back and retried so counts can be delayed
but never lost or double-counted. The gauges are counted inside each tenant's own
scope, so a siloed tenant is counted exactly once in its own schema and pooled and
siloed tenants cannot double-count each other.

probectl deliberately does **not** build an invoicing engine — it *exports*. The
export feed is vendor-neutral (comma-separated values and JSON Lines), because
every billing system imports those. The column set is a stable contract — only
additive changes are allowed — so an importer never breaks.

Quotas are a related, separate control: they cap how many agents or tests a tenant
may *create* (denied with a clear error), but they **never** drop telemetry —
observability must not silently lose data, and a database blip degrades a quota
check *open* because a quota is a billing control, not a security boundary.

### White-label branding

White-labeling is a *runtime override of design values*. Every screen styles
itself from named design values rather than hardcoded colors, so re-branding is
just overriding those values at runtime — zero per-screen work, like sliding a few
faders on a theater lighting board to re-light the whole show. A brand carries a
product name, an inline logo, a login message, a strict allowlist of color and
typography overrides, email branding, and a custom-domain mapping.

Two safety properties matter:

- **No bleed between tenants.** One tenant's brand must never leak into another's
  resolution. Resolution caches under a strictly-scoped key, an authenticated
  tenant resolves by tenant only (a signed-in tenant-B user on tenant-A's domain
  gets B's brand), and the responses are marked so a shared cache cannot serve the
  wrong brand on the wrong domain. A resolution *failure* degrades to the default
  brand — never an error page, and never another tenant's brand.
- **Override values are injection-safe by construction.** Only narrow shapes are
  accepted — a color, a simple length, a plain font list — and never a fetchable
  URL or an arbitrary expression, so a brand value cannot become a foothold that
  makes every visitor's browser call an attacker's server. Color choices are also
  checked against a contrast bar so a tenant cannot brand its own UI unreadable.

### Export, residency & verifiable deletion

Offboarding **never silently destroys data**. Suspending a tenant rejects its
users at the API but leaves data, agents, and ingestion untouched — a reversible
billing state, not destruction. The actual data export and verifiable deletion is
a separate flow (deliberately a core capability, not gated): erasure removes or
projects data across every *live* store and produces a **recomputable
attestation** — a proof document anyone can re-derive to confirm the deletion
happened. Backups keep their own clock; the attestation records your
backup-erasure deadline rather than reaching into a backup.

Residency for a strict tenant means running it siloed with its telemetry databases
pinned to the permitted region (covered in detail on the tenancy page).

### Per-tenant keys / BYOK

On the licensed tier, each tenant's sensitive at-rest values can be sealed under
that tenant's *own* key. That makes tenants cryptographically separable — even
with raw database access you cannot read tenant A's sealed data without tenant A's
key — and it turns offboarding into a **key-destruction** event: destroy the key,
and any sealed data that ever lingered in a backup becomes permanently unreadable
(crypto-shredding).

There are two modes. In **managed** mode probectl generates a random per-tenant
key and wraps it under the deployment master key (a key whose only job is to lock
up other keys). In **BYOK** mode the key lives in *your* secret manager and
probectl stores only a *reference*, resolving it at use time — the material is
never persisted. The fail-safe rule is non-negotiable: once a value is sealed
under a tenant key, an unavailable or destroyed key is an *error*, never a silent
fallback to a shared key.

## Use it

**Bootstrap the first operator** on a fresh deployment, then enroll with
multi-factor:

```sh
curl -X POST https://control.example/provider/v1/auth/bootstrap \
  -H 'Content-Type: application/json' \
  -d '{"token":"<one-time bootstrap token>","email":"ops@msp.example"}'
```

What you should observe: the first admin is created and the bootstrap path goes
inert the moment *any* operator exists — the token cannot be replayed. The
operator then binds an authenticator app and sets a password before the account
activates.

**Provision a tenant** (the license's tenant band is enforced here):

```sh
curl -X POST https://control.example/provider/v1/tenants \
  -H 'Content-Type: application/json' \
  -d '{"slug":"acme","name":"Acme Corp","isolation_model":"pooled"}'
```

What you should observe: a created tenant. Provisioning past the licensed band
fails loudly with `tenant_band_exhausted` and existing tenants are never affected.

**Export the billing feed** for the current period:

```sh
curl 'https://control.example/provider/v1/usage/export?format=csv'
```

What you should observe: one row per tenant per meter per day — the export defaults
to a month-to-date window at day rollup. Within each day, counters are *summed* and
gauges report the *peak* (you bill for the most agents a tenant ran, not the
average). The stable columns are
`tenant_id,tenant_slug,meter,kind,period_start,period_end,value,unit`, with
timestamps in coordinated universal time.

**Request break-glass access** to a tenant's telemetry (then the *tenant* must
approve from its own session before any read works):

```json
{ "tenant_id": "…", "reason": "Sev1: investigating customer-reported outage", "ttl_minutes": 60 }
```

What you should observe: a grant in state `pending`. It does not unlock any read
until a tenant admin approves it, and every subsequent read writes an audit record
before returning data.

## Pitfalls & limits

- **Operators genuinely cannot read tenant telemetry without consent.** This is
  not a UI nicety — the database role lacks the grant. Break-glass is the only
  path, and it requires the tenant's own approval. Plan your incident process
  around tenant consent, not around operator omnipotence.
- **The provider plane refuses to start without an encryption key configured.**
  Operator authenticator secrets are sealed at rest, so a deployment-wide
  encryption key is a hard prerequisite for the plane to run.
- **probectl is not an invoicing system.** Metering exports usage; you import it
  into your own billing or professional-services-automation tool. Vendor-shaped
  connectors are follow-ups, not shipped today.
- **Quotas gate creation, never telemetry.** A quota can stop a tenant creating a
  new agent or test; it will never drop ingested telemetry, and it degrades *open*
  on infrastructure failure because it is a billing control, not a security
  boundary. Throttling shared ingest is the fairness layer's job (see the tenancy
  page).
- **Custom-domain certificates are yours to issue.** probectl does not auto-issue
  TLS certificates in this release. Each white-label custom domain needs an alias
  DNS record and a certificate at your TLS-terminating front door (managed by your
  own certificate tooling or the sibling certificate-lifecycle product).
- **BYOK means you own the lock.** A dead key reference is rejected *before*
  activation, so you cannot rotate into a key probectl can't reach. But if you
  later revoke probectl's access to the key, your sealed data becomes unreadable
  and there is no recovery path through probectl — that is the feature, not a bug.
  Document your secret manager's own backup and escrow policy.
- **Per-tenant keys cover the sensitive-value class, not the bulk stores.** The
  high-volume telemetry stores rely on isolation-model separation plus verifiable
  deletion at offboarding; per-tenant keys protect sealed sensitive values.
- **Erasure clears live stores, not backups.** A governed deletion attests the
  live-store removal and records your backup-erasure deadline; the destination
  owns its own clock. probectl cannot truthfully promise a backup or an external
  destination already deleted its copy.
- **A licensed feature degrades read-only after expiry, never dark.** Past the
  grace window, provider mutations are refused (no new tenants, operators, or
  grants) while reads keep working and running telemetry pipelines are never
  touched. Branding persists read-only.

## Reference

- **Privilege model:** operators are a separate domain with their own accounts,
  in-memory sessions, mandatory multi-factor login, and separation of duties; the
  provider database role has no grant on tenant telemetry tables. Unlicensed →
  routes return *not found* (hidden, not locked).
- **Break-glass:** request (reason + capped lifetime) → tenant consent →
  active grant → audited-on-every-access; revocation/expiry ends it immediately;
  all provider actions go to a separate tamper-evident audit stream.
- **Tenant lifecycle:** provision (tenant band enforced), configure, suspend
  (reversible; data untouched), resume, offboard (frees the band slot; never
  silently destroys data).
- **Metering:** counters (results ingested, ingest bytes, flow events, AI calls)
  summed; gauges (agents, tests) peaked; export at
  `GET /provider/v1/usage/export?format=csv|jsonl` with a stable additive column
  contract; quotas gate creation only, never drop telemetry.
- **White-label:** runtime override of design values; per-tenant and
  provider-master brands; strict injection-safe override allowlist; no cross-tenant
  bleed; failure degrades to the default brand.
- **Export / deletion:** suspend is reversible; offboarding plus a separate
  verifiable-deletion flow produces a recomputable attestation; residency via
  siloed region-pinned stores.
- **Per-tenant keys / BYOK:** managed (wrapped under the deployment master key) or
  BYOK (reference into your secret manager, material never persisted); unavailable
  key fails closed; offboarding crypto-shreds the key chain.
- **Related capabilities (separate pages):** Tenancy & hard isolation; Running
  probectl in production (governance, residency in multi-region, supportability).

**Covers:** F51, F53, F54, F55, F56
