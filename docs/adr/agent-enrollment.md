# ADR: Agent enrollment & SVID issuance

**Status:** Accepted (2026-06-07). The token-mint surface is both the admin
API and the operator CLI.

> This is the **decision record** — what we decided and why. The operator
> how-to (mint a token, enroll an agent, rotate, revoke) lives in
> `docs/agent/enrollment.md`. If you want to *run* enrollment, read that; if
> you want to know *why it works this way*, read this.

## The plain version

An agent only gets to talk to the control plane if it presents a valid mTLS
client certificate whose SPIFFE identity names a tenant and an agent. The
server reads the tenant/agent from that *verified* certificate — never from the
request body — so a result can never lie about which tenant it belongs to.

There was a hole: the code *verifies* those certificates, but nothing in the
repo *issued* them. The trust root was an operator running `gen-cert` by hand
and copying files around. So the single strongest isolation mechanism in the
product rested on an undocumented manual step. This ADR closes that hole: a
repo-managed certificate authority issues short-lived agent identities,
bootstrapped by a one-time join token.

## What already existed (this ADR builds on, not around)

- mTLS transport with a SPIFFE URI identity, verified on every connection
  (`internal/agenttransport`, `crypto.ServerMTLSConfigRevocable`), with a
  handshake-checked revocation list.
- `crypto.AgentSPIFFEID(tenant, agent)` — the identity scheme
  `spiffe://probectl/tenant/<tenant>/agent/<agent>`, pinned to one trust
  domain.
- `crypto.CA` — an ECDSA P-256 CA with SPIFFE-SAN leaf issuance (dev/test
  only, until this ADR).
- `crypto.ClientMTLSConfigRotating` — the agent client already hot-reloads its
  certificate material, so rotation needs an *issuer*, not a transport change.
- Registration: the tenant/agent are read from the VERIFIED certificate, never
  the request.

## Decision 1 — Bootstrap: single-use, tenant-scoped join tokens

An operator — through the `agent.write`-gated, audited admin API or the
database-direct CLI — mints an **enrollment token** scoped to a tenant (and
optionally pinned to a fixed agent id): 32 random bytes via `internal/crypto`,
shown once, **stored only as a hash** — the same pattern as session tokens.
The agent presents it exactly once; the row is consumed atomically
(`UPDATE ... WHERE used_at IS NULL`, so a replay finds no row and is refused).
Tokens expire (default 1h), and the storage supports voiding an unused token
before use (no operator command is wired to that yet — the short expiry is the
working bound).

*Why not cloud-IID/OIDC attestation now:* probectl's primary deployments are
sovereign/air-gapped, where there is no cloud identity document to attest
against — a join token works everywhere. The enrollment endpoint is left as a
seam: an `attestor` field on the request leaves room for `aws-iid` / `gcp` /
`oidc` attestors later without changing the *shape* of the issued identity.
(Today only `join-token`, or empty, is accepted; `internal/enroll/enroll.go`
rejects anything else.)

## Decision 2 — CA hierarchy: repo-managed root → intermediate → leaf

- **Agent root CA** (10y, P-256): generated once by
  `probectl-control agent-ca init`; signs ONLY intermediates (`MaxPathLen=1`).
  The root *key* is printed at init for offline custody and is **not** stored —
  runtime operation never needs it.
- **Issuing intermediate** (1y default): held by the control plane and
  **sealed at rest through `internal/tenantcrypto`** (the deployment envelope /
  BYOK — the same posture as every other secret). Signs leaves only.
- **Leaf SVIDs** (default TTL **24h**): issued from a **CSR**, so the private
  key is generated on the agent and never leaves it. The leaf carries the
  SPIFFE URI SAN binding `tenant + agent`, with client-auth EKU only.
- The CA **bundle** (root + intermediate) is what transports trust: agents get
  it at enrollment and on every rotation, so an intermediate roll-over is
  picked up automatically on the next rotation.
- `trustctl` (the sibling certificate-lifecycle product) can later **replace**
  the issuing intermediate; the enrollment/rotation API is the integration
  seam.

## Decision 3 — Issuance flows

**Enroll (pre-identity, HTTPS):** `POST /enroll/agent` on the control API. This
route is *off* `/v1` on purpose — `/v1` is the RBAC-gated session API, whereas
this is a bootstrap surface like `/auth`. The agent has no certificate yet, so
the channel is server-auth TLS only (HTTPS-by-default recipes make that safe);
the request is authenticated by the join token. The server: consumes the token
→ derives `tenant` from the TOKEN (never the request) → assigns or verifies the
agent id → signs a leaf → records the issued identity (serial, SPIFFE id,
expiry) in the registry → returns the leaf plus the CA bundle. The agent is now
registered, so ingest verification immediately vouches for it.

**Rotate (identified, HTTPS):** before expiry (at roughly 2/3 of TTL) the
agent calls `POST /enroll/agent/rotate` on the same HTTPS bootstrap surface,
carrying its CURRENT leaf in the request. Authentication is cryptographic
rather than channel-level: the presented cert must chain to *our* hierarchy
and be time-valid, its serial must be one we recorded at issuance, and the
request must prove possession of the current key (an ECDSA signature over the
new CSR). The server checks the revocation list, then issues a fresh leaf for
the PROVEN identity — the SAN is set server-side and CSR-requested names are
ignored, so identity can never change on rotation — and records it.
`ClientMTLSConfigRotating` hot-swaps the files and connections re-handshake
naturally.

**Agent CLI:** `probectl-agent enroll --server https://control:8443
--token <jt> --dir /var/lib/probectl-agent/identity [--ca-pin <sha256>]`
writes key/cert/bundle (0600) and exits; the runtime config points at those
paths and rotates them automatically. `--ca-pin` (printed at token mint when
the CLI can read the serving certificate) authenticates the SERVER on first
contact in self-signed / quickstart deployments — trust-on-first-use is
refused when a pin is provided and mismatched.

## Threat-model delta (what changes, honestly)

| Threat | Before | After |
|---|---|---|
| Forged tenant claim on the bus | possible with another tenant's REGISTERED agent id over pooled bus creds | agent ids exist only via enrollment; identity is cryptographic end-to-end — registry rows now have an issuance provenance |
| Token theft in transit/at rest | n/a (no tokens) | single-use + short expiry + hash-at-rest + tenant-scoped: a stolen UNUSED token is a bounded window; a USED one is inert; API mints are audited, and every issuance is recorded with provenance (serial, SPIFFE id, expiry) |
| Control-plane DB read | cert material was operator-managed, outside the DB | the intermediate CA key is sealed via `tenantcrypto` (envelope/BYOK); a DB read without the KEK yields ciphertext; token hashes are one-way |
| Stolen agent key | manual revocation of a manually-tracked cert | the 24h leaf TTL bounds exposure; every serial is recorded at issuance and feeds the handshake revocation list |
| Rogue/compromised control plane | already total (it terminates ingest) | unchanged — the issuer *is* the control plane; keeping the root key offline limits blast radius to the intermediate's lifetime |
| Enrollment endpoint abuse | n/a | unauthenticated callers can only burn CPU: every request requires a valid unconsumed token before any signing, and the route is rate-limited like the login surfaces |
| Wrong-tenant enrollment | operator error distributes a cert with the wrong SPIFFE | the tenant comes ONLY from the token; an agent cannot request a tenant |

## Stated residuals

1. There is no workload attestation beyond *possession of the join token* at
   first boot — cloud/OIDC attestors are the documented extension seam
   (Decision 1).
2. The bus credential itself (e.g. Kafka ACLs) is unchanged — the
   consumer-side tenant verification plus cryptographic issuance is the
   compensating pair until per-tenant siloed lanes exist.

## Out of scope (deliberate)

External CA integration (the `trustctl` seam is documented above), cloud
attestors, CRL/OCSP distribution (the in-process revocation list is the
mechanism), and per-probe identities.
