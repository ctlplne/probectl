# Hardening and FIPS 140-3 guide

**Hardening** is the work of removing slack from a deployment — fewer defaults
trusted, fewer ports open, every security claim checked rather than assumed.
This guide covers running probectl in a hardened, regulated, or air-gapped
posture: the FIPS 140-3 build, a STIG/CIS-style hardening checklist (STIG and
CIS are the two widely-used catalogs of security configuration requirements —
the checklists auditors walk), and a secure-defaults review. It is written for
operators of sovereign single-tenant and MSP/provider deployments alike.

probectl is sovereign by design — it never phones home, all crypto routes
through one validated-swappable module, and every listener is TLS with
authenticated, untrusted-by-default ingestion (the project's security
[non-negotiables](../CONTRIBUTING.md)). The defaults are already hardened; this
guide makes the posture explicit and auditable.

---

## 0. Prometheus-mode deployment restriction

In `tsdb=prometheus` mode the upstream Prometheus/VictoriaMetrics (the TSDB —
the time-series database holding metrics) has **no server-side tenancy** of its
own — probectl's query proxy is the boundary. Two layers enforce that in code:
every parsed selector is tenant-forced (`promapi.ForceTenant` strips any
caller-supplied `tenant_id` matcher and pins the authenticated tenant), and the
upstream forwarder itself **refuses** any selector not pinned to exactly one
tenant (`ErrUnscopedUpstreamQuery` in `internal/promapi/upstream.go`).

**Hard deployment restriction:** the upstream TSDB must be reachable ONLY by
the probectl control plane (network policy / private listener / mTLS). Any
user, dashboard, or service with direct network access to the upstream can
read ALL tenants' series. Grafana and federation must go through probectl's
`/prom` endpoints, never the upstream directly.

## 0b. Audit WORM export

**What:** an off-database, tamper-evident copy of the provider audit chain that
survives a database owner deleting rows.

**Why it is needed.** The audit chains are already tamper-*evident* inside
Postgres — each record hash-chains to the previous one (its hash covers the
previous record's hash, so editing, deleting, or reordering any record breaks
every later link; `internal/audit/audit.go`), and the app role has no
UPDATE/DELETE on them. Tamper-evident means tampering cannot be *hidden* — it
does not mean the rows cannot be destroyed: a database *owner* can still
truncate a table. WORM ("Write Once, Read Many") export defends against that:
the record exists somewhere the database owner cannot reach.

**How.** Set `PROBECTL_AUDIT_WORM_DIR` to a mount backed by an **object-lock
bucket** (S3 Object Lock or MinIO in compliance mode — the actual immutability
guarantee lives in the bucket, not in probectl). The provider audit chain then
exports hourly as Ed25519-signed segments (Ed25519 is a compact, fast signature
algorithm; the files are `worm/audit/provider/segment-*.json` plus a `.sig` and
the public key), and every cycle re-verifies signatures, sequence continuity,
and the cross-segment hash chain (`internal/audit/worm.go`).
A purge or gap logs an unmissable error. Because the public key is published next
to the segments, any third party can verify the export with nothing but that
key — no access to probectl required.

The signing key is **persisted, not ephemeral**: set
`PROBECTL_WORM_SIGNING_KEY_FILE` to a PEM path (generated and persisted `0600` on
first boot, reused thereafter) or inject `PROBECTL_WORM_SIGNING_KEY` (base64 PEM)
from your secret manager. **Back this key up like the envelope key** — it is the
identity the whole exported history is signed under; lose it and you forfeit
cross-restart verification of every segment signed before the loss. Enabling WORM
export with no key configured **fails closed**: the control plane refuses to start
rather than mint a fresh key each boot (which would silently invalidate every
prior segment's signature).

## 0c. At-rest encryption — who encrypts what

probectl is self-hosted, so some at-rest encryption is the product's job and
some is necessarily the operator's. This section is the contract that draws the
line; `probectl-control preflight` is the check that keeps it honest.

**What probectl encrypts (on by default).** Sealed tenant values (alert-channel
secrets, integration credentials, ...) are envelope-encrypted through
`internal/tenantcrypto` before they ever reach Postgres. **Envelope encryption**
means the value is encrypted under a data key, and data keys are themselves
encrypted ("wrapped") under one master **key-encryption key** (KEK) — like a
hotel key cabinet: every room has its own key, and the one master key opens
only the cabinet the room keys hang in, so stealing a single room key opens one
room, never the building. The shipped recipes turn this on:

- compose sets `PROBECTL_ENVELOPE_KEY_FILE=/var/lib/probectl/envelope.key` on the
  `controldata` volume — on first boot the control plane **generates** a master
  key there (`0600`) and logs it loudly. **Back that volume up like key
  material**: lose the key and sealed values become unreadable.
- Helm refuses to template without `secrets.envelopeKey` / `existingSecret`.
- Both set `PROBECTL_REQUIRE_AT_REST_ENCRYPTION=true`, so a keyless
  misconfiguration is a **fatal startup error** — never silent plaintext.
- Production should supply its own key: `PROBECTL_ENVELOPE_KEY` (which always
  wins over the file), injected from a KMS / secret manager; or per-tenant BYOK
  on the licensed tier ([byok.md](byok.md)).

**What the operator encrypts (a documented duty, not an assumption).**
probectl does not re-encrypt the bulk telemetry stores' data files — at that
scale it is the storage layer's job. **You MUST provide at-rest encryption for
the volumes backing:**

| Store | Holds | How |
|---|---|---|
| Postgres (`pgdata`) | durable state, tenants, audit, sealed values | dm-crypt/LUKS, ZFS native encryption, or encrypted cloud volume (EBS / PD / Azure Disk) |
| ClickHouse | flow/path/threat/change/cost telemetry | same; ClickHouse disk-level encryption also acceptable |
| Object store | exports, support bundles, WORM segments | server-side encryption or encrypted volume |
| `controldata` | the generated envelope key | encrypted volume strongly recommended — it IS key material |

**The preflight check.**

```text
probectl-control preflight [--strict] [--paths /var/lib/postgresql,/var/lib/clickhouse,/var/lib/probectl]
```

Per data path it reports whether the backing mount is detectably encrypted:
`/dev/mapper/*` (dm-crypt/LUKS; plain LVM also matches — confirm) and
ZFS/eCryptFS pass; a plain block device **warns**, and `--strict` exits
non-zero so regulated profiles and CI can gate on it. Cloud-volume encryption
is invisible from inside a container — if your volumes are encrypted below the
host, set `PROBECTL_STORAGE_ENCRYPTION_ATTESTED=true`: the finding downgrades
to informational and the attestation goes on the record. The check also
reports probectl's own envelope-key posture.

## 1. FIPS 140-3 mode

### What the FIPS build is

FIPS 140-3 is the U.S./Canada government standard for validating cryptographic
modules; **CMVP** — the Cryptographic Module Validation Program — is the body
that tests them and issues the certificate numbers an auditor accepts as proof.
probectl routes **every** cryptographic primitive through one package,
`internal/crypto`, and a CI guard (`scripts/check_crypto_imports.sh`) blocks any
handler or service from calling a crypto primitive directly. That single choke
point is what makes a FIPS build possible: a FIPS 140-3 **validated** module can
be compiled in transparently, swapping the underlying implementations while the
`Provider` API and all of its outputs stay byte-for-byte identical — the same
dashboard and controls, a certified engine under the hood. A test asserts that
the standardized outputs are the same with or without FIPS compiled in, so
"swap the module" is provably not "change the behavior."

The FIPS artifact embeds **the Go Cryptographic Module v1.0.0** — validated under
FIPS 140-3 as **CMVP certificate #5247** (CAVP algorithm certificate A6650 —
CAVP is CMVP's sibling program that validates the individual algorithms;
included in Go 1.24+) — selected at build time with `GOFIPS140` and marked with
the `probectl_fips` build tag.

**Exactly what is and is not certified — read this before quoting FIPS to an
auditor.** The *module* holds the CMVP certificate; **probectl as a product holds
no CMVP certificate of its own.** The accurate claim is: "probectl's FIPS artifact
builds against and operates the FIPS 140-3-validated Go Cryptographic Module
v1.0.0 (CMVP #5247), with a power-on self-test asserting the validated module is
live." The authoritative sources are the
[Go FIPS 140-3 documentation](https://go.dev/doc/security/fips140) and the NIST
CMVP listing for certificate #5247 — verify the certificate number there yourself
rather than taking this doc's word for it. **Certification path:** if a
procurement requires a *product-level* validation (probectl itself listed with
CMVP), that is a separate vendor engagement with an accredited lab — planned only
on concrete regulated-buyer demand. Until then, no probectl-level certificate is
claimed anywhere.

```sh
make build-fips                 # GOFIPS140=v1.0.0 -tags probectl_fips -> bin/*-fips
make fips-gate                  # build + power-on self-test with the module active
```

**The FIPS build is gated by the artifact, not by a runtime license check** —
there is no `lic.Has(fips)` gate anywhere in the code. The `fips` entry in the
tier table documents the entitlement (the validated *distribution* is an
Enterprise deliverable), but the running binary enforces nothing license-side for
FIPS. The build you run is the gate.

### Power-on self-test (POST)

Both `probectl-control` and `probectl-agent` run `crypto.PowerOnSelfTest()` at
startup, before serving any traffic, and **fail closed** if it errors (an
errored self-test means the process refuses to start — never "warn and serve").
The POST:

- Known-answer tests (a KAT feeds an algorithm a fixed input and demands the
  standard's exact published output — catching a swapped or miscompiled
  primitive): SHA-256 (FIPS 180-4), HMAC-SHA-256 (RFC 4231),
  PBKDF2-HMAC-SHA-256 (SP 800-132).
- Operational tests: AES-256-GCM seal/open with authenticity (tampered AAD
  rejected); Ed25519 sign/verify through the full PEM round-trip (tampered
  message and foreign key rejected); DRBG draw (DRBG — deterministic random
  bit generator, the approved construction behind `crypto/rand`).
- In a `probectl_fips` build: asserts the validated module is **actually active**
  (`crypto/fips140.Enabled()`), catching an artifact tagged FIPS but built
  without `GOFIPS140`.

The Go module additionally runs its own CAST / integrity self-tests at init;
the POST proves the probectl integration end-to-end.

### Activating the module

| How | Effect |
|---|---|
| `make build-fips` (`GOFIPS140=v1.0.0`) | bakes `fips140=on` as the default — the artifact runs validated out of the box |
| `GODEBUG=fips140=on` at runtime | enables the module for a normally-built binary |
| `GODEBUG=fips140=only` | **enforced** mode — non-approved algorithms error or panic instead of being permitted. Upstream documents `only` as a best-effort testing/assessment mode, not a production requirement — use it to *prove* your deployment touches only approved algorithms, then run `fips140=on` |

`/v1/editions` reports the live posture under `fips`: `build_tag`,
`module_active`, `enforced`, `module_version`, `self_test_passed`. The Admin →
Editions card shows a FIPS badge when the build or module is present. This is a
**status indicator only** — FIPS is a hardening mode, not a feature surface.

### FIPS coverage / boundary

The **validated cryptographic boundary** is the Go Cryptographic Module. probectl
uses only algorithms inside that boundary for security functions. (In the table,
AEAD means authenticated encryption with associated data — ciphertext that
detects tampering rather than merely hiding content; a KDF is a key-derivation
function, the deliberately-slow transform between a password and a key.)

| Operation | Algorithm | FIPS status |
|---|---|---|
| Digest (`Hash`) | SHA-256 | Approved (FIPS 180-4) |
| MAC (`Sign`/`Verify`) | HMAC-SHA-256 | Approved (FIPS 198-1) |
| AEAD (`Encrypt`/`Decrypt`, envelope) | AES-256-GCM | Approved (SP 800-38D) |
| Password KDF | PBKDF2-HMAC-SHA-256, 600k iters | Approved (SP 800-132); the construction wraps module-validated HMAC-SHA-256 |
| Signatures (license, identity) | Ed25519 | Approved (FIPS 186-5) |
| RNG | DRBG via `crypto/rand` | Approved (SP 800-90A), inside the module |
| TLS | AES-GCM suites + P-256 | Approved; see TLS note below |

**Documented non-approved uses (outside the security boundary, FIPS-defensible):**

- **TOTP** uses HMAC-**SHA-1** (RFC 6238 interop — authenticator apps fix the
  algorithm). HMAC-SHA-1 is permitted in FIPS in HMAC mode; this is not a bare
  SHA-1 digest.
- **Certificate fingerprints** (`CertSHA1`) use SHA-1 **only as a non-secret
  content identifier** (the abuse.ch SSLBL / CT-log scheme), never as a security
  primitive or signature.
- **TLS negotiation** offers both approved (AES-GCM, P-256) and non-approved
  (ChaCha20-Poly1305, X25519) options for broad interoperability. In FIPS mode
  the module **negotiates only the approved subset** — the approved options are
  always present in the hardened config, so handshakes succeed without ChaCha or
  X25519.

For `fips140=only` (enforced) deployments, confirm clients support an AES-GCM
suite and P-256, and that any TOTP/SHA-1 fingerprint paths are acceptable in
your accreditation scope (both are HMAC- or identifier-only uses).

---

## 2. STIG / CIS hardening checklist

A condensed, auditable checklist mapped to the project's security
[non-negotiables](../CONTRIBUTING.md). probectl ships these as defaults except
where noted "operator action".

### Transport & network

- [x] Every listener serves **TLS 1.2+** (1.3 preferred); AEAD-only suites.
- [x] Agent ↔ control-plane is **mTLS** with SPIFFE-style tenant-bound
      identity; no plaintext agent transport.
- [x] REST API, web UI, OTLP, MCP are **HTTPS**; shipped compose + Helm are
      **HTTPS-by-default** (TLS-terminating ingress, HSTS — the response header
      telling browsers to never retry plain HTTP).
- [x] UI sets a **CSP** (Content-Security-Policy — the page's allowlist of what
      may load or execute) and **Secure + HttpOnly + SameSite** session cookies.
- [x] Inbound webhooks verify the sender's **HMAC signature** (a keyed hash
      proving the sender held the shared secret); all ingestion is
      authenticated, tenant-scoped, and treated as untrusted input.
- [x] Outbound fetches **validate certificates** (never disabled); fetched
      content is untrusted.
- [ ] **Operator action:** terminate TLS at a hardened ingress; restrict the
      management/provider plane to an admin network (NetworkPolicy / firewall).

### Identity, access & tenancy

- [x] **Tenant isolation** enforced at the storage + query layer (RLS /
      partitions / physical silo), not application code alone; AI/MCP enforce
      tenant **then** RBAC.
- [x] Provider/MSP operators get **no implicit read** of tenant telemetry;
      access is time-bounded, consented, separately-audited break-glass.
- [x] Passwords: PBKDF2-HMAC-SHA-256, 600k iterations. TOTP MFA available
      (TOTP — the six-digit time-based authenticator-app code).
- [x] Dev auth is **physically absent from release builds**: a release binary
      refuses `PROBECTL_AUTH_MODE=dev` at boot with a fatal error — never a
      warning. Even the local-evaluation build (`make build-devauth`,
      `-tags devauth`) additionally requires
      `PROBECTL_DEV_AUTH_ACK=i-understand` AND a loopback-only bind. The
      `no-devauth-in-release` CI job proves both the symbol absence and the
      boot refusal on every pass.
- [ ] **Operator action:** wire per-tenant SSO/SCIM (SCIM — automated user
      provisioning and deprovisioning from your identity provider); require MFA
      for admin and all provider operators; set least-privilege RBAC roles.

### Crypto & secrets

- [x] All primitives via `internal/crypto`; FIPS-swappable (this guide).
- [x] Sensitive config uses envelope encryption at rest; the control plane stores
      no plaintext private keys for managed-host flows.
- [x] Secrets resolve from references (Vault / CyberArk / cloud KMS) — never
      logged, never in URLs or git.
- [x] At-rest sealing **on by default** in the shipped recipes (generated key
      file + `PROBECTL_REQUIRE_AT_REST_ENCRYPTION=true`, §0c); keyless = fatal.
- [ ] **Operator action:** supply `PROBECTL_ENVELOPE_KEY` from a secret
      manager in production; enable per-tenant BYOK (Bring Your Own Key —
      [byok.md](byok.md)) for regulated tenants; encrypt the bulk telemetry
      volumes (§0c — `preflight --strict`).

### Audit and data lifecycle

- [x] Config changes and data-access actions write to an immutable,
      tamper-evident audit chain; provider/break-glass actions go to a **separate**
      provider chain.
- [x] Per-tenant export + **verifiable deletion** with a recomputable
      attestation; crypto-offboarding destroys per-tenant keys
      ([byok.md](byok.md)).
- [ ] **Operator action:** ship audit streams to your SIEM; set the backup-TTL
      statement (`PROBECTL_BACKUP_RETENTION_NOTE`) and retention policy.

### Sovereignty

- [x] **No phone-home** — no outbound telemetry/analytics on by default.
- [x] Threat detection is a **signal**, not an inline IPS; never auto-blocks.
- [x] Open-data/threat-intel is read-only, cached, ingested once, **degrades
      gracefully**; a down feed never breaks core function.
- [x] The web UI is usable **without third-party calls** (no CDN fonts/beacons).
- [x] Remediation is **observe-only / human-gated** by default — never
      autonomous.
- [ ] **Operator action:** for air-gapped installs, use the air-gapped bundle;
      point AI at a local model (Ollama / vLLM); disable external feeds if policy
      requires.

### Container / host (CIS Docker / Kubernetes)

- [ ] **Operator action:** run as **non-root**, **read-only root filesystem**,
      `no-new-privileges`, all Linux capabilities dropped (the eBPF agent needs
      only `CAP_BPF`/`CAP_PERFMON` where used).
- [ ] **Operator action:** apply NetworkPolicies (default-deny egress; allow only
      the datastores, bus, and explicitly-configured feeds).
- [ ] **Operator action:** enable TLS in transit to Postgres / ClickHouse / Kafka
      (default-on in the multi-tenant/regulated deploy profiles).
- [ ] **Operator action:** pin image digests; scan with your supply-chain tooling.

---

## 3. Secure-defaults review

The shipped default vs the hardened-deployment recommendation, per component.
"Shipped" is what probectl does out of the box; "Hardened" is the regulated
posture. A green default means no action needed.

| Component | Shipped default | Hardened recommendation | Action? |
|---|---|---|---|
| API / UI transport | HTTPS, TLS 1.2+, HSTS, CSP, secure cookies | Same; TLS 1.3-only at the ingress if clients allow | default ✓ |
| Agent transport | mTLS, tenant-bound SPIFFE identity | Same | default ✓ |
| Dev auth | absent from release binaries; `PROBECTL_AUTH_MODE=dev` is a boot refusal (§2) | Same (never deploy a `-tags devauth` build) | default ✓ |
| Crypto module | stdlib (transparent-swappable) | FIPS build (`make build-fips`), `fips140=on` | operator |
| Tenant isolation | pooled (RLS, storage-layer) | siloed/hybrid (see [isolation.md](isolation.md)) for regulated tenants | operator |
| Password KDF | PBKDF2-HMAC-SHA-256 ×600k | Same | default ✓ |
| MFA | TOTP available | required for admin + all operators | operator |
| Envelope key | generated-or-required, fail-closed (§0c) | `PROBECTL_ENVELOPE_KEY` from a KMS/secret manager | default ✓ |
| Bulk telemetry volumes | operator's storage layer (§0c duty) | LUKS/ZFS/cloud-volume encryption + `preflight --strict` | operator |
| Per-tenant keys | deployment envelope | BYOK ([byok.md](byok.md)) for regulated tenants | operator |
| Secrets | env / references | Vault / CyberArk / cloud KMS references only | operator |
| Phone-home | off | off | default ✓ |
| Remediation | observe-only / human-gated | Same (never un-gated) | default ✓ |
| Threat engine | signal-only, no auto-block | Same; export to SIEM | default ✓ |
| External feeds | on, cached, graceful-degrade | off for air-gapped; otherwise pin AUP | operator |
| Audit | tamper-evident, dual-stream | ship to SIEM; verify chain periodically | operator |
| Datastore TLS | on in regulated profiles | on everywhere | operator |
| Container | — (deploy-defined) | non-root, read-only FS, dropped caps, NetworkPolicy | operator |

CI asserts the **code-level** defaults in this table (TLS minimum version,
HSTS, secure-cookie attributes, no-phone-home, the FIPS self-test). The
**operator-action** rows are deployment policy and are validated by the Helm
hardening gate and your own controls.

---

## 3a. Day-2 ops and the strict NetworkPolicy profile

A **NetworkPolicy** is Kubernetes's pod-level firewall rule — it declares which
peers may talk to a pod (ingress) and which the pod may reach (egress). The
default Helm profile ships NetworkPolicy **on**, but with two deliberate
holes: an empty `ingressFrom` (any pod may reach the API port) and an empty
`egressTo` (allow-all egress). That is on purpose — a default install must not
lock itself out of an unknown ingress controller. For regulated or air-gapped
deployments, apply the **strict profile**, which closes both holes:

```sh
helm install probectl deploy/helm/probectl -f deploy/helm/probectl/values-strict.yaml
```

`values-strict.yaml` is full default-deny: a **named** ingress-controller
selector (plus the monitoring namespace for `/metrics` scraping) and an explicit
datastore / bus / IdP egress allow-list — no allow-all rule survives. **Match the
selectors and CIDRs to your cluster before applying.** A wrong selector fails
**closed** (the API becomes unreachable), which is the safe failure direction.
The strict profile also turns on the ServiceMonitor (the Prometheus operator's
scrape-config object) and the backup CronJobs.

Other day-2 surfaces, all chart-managed:

- **Probes:** the control Deployment and the agent DaemonSet both ship liveness
  (`/healthz`) and readiness (`/readyz`) probes. Agent readiness reflects
  flow-source attachment, so a stuck `bpf()` call or a kernel lockdown surfaces
  as *not ready* rather than a silently dead pod.
- **/metrics:** the control plane serves Prometheus self-metrics (process and
  aggregate only — no tenant data) at `/metrics`, scraped by the ServiceMonitor
  (`metrics.serviceMonitor.enabled`).
- **Backups:** Postgres and ClickHouse backup CronJobs are folded into the chart
  behind `backup.enabled` (off by default; supply the credentials secret).

---

## 4. References

- FIPS module behavior: <https://go.dev/doc/security/fips140>
- Editions / licensing: [editions.md](editions.md)
- Per-tenant keys / BYOK: [byok.md](byok.md)
- Tenant isolation models: [isolation.md](isolation.md)
- Storage-layer isolation threat model: [security/tenant-isolation.md](security/tenant-isolation.md)
- Lifecycle / verifiable deletion: [runbooks/tenant-offboarding.md](runbooks/tenant-offboarding.md)
- Security non-negotiables: [../CONTRIBUTING.md](../CONTRIBUTING.md)
