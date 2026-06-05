# Hardening & FIPS 140-3 guide (S-EE1, F32)

This guide covers running probectl in a hardened, regulated, or air-gapped
posture: the FIPS 140-3 build, a STIG/CIS-style hardening checklist, and a
secure-defaults review. It is written for operators of sovereign single-tenant
and MSP/provider deployments alike.

probectl is sovereign by design — it never phones home (guardrail 2), all
crypto routes through one validated-swappable module (guardrail 3), and every
listener is TLS with authenticated, untrusted-by-default ingestion (guardrail
12). The defaults are already hardened; this guide makes the posture explicit
and auditable.

---

## 1. FIPS 140-3 mode

### What the FIPS build is

The crypto abstraction (S3) routes **every** cryptographic primitive through
`internal/crypto`, enforced by a CI guard. That lets a FIPS 140-3 **validated**
module compile in transparently: the FIPS artifact swaps the underlying
implementations while the `Provider` API and all of its outputs stay byte-for-byte
identical (proven by the transparent-swap test).

The FIPS artifact is **the Go Cryptographic Module** (the validated module that
ships with the Go toolchain), selected at build time with `GOFIPS140` and marked
with the `probectl_fips` build tag.

```
make build-fips                 # GOFIPS140=v1.0.0 -tags probectl_fips -> bin/*-fips
make fips-gate                  # build + power-on self-test with the module active
```

Per the ratified editions decision, **the FIPS build is gated by the artifact,
not a runtime license check** — there is no `lic.Has(fips)` gate anywhere. The
`fips` feature in the tier table documents the entitlement (the validated
**distribution** is an Enterprise deliverable); the running binary enforces
nothing license-side for FIPS.

### Power-on self-test (POST)

Both `probectl-control` and `probectl-agent` run `crypto.PowerOnSelfTest()` at
startup, before serving any traffic, and **fail closed** if it errors. The POST:

- Known-answer tests: SHA-256 (FIPS 180-4), HMAC-SHA-256 (RFC 4231),
  PBKDF2-HMAC-SHA-256 (SP 800-132).
- Operational tests: AES-256-GCM seal/open with authenticity (tampered AAD
  rejected); Ed25519 sign/verify through the full PEM round-trip (tampered
  message and foreign key rejected); DRBG draw.
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
| `GODEBUG=fips140=only` | **enforced** mode — non-approved algorithms panic instead of being permitted |

`/v1/editions` reports the live posture under `fips`: `build_tag`,
`module_active`, `enforced`, `module_version`, `self_test_passed`. The Admin →
Editions card shows a FIPS badge when the build or module is present. This is a
**status indicator only** — FIPS is a hardening mode, not a feature surface.

### FIPS coverage / boundary

The **validated cryptographic boundary** is the Go Cryptographic Module. probectl
uses only algorithms inside that boundary for security functions:

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

A condensed, auditable checklist mapped to the §7 guardrails. probectl ships
these as defaults except where noted "operator action".

### Transport & network (guardrail 12)

- [x] Every listener serves **TLS 1.2+** (1.3 preferred); AEAD-only suites.
- [x] Agent ↔ control-plane is **mTLS** with SPIFFE-style tenant-bound identity
      (guardrail 4); no plaintext agent transport.
- [x] REST API, web UI, OTLP, MCP are **HTTPS**; shipped compose + Helm are
      **HTTPS-by-default** (TLS-terminating ingress, HSTS).
- [x] UI sets a **CSP** and **Secure + HttpOnly + SameSite** session cookies.
- [x] Inbound webhooks verify the sender's **HMAC signature**; all ingestion is
      authenticated, tenant-scoped, and treated as untrusted input.
- [x] Outbound fetches **validate certificates** (never disabled); fetched
      content is untrusted.
- [ ] **Operator action:** terminate TLS at a hardened ingress; restrict the
      management/provider plane to an admin network (NetworkPolicy / firewall).

### Identity, access & tenancy (guardrails 1, 5)

- [x] **Tenant isolation** enforced at the storage + query layer (RLS /
      partitions / physical silo), not application code alone; AI/MCP enforce
      tenant **then** RBAC.
- [x] Provider/MSP operators get **no implicit read** of tenant telemetry; access
      is time-bounded, consented, separately-audited break-glass (guardrail 7).
- [x] Passwords: PBKDF2-HMAC-SHA-256, 600k iterations. TOTP MFA available.
- [ ] **Operator action:** wire per-tenant SSO/SCIM; require MFA for admin and
      all provider operators; set least-privilege RBAC roles.

### Crypto & secrets (guardrails 3, 6)

- [x] All primitives via `internal/crypto`; FIPS-swappable (this guide).
- [x] Sensitive config uses envelope encryption at rest; the control plane stores
      no plaintext private keys for managed-host flows.
- [x] Secrets resolve from references (Vault / CyberArk / cloud KMS) — never
      logged, never in URLs or git.
- [ ] **Operator action:** set `PROBECTL_ENVELOPE_KEY` (32-byte base64) from a
      secret manager; enable per-tenant BYOK (S-T6) for regulated tenants.

### Audit & data lifecycle (guardrails 7, and S-T5)

- [x] Config changes and data-access actions write to an immutable,
      tamper-evident audit chain; provider/break-glass actions go to a **separate**
      provider chain.
- [x] Per-tenant export + **verifiable deletion** with a recomputable attestation
      (S-T5); crypto-offboarding destroys per-tenant keys (S-T6).
- [ ] **Operator action:** ship audit streams to your SIEM; set the backup-TTL
      statement (`PROBECTL_BACKUP_RETENTION_NOTE`) and retention policy.

### Sovereignty (guardrails 2, 9, 10, 11)

- [x] **No phone-home** — no outbound telemetry/analytics on by default.
- [x] Threat detection is a **signal**, not an inline IPS; never auto-blocks.
- [x] Open-data/threat-intel is read-only, cached, ingested once, **degrades
      gracefully**; a down feed never breaks core function.
- [x] The web UI is usable **without third-party calls** (no CDN fonts/beacons).
- [x] Remediation is **observe-only / human-gated** by default (guardrail 8).
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
| Crypto module | stdlib (transparent-swappable) | FIPS build (`make build-fips`), `fips140=on` | operator |
| Tenant isolation | pooled (RLS, storage-layer) | siloed/hybrid (S-T2) for regulated tenants | operator |
| Password KDF | PBKDF2-HMAC-SHA-256 ×600k | Same | default ✓ |
| MFA | TOTP available | required for admin + all operators | operator |
| Envelope key | none (keyless dev = passthrough) | `PROBECTL_ENVELOPE_KEY` from a secret manager | operator |
| Per-tenant keys | deployment envelope | BYOK (S-T6) for regulated tenants | operator |
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

## 4. References

- FIPS module behavior: <https://go.dev/doc/security/fips140>
- Editions / licensing: `docs/editions.md`
- Per-tenant keys / BYOK: `docs/byok.md`
- Tenant isolation: `docs/isolation.md`
- Lifecycle / verifiable deletion: `docs/runbooks/tenant-offboarding.md`
- Security guardrails: `CLAUDE.md` §7
