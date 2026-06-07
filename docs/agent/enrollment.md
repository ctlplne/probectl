# Agent enrollment & SVID rotation

How an agent gets — and keeps — its cryptographic identity (Sprint 11; ADR:
`docs/adr/agent-enrollment.md`). Until enrollment, an agent has no SVID; the
mTLS transport refuses it, the bus consumers won't vouch for it (Sprint 4),
and nothing it sends lands anywhere. The trust root is repo-managed, not an
operator's hand-distributed certificate.

## One-time deployment setup

```
probectl-control agent-ca init
```

Generates the hierarchy: **root** (10y, signs intermediates only) →
**issuing intermediate** (1y, sealed at rest via the deployment envelope) →
leaf SVIDs (24h). The ROOT private key is printed **once** for offline custody
(HSM / sealed envelope / offline vault) and is never stored — runtime
operation never needs it. Re-running refuses to overwrite the trust root.

## Enrolling an agent

**1. Mint a join token** (operator; both surfaces audit and store only a hash):

```
# CLI on the control host
probectl-control enroll-token --tenant <tenant-uuid> [--agent <id>] [--ttl 1h]

# or the admin API (agents.write)
POST /v1/agents/enroll-tokens   {"agent_id": "...", "ttl_seconds": 3600}
```

The token (`pjt_…`) is shown **once**, is **single-use**, expires (default
1h), and is **tenant-scoped — the token, not the agent, names the tenant**.
The CLI also prints the server-certificate **pin** for first contact.

**2. Redeem it on the agent host:**

```
probectl-agent enroll \
  --server https://control.example:8443 \
  --token pjt_... \
  --dir /var/lib/probectl-agent/identity \
  --ca-pin <hex sha256>        # self-signed quickstarts; or --ca-file ca.crt
```

The agent generates its key **locally** (it never leaves the host), sends a
CSR, and receives: the leaf SVID (SPIFFE URI
`spiffe://probectl/tenant/<t>/agent/<a>` — client-auth only, server-set SAN),
the intermediate, and the trust bundle — written 0600 into `--dir`. The agent
is simultaneously registered in its tenant's registry, so ingest verification
(Sprint 4) vouches for it immediately. A provided `--ca-pin` that mismatches
**refuses** — there is no trust-on-first-use fallback.

**3. Point the agent config at the identity** (printed by `enroll`):

```yaml
tls:
  cert_file: /var/lib/probectl-agent/identity/cert.pem
  key_file:  /var/lib/probectl-agent/identity/key.pem
  ca_file:   /var/lib/probectl-agent/identity/ca.pem
identity:
  server: https://control.example:8443   # enables automatic rotation
```

## Rotation

SVIDs live 24h. With `identity.server` set, the runtime rotates **automatically
at ~2/3 of the lifetime**: it generates a fresh key, proves possession of the
current one (an ECDSA signature over the new CSR), and calls
`POST /enroll/agent/rotate` — the server verifies the chain against its own
hierarchy, the proof, and the issued-serial provenance, and **the identity can
never change on rotation**. Files are replaced atomically; the mTLS client
hot-reloads them per handshake (no restart, no ingest gap). A failed rotation
retries every minute while the current SVID is valid, logging loudly.

## Security properties (what to rely on)

| Property | Mechanism |
|---|---|
| Replay-proof bootstrap | single-use token, consumed atomically; hash-at-rest; expiry; revocable before use |
| Tenant binding | the SPIFFE URI SAN is set by the SERVER from the token's tenant; agents cannot request one |
| Key custody | agent keys are generated on the agent (CSR flow); the root key lives offline; the intermediate key is sealed at rest |
| Bounded theft | 24h leaf TTL; every issued serial is recorded (feeds the handshake revocation list — operator path: Sprint 12) |
| Throttled bootstrap surface | `/enroll/agent[/rotate]` ride the per-IP login throttle; no signing before the token/proof check |

## Revoking an agent (Sprint 12)

```
probectl-control revoke-agent -tenant <uuid> -agent <id>     # CLI
POST /v1/agents/{id}/revoke                                  # admin API (agents.write, audited)
```

Both persist the revocation (restart-proof) and feed the mTLS handshake
deny-list: the API pushes it live immediately; the running control plane also
reloads the persisted list every 30s (which is how CLI-side revocations
arrive). A revoked agent's handshakes are refused from the next connection,
its live serials are denied, its SPIFFE id is denied (so a re-issued cert is
refused too), and **enrollment/rotation refuse the identity** — there is no
resurrection path short of an operator un-revoking in the database.

Threat-model details and the stated residuals: the ADR's threat-model delta.
