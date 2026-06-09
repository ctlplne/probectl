# Agent enrollment & SVID rotation

How an agent gets — and keeps — its cryptographic identity. This is the
operator how-to; the decision and threat model behind it are in
`docs/adr/agent-enrollment.md`.

The intuition: an agent is useless until it has an **SVID** (a short-lived mTLS
client certificate whose SPIFFE identity names its tenant and agent id). Until
then the mTLS transport refuses its connection, the ingest path won't vouch for
it, and nothing it sends lands anywhere. The trust root is repo-managed — you
do **not** hand-distribute certificates.

The lifecycle is four steps: set up the CA once, mint a join token, redeem it
on the agent, and let the runtime rotate forever after.

## One-time deployment setup

```
probectl-control agent-ca init
```

This generates the certificate hierarchy: **root** (10y, signs intermediates
only) → **issuing intermediate** (1y, sealed at rest via the deployment
envelope) → leaf SVIDs (24h). The ROOT private key is printed **once** to
stdout for offline custody (HSM / sealed envelope / offline vault) and is never
stored — runtime operation never needs it. Re-running refuses to overwrite the
trust root.

## Enrolling an agent

**1. Mint a join token** (operator action; both surfaces audit the mint and
store only a hash of the token):

```
# CLI on the control host
probectl-control enroll-token --tenant <tenant-uuid> [--agent <id>] [--ttl 1h]

# or the admin API (requires the agent.write permission)
POST /v1/agents/enroll-tokens   {"agent_id": "...", "ttl_seconds": 3600}
```

The token (`pjt_…`) is shown **once**, is **single-use**, expires (default 1h),
and is **tenant-scoped — the token, not the agent, names the tenant.** The CLI
also prints the server-certificate **pin** for first contact.

**2. Redeem it on the agent host:**

```
probectl-agent enroll \
  --server https://control.example:8443 \
  --token pjt_... \
  --dir /var/lib/probectl-agent/identity \
  --ca-pin <hex sha256>        # for self-signed quickstarts; or --ca-file ca.crt
```

The agent generates its private key **locally** (it never leaves the host),
sends a CSR, and receives: the leaf SVID (SPIFFE URI
`spiffe://probectl/tenant/<t>/agent/<a>` — client-auth only, with the SAN set
by the *server*), the intermediate, and the trust bundle — all written 0600
into `--dir`. The agent is simultaneously registered in its tenant's registry,
so ingest verification vouches for it immediately. A provided `--ca-pin` that
mismatches **refuses** the connection — there is no trust-on-first-use
fallback.

**3. Point the agent config at the identity** (the paths `enroll` just wrote):

```yaml
tls:
  cert_file: /var/lib/probectl-agent/identity/cert.pem
  key_file:  /var/lib/probectl-agent/identity/key.pem
  ca_file:   /var/lib/probectl-agent/identity/ca.pem
identity:
  server: https://control.example:8443   # enables automatic rotation
```

## Rotation

SVIDs live 24h. With `identity.server` set, the runtime rotates
**automatically at roughly 2/3 of the lifetime**: it generates a fresh key,
proves possession of the current one (an ECDSA signature over the new CSR), and
calls `POST /enroll/agent/rotate`. The server verifies the chain against its
own hierarchy, verifies the proof, checks that the issued serial is one it
recorded, and **the identity can never change on rotation.** Files are replaced
atomically and the mTLS client hot-reloads them on the next handshake — no
restart, no ingest gap. A failed rotation retries every minute while the
current SVID is still valid, logging loudly.

## Security properties (what to rely on)

| Property | Mechanism |
|---|---|
| Replay-proof bootstrap | single-use token, consumed atomically; hash-at-rest; expiry; revocable before use |
| Tenant binding | the SPIFFE URI SAN is set by the SERVER from the token's tenant; an agent cannot request one |
| Key custody | agent keys are generated on the agent (CSR flow); the root key lives offline; the intermediate key is sealed at rest |
| Bounded theft | 24h leaf TTL; every issued serial is recorded and feeds the handshake revocation list |
| Throttled bootstrap surface | `/enroll/agent` and `/enroll/agent/rotate` ride the per-IP login throttle; no signing happens before the token/proof check |

## Revoking an agent

```
probectl-control revoke-agent -tenant <uuid> -agent <id>     # CLI
POST /v1/agents/{id}/revoke                                  # admin API (agent.write, audited)
```

Both persist the revocation (so it survives a restart) and feed the mTLS
handshake deny-list. The API pushes it live immediately; the running control
plane also reloads the persisted list every 30s, which is how CLI-side
revocations propagate. From the next connection, a revoked agent's handshakes
are refused, its live serials are denied, and its SPIFFE id is denied (so even
a re-issued cert is refused) — and **enrollment and rotation both refuse the
identity.** There is no resurrection path short of an operator un-revoking it in
the database.

For the full threat-model delta and the stated residuals, see
`docs/adr/agent-enrollment.md`.
