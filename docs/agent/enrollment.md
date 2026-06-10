# Agent enrollment & SVID rotation

How an agent gets — and keeps — its cryptographic identity. This is the
operator how-to; the decision and threat model behind it are in
[`adr/agent-enrollment.md`](../adr/agent-enrollment.md).

The intuition: an agent is useless until it has an **SVID** (a short-lived mTLS
client certificate whose SPIFFE identity names its tenant and agent id). Until
then the mTLS transport refuses its connection, the ingest path won't vouch for
it, and nothing it sends lands anywhere. The trust root is repo-managed — you
do **not** hand-distribute certificates.

The lifecycle is four steps: set up the CA once, mint a join token, redeem it
on the agent, and let the runtime rotate forever after.

## One-time deployment setup

```sh
probectl-control agent-ca init
```

This generates the certificate hierarchy: **root** (10y, signs intermediates
only) → **issuing intermediate** (1y, sealed at rest via the deployment
envelope) → leaf SVIDs (24h). The ROOT private key is printed **once** to
stdout for offline custody (HSM / sealed envelope / offline vault) and is never
stored — runtime operation never needs it. Re-running refuses to overwrite the
trust root.

The control plane's agent gRPC listener verifies every connecting agent's
certificate against this agent CA, which it reads from a file
(`PROBECTL_AGENT_TLS_CA_FILE`). Export that public trust bundle (root +
intermediate — never a key) with:

```sh
probectl-control agent-ca export /etc/probectl/agent-ca.crt   # "-" writes to stdout
```

Point `PROBECTL_AGENT_TLS_CA_FILE` at the result. `export` copies only public
certificates, so it needs no envelope key and works anywhere the database is
reachable (set `PROBECTL_DATABASE_URL`). It writes one world-readable file and
does not create parent directories — the target directory must already exist.

## Enrolling an agent

**1. Mint a join token** (operator action; both surfaces store only a **hash**
of the token):

```sh
# CLI — talks directly to the control plane's DATABASE, not the API
# (set PROBECTL_DATABASE_URL; works even while the API is down)
probectl-control enroll-token -tenant <tenant-uuid> [-agent <id>] [-name <label>] [-ttl 1h]

# or the admin API (requires the agent.write permission; audited, and the
# token is scoped to the CALLER's tenant)
POST /v1/agents/enroll-tokens   {"agent_id": "...", "ttl_seconds": 3600}
```

The token (`pjt_…`) is shown **once**, is **single-use**, expires (default 1h),
and is **tenant-scoped — the token, not the agent, names the tenant.** The CLI
also prints the server-certificate **pin** for first contact — but only when
`PROBECTL_TLS_CERT_FILE` points at the serving certificate; without it, no pin
prints and you use `--ca-file` in step 2 instead.

**2. Redeem it on the agent host:**

```sh
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
fallback. With neither `--ca-pin` nor `--ca-file`, the system trust roots
verify the server (the right choice when the control plane serves a
publicly-issued certificate).

**3. Point the agent config at the identity** (the paths `enroll` just wrote):

```yaml
tls:
  cert_file: /var/lib/probectl-agent/identity/cert.pem
  key_file:  /var/lib/probectl-agent/identity/key.pem
  ca_file:   /var/lib/probectl-agent/identity/ca.pem
identity:
  server: https://control.example:8443   # enables automatic rotation
```

One subtlety about `tls.ca_file`: it is what the **agent** uses to verify the
**control plane's** server certificates (the gRPC listener, and the HTTPS
endpoint that rotation calls). The enrollment-written `ca.pem` — the agent CA
bundle — verifies them only if you issued those server certificates from the
agent CA. If they come from a different CA (for example the `gen-cert`
quickstart CA), point `ca_file` at *that* CA instead. Two trust checks, two
CAs: the agent verifies the server against `tls.ca_file`; the server verifies
the agent against `PROBECTL_AGENT_TLS_CA_FILE`. The worked laptop example is
in [`getting-started.md`](../getting-started.md).

### Enroll on first boot (token-on-boot)

Steps 2–3 can also happen **automatically on startup**, which suits containers
and DaemonSets: ship a join token instead of a pre-provisioned identity, and the
agent enrolls itself the first time it boots. On startup, if no identity exists
yet (`cert.pem` + `key.pem` are absent) **and** a token is available, the agent
enrolls — writing the identity into the **directory of `tls.cert_file`** — and
then runs. The full config is still required (the normal `tls:` paths name
where the identity will *land*; keep the `cert.pem`/`key.pem` filenames, since
those are what enrollment writes):

```yaml
control_plane:
  grpc_addr: control.example:9443
tls:
  cert_file: /var/lib/probectl-agent/identity/cert.pem   # enrollment writes here
  key_file:  /var/lib/probectl-agent/identity/key.pem
  ca_file:   /etc/probectl/control-ca.crt   # must EXIST at first boot (see below)
identity:
  server: https://control.example:8443
enroll:
  token_file: /var/run/secrets/probectl/join-token   # or the env var below
  # ca_pin: <hex sha256>   # alternative first-contact trust for self-signed deploys
```

```sh
# equivalently, env-only (e.g. a token mounted from a Kubernetes Secret):
PROBECTL_AGENT_JOIN_TOKEN=pjt_...  probectl-agent -config agent.yml
```

`PROBECTL_AGENT_JOIN_TOKEN` takes precedence over `enroll.token_file`. The
enrollment target defaults to `identity.server`; `enroll.server` overrides it.
Each key also has an env form (`PROBECTL_AGENT_ENROLL_TOKEN_FILE`,
`PROBECTL_AGENT_ENROLL_SERVER`, `PROBECTL_AGENT_ENROLL_CA_PIN`) — all
documented in [`configuration.md`](../configuration.md).

**First-contact trust still applies on boot.** The boot enrollment verifies
the control plane with `enroll.ca_pin` if set, else with the file at
`tls.ca_file` — which must therefore already exist at first boot (mount it
alongside the token) — else with the system roots. A missing `ca_file` is
treated as a transient failure: the agent retries and eventually gives up
rather than ever connecting unverified.

It is **idempotent and fail-closed**: an existing identity is never overwritten
(renewal stays the rotation loop's job); a transient failure (e.g. the control
plane isn't up yet, or a 5xx) retries with capped backoff — 1 s doubling up to
30 s — for up to **five minutes**, then exits with an error; a **definitive**
rejection (an HTTP 4xx: a used, expired, invalid, or revoked token; a malformed
CSR) exits immediately with a clear error instead of looping — mint a fresh
single-use token and retry. The token is never logged. With no token, behavior
is unchanged — you enroll out of band with the steps above.

## Rotation

SVIDs live 24h. With `identity.server` set, the runtime rotates
**automatically at roughly 2/3 of the lifetime** (checked once a minute): it
generates a fresh key, proves possession of the current one (an ECDSA
signature over the new CSR), and calls `POST /enroll/agent/rotate` over HTTPS
— verified against `tls.ca_file`; the pin is first-contact only. The server
verifies the presented chain against its own hierarchy, verifies the proof,
checks that the issued serial is one it recorded, checks the revocation list,
and **the identity can never change on rotation** (the server sets the SAN
from the proven identity; CSR-requested names are ignored). Files are replaced
atomically and the mTLS client hot-reloads them on the next handshake — no
restart, no ingest gap. A failed rotation retries every minute while the
current SVID is still valid, logging loudly.

## Security properties (what to rely on)

| Property | Mechanism |
|---|---|
| Replay-proof bootstrap | single-use token, consumed atomically (a replay finds no row); hash-at-rest; short expiry (default 1h); an unused token can additionally be voided in the database |
| Tenant binding | the SPIFFE URI SAN is set by the SERVER from the token's tenant; an agent cannot request one |
| Key custody | agent keys are generated on the agent (CSR flow); the root key lives offline; the intermediate key is sealed at rest |
| Bounded theft | 24h leaf TTL; every issued serial is recorded and feeds the handshake revocation list |
| Throttled bootstrap surface | `/enroll/agent` and `/enroll/agent/rotate` ride the per-IP login throttle; no signing happens before the token/proof check |

## Revoking an agent

```sh
probectl-control revoke-agent -tenant <uuid> -agent <id>     # CLI (database-direct)
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
[`adr/agent-enrollment.md`](../adr/agent-enrollment.md).
