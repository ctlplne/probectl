# Agent enrollment & SVID rotation

How an agent gets — and keeps — its cryptographic identity. This is the
operator how-to; the decision and threat model behind it are in
[`adr/agent-enrollment.md`](../adr/agent-enrollment.md).

Three terms carry this page. **mTLS** is mutual TLS — both ends of a
connection present a certificate, so each side proves who it is to the other
in one handshake. An **SVID** (SPIFFE Verifiable Identity Document) is the
agent's half of that proof: a short-lived mTLS client certificate whose
**SPIFFE** identity — a standard URI scheme for naming workloads — names the
agent's tenant (the isolated customer/organization it belongs to) and its
agent id. And a **CA** (certificate authority) is the signer whose signature
makes a certificate trusted: verifying a certificate means checking it chains
back to a CA you already hold.

The intuition: an agent is useless until it has an SVID. Until then the mTLS
transport refuses its connection, the ingest path won't vouch for it, and
nothing it sends lands anywhere. The shape of the whole lifecycle is a company
badge system: the control plane runs the badge office; every badge expires
after a day; a new hire gets through the door the first time with a one-time
invitation letter from HR that names their department; and from then on, the
badge renews itself by proving the current one is still in hand. The trust
root is repo-managed — you do **not** hand-distribute certificates.

The lifecycle is four steps: set up the CA once, mint a join token, redeem it
on the agent, and let the runtime rotate forever after.

## One-time deployment setup

```sh
probectl-control agent-ca init
```

This generates the certificate hierarchy: **root** (10y, signs intermediates
only) → **issuing intermediate** (1y, sealed at rest via the deployment
envelope) → leaf SVIDs (24h). Three tiers instead of one is deliberate: the
root is the master stamp that signs once and goes into the vault, the
intermediate is the working stamp at the front desk, and leaves are what
agents actually carry — if the desk stamp is ever compromised, the vault stamp
mints a replacement without re-keying the deployment. The ROOT private key is
printed **once** to stdout for offline custody (an HSM — dedicated key-safe
hardware — a sealed envelope, or an offline vault) and is never stored —
runtime operation never needs it.
Re-running refuses to overwrite the trust root.

The control plane's agent gRPC listener (gRPC is the streaming protocol
agents use to talk to the control plane) verifies every connecting agent's
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

**1. Mint a join token** (operator action). A **join token** is the one-time
invitation letter: it authenticates exactly one enrollment, and it — not the
agent — decides which tenant the new identity lands in. Both surfaces store
only a **hash** of the token, so a database read can never recover a usable
one:

```sh
# CLI — talks directly to the control plane's DATABASE, not the API
# (set PROBECTL_DATABASE_URL; works even while the API is down)
probectl-control enroll-token -tenant <tenant-uuid> [-agent <id>] [-name <label>] [-ttl 1h]

# or the admin API (requires the agent.write permission; audited, and the
# token is scoped to the CALLER's tenant)
POST /v1/agents/enroll-tokens   {"agent_id": "...", "ttl_seconds": 3600}
```

(One auditing difference between the two: the API mint writes an audit event;
the database-direct CLI mint records who minted on the token row itself but
does not pass through the API's audit path.)

The token (`pjt_…`) is shown **once**, is **single-use**, expires (default 1h),
and is **tenant-scoped — the token, not the agent, names the tenant.** The CLI
also prints the server-certificate **pin** for first contact — a hex SHA-256
fingerprint of the exact certificate the control plane serves, so the agent
can recognize the right server before it holds any CA — but only when
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

To force the same proof-of-possession rotation used by the automatic
two-thirds-lifetime loop (for example, during an operator drill), run:

```sh
probectl-agent rotate \
  --server https://control.example:8443 \
  --dir /var/lib/probectl-agent/identity \
  --ca-file /etc/probectl/control-plane-ca.crt
```

The command verifies HTTPS with `--ca-file`, or by default with the server trust
`enroll` captured (`<dir>/server-ca.pem`; `<dir>/ca.pem` only when the same CA
anchors both channels), keeps the private key on the agent host, preserves the
tenant/agent SPIFFE identity, and atomically replaces the leaf certificate and
key only after successful issuance.

The agent generates its private key **locally** (it never leaves the host) and
sends a **CSR** — a certificate signing request, which carries only the public
key: "please sign this." Back comes the leaf SVID (SPIFFE URI
`spiffe://probectl/tenant/<t>/agent/<a>` — client-auth only, with the SAN set
by the *server*; the SAN, subject alternative name, is the certificate field
that carries the identity), the intermediate, and the trust bundle — all
written 0600 into `--dir`. The agent is simultaneously registered in its
tenant's registry, so ingest verification vouches for it immediately. A
provided `--ca-pin` that mismatches **refuses** the connection — there is no
trust-on-first-use fallback (no "accept whoever answers first and remember
them"). With neither `--ca-pin` nor `--ca-file`, the system trust roots verify
the server (the right choice when the control plane serves a
publicly-issued certificate).

Direct BMP routers reuse this exact enrollment CA, issuance code, identity
tables, rotation proof, and revocation API with a plane-separated identity:
`spiffe://probectl/tenant/<t>/bmp/<router-id>`. Register a router through
`POST /v1/collectors/register` with `plane=bmp` and its locally generated
`csr_pem`. Agent listeners accept only `/agent/`; the BMP listener accepts only
`/bmp/` and requires the certificate's exact SPIFFE ID and serial to exist in
the tenant-scoped registry. A credential therefore cannot cross either the
tenant boundary or the agent/BMP plane boundary.

Plaintext `http://` enrollment is refused before any token or CSR can leave the
host. The only exception is an explicit local-development override
(`--allow-plaintext-loopback`, or `enroll.allow_plaintext_loopback: true` for
first-boot config enrollment), and that override accepts only `localhost` /
loopback IP addresses.

**3. Point the agent config at the identity** (the paths `enroll` just wrote):

```yaml
tls:
  cert_file: /var/lib/probectl-agent/identity/cert.pem
  key_file:  /var/lib/probectl-agent/identity/key.pem
  ca_file:   /var/lib/probectl-agent/identity/server-ca.pem
identity:
  server: https://control.example:8443   # enables automatic rotation
```

Two trust checks, two CAs. `tls.ca_file` is what the **agent** uses to verify
the **control plane's** server certificates (the gRPC listener, and the HTTPS
endpoint that rotation calls); `PROBECTL_AGENT_TLS_CA_FILE` is what the
**server** uses to verify the agent. `enroll` writes the server side of that
pair for you: `server-ca.pem` is the trust the enrollment itself verified the
control plane against — the `--ca-file` bundle, or the certificate a `--ca-pin`
matched — so the printed snippet works as-is. The other bundle it writes,
`ca.pem`, is the **agent CA** trust bundle: it vouches for agents, and verifies
the control plane only in deployments that issue the server certificates from
that same agent CA. If you enrolled with neither flag (a publicly issued
control-plane certificate), no `server-ca.pem` is written and the snippet points
`ca_file` at the system bundle instead. When the control plane's certificate
is later replaced by one a pinned enrollment did not see, update `ca_file` to
the new issuing CA. The worked laptop example is in
[`getting-started.md`](../getting-started.md).

### Enroll on first boot (token-on-boot)

Steps 2–3 can also happen **automatically on startup**, which suits containers
and DaemonSets (the Kubernetes pattern that runs one agent on every node):
ship a join token instead of a pre-provisioned identity, and the agent enrolls
itself the first time it boots. On startup, if no identity exists yet
(`cert.pem` + `key.pem` are absent) **and** a token is available, the agent
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

It is **idempotent and fail-closed** — idempotent meaning a second boot with
an identity already on disk changes nothing, fail-closed meaning doubt ends in
refusal, never in an unverified connection. An existing identity is never
overwritten (renewal stays the rotation loop's job); a transient failure (e.g.
the control plane isn't up yet, or a 5xx) retries with capped backoff — 1 s
doubling up to 30 s — for up to **five minutes**, then exits with an error; a
**definitive** rejection (an HTTP 4xx: a used, expired, invalid, or revoked
token; a malformed CSR) exits immediately with a clear error instead of
looping — mint a fresh single-use token and retry. The token is never logged.
With no token, behavior is unchanged — you enroll out of band with the steps
above.

## Rotation

**Rotation** is replacing the certificate before it expires — the daily badge
renewal. SVIDs live 24h. With `identity.server` set, the runtime rotates
**automatically at roughly 2/3 of the lifetime** (checked once a minute): it
generates a fresh key, proves possession of the current one (an ECDSA
signature over the new CSR — something only the holder of the current private
key can produce), and calls `POST /enroll/agent/rotate` over HTTPS — verified
against `tls.ca_file`; the pin is first-contact only. Note the channel:
rotation rides the HTTPS bootstrap surface, not the mTLS data channel — the
request authenticates itself cryptographically (presented chain + possession
proof) rather than by the connection it arrives on. The server verifies the
presented chain against its own hierarchy, verifies the proof, checks that the
issued serial is one it recorded, checks the revocation list, and **the
identity can never change on rotation** (the server sets the SAN from the
proven identity; CSR-requested names are ignored). Files are replaced
atomically and the mTLS client hot-reloads them on the next handshake — no
restart, no ingest gap. Rotating at 2/3 rather than at the deadline leaves a
third of the lifetime — eight hours — of slack for a down control plane: a
failed rotation retries every minute while the current SVID is still valid,
logging loudly.

**What the retry loop cannot save you from.** Rotation is a network call, so it
is also a reachability problem. If the agent cannot reach `identity.server` for
a whole lifetime — a network policy that admits only telemetry ports, a firewall
rule, a DNS change — the retries expire with the certificate, and an expired
SVID **cannot rotate itself**: the server verifies the presented chain at the
current time and refuses it, exactly as it would refuse a stranger. The agent
must then enroll again with a fresh join token. In Kubernetes this is the whole
reason the chart opens the API port to agent pods
(`networkPolicy.agentEnrollmentFrom`, DPR-174).

The failure is quiet by nature, which is why the product now says it out loud in
three places (DPR-176):

| Where | What it says |
|---|---|
| `GET /v1/agents` | `identity_state` (`current` / `renewal_overdue` / `expired` / `unknown`), `identity_expires_at`, and a sentence in `identity_reason` |
| Admin → Agents | an **Agent identity** column, and a fleet verdict of *Identity expired* whose next safe action is re-enrollment rather than "inspect the heartbeat" |
| `probectl agent list` / `agent get` | an `IDENTITY` column and an `identity:` line |

`renewal_overdue` means the identity is past 75% of its lifetime with no
rotation recorded — the state an agent sits in for hours before it dies, and the
one worth alerting on. `unknown` means no issuance is recorded for that agent
and the lifetime cannot be read; it is never reported as healthy.

## Renewing the issuing CA (once a year, with the offline root)

The intermediate that signs every SVID lives **one year**, and the root that can
replace it is offline by design — so the deployment cannot renew itself. When it
expires, enrollment and rotation refuse, and the fleet stops within one SVID
lifetime. This is the one dated maintenance task the product has (DPR-177):

```sh
# with the root key retrieved from custody for this one command:
probectl-control agent-ca renew -root-key ./root.key        # -years 1 by default
probectl-control agent-ca export /etc/probectl/agent-ca.crt # re-export wherever it is pinned
# then put root.key back in offline custody and delete the copy
```

**On Kubernetes, pipe the key in — do not try to copy it in.** The control image
is distroless: no shell, no `tar`, so `kubectl cp` into it fails with
`exec: "tar": executable file not found in $PATH`. `-root-key -` reads the key
from stdin instead, the same way `agent-ca export -` writes the bundle to stdout
(DPR-191):

```sh
kubectl -n probectl exec -i deploy/probectl -c control -- \
  probectl-control agent-ca renew -root-key - < ./root.key
kubectl -n probectl exec deploy/probectl -c control -- \
  probectl-control agent-ca export - > ./agent-ca.crt
```

`exec -i` is not optional — without it the command gets a closed stdin and
refuses rather than guessing. **Do not mount the root key as a Secret** to get
around this: that writes the offline root into etcd and onto every replica, which
is the one thing keeping it offline exists to prevent. Piped into `exec -i`, the
key exists only in the command's memory for the length of the call.

Renewal is safe to run at any time, including long before the deadline: the
superseded intermediate is **kept until its own expiry**, so every agent still
holding a leaf it signed keeps verifying and moves onto the new chain at its
next rotation. Nothing is re-enrolled, no agent is restarted, and the trust
bundle carries both issuing certificates for the length of the overlap.

You do not have to remember the date. `GET /v1/diagnostics` (admin) and the
support bundle carry an `agent_ca` check that goes **degraded** once the
intermediate is three quarters through its life — about 91 days of warning on
the shipped one-year lifetime — and says exactly which command to run. It is
deliberately NOT part of `/readyz`: a CA that expires in three months is
something to schedule, not a reason to take a healthy replica out of the load
balancer.

## Security properties (what to rely on)

| Property | Mechanism |
|---|---|
| Replay-proof bootstrap | single-use token, consumed atomically (a replay finds no row); hash-at-rest; short expiry (default 1h); an unused token can additionally be voided in the database |
| Tenant binding | the SPIFFE URI SAN is set by the SERVER from the token's tenant; an agent cannot request one |
| Key custody | agent keys are generated on the agent (CSR flow); the root key lives offline; the intermediate key is sealed at rest |
| Bounded theft | 24h leaf TTL; every issued serial is recorded and feeds the handshake revocation list |
| Throttled bootstrap surface | `/enroll/agent` and `/enroll/agent/rotate` ride the per-IP login throttle; no signing happens before the token/proof check |

## Revoking an agent

**Revocation** means telling the deployment to stop trusting an identity
*before* its certificate expires — the badge office's deny-list at the door:

```sh
probectl-control revoke-agent -tenant <uuid> -agent <id>     # CLI (database-direct)
POST /v1/agents/{id}/revoke                                  # admin API (agent.write, audited)
```

A *join token* that leaked before anyone redeemed it has its own, smaller
revoke — voiding the invitation rather than the badge (the id is printed when
the token is minted; single-use + the ~1h expiry already bound the exposure):

```sh
probectl-control revoke-enroll-token -id <token-id>
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
