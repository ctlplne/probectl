# Getting started: from zero to first real data

Most "install" guides stop the moment the control plane answers `/readyz`. That
feels like success — but a control plane on its own **observes nothing**. This
guide takes you the rest of the way: to **actual data on the screen**.

## The one idea that explains everything: consumer vs. producer

probectl has two kinds of moving part, and almost every "why do I see nothing?"
question comes from blurring them:

- The **control plane** is a **consumer**. It receives data, stores it, correlates
  it, and serves the API/UI. It produces *no* observations of its own. (Its
  tagline — *see everything, send nothing* — is about telemetry never leaving
  your network, not about the box magically seeing traffic.)
- **Agents and collectors** are the **producers**. They are what actually watch
  the network: a synthetic probe *sends* traffic and times the answer; an eBPF
  agent *reads* the kernel's view of real connections; a flow collector *receives*
  NetFlow from your routers. Each one ships what it sees to the control plane.

> **No producers = no data.** A freshly installed control plane is a perfectly
> healthy database with nothing writing to it. `/readyz` is green and the
> dashboards are empty — that is expected, not a bug. The fix is always the same:
> **attach a producer.**

This guide brings up one control plane, then walks **three independent ways** to
put first data behind it, and finally **combines** them into the payoff probectl
is built for — a single correlated incident drawn from more than one plane.

```mermaid
%%{init: {'theme':'base','themeVariables':{'background':'#0d1117','primaryColor':'#161b22','primaryTextColor':'#e6edf3','primaryBorderColor':'#3b82f6','lineColor':'#8b949e','secondaryColor':'#21262d','tertiaryColor':'#0d1117','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'},'flowchart':{'curve':'basis','nodeSpacing':50,'rankSpacing':45,'padding':12}}}%%
flowchart LR
  subgraph P["producers (what you add in this guide)"]
    A["canary agent<br/>(synthetic probes)"]
    E["eBPF host agent<br/>(real flows)"]
  end
  A -- "gRPC / mTLS" --> CP["control plane<br/>(consumer)"]
  E -- "bus (Kafka)" --> CP
  CP --> UI["API / UI<br/>(data on the screen)"]
```

---

## The fastest way to first data: the evaluation stack

If you just want to *watch probectl collect data* with one command and no Go
toolchain, use the **evaluation stack** ([`deploy/compose/eval.yml`](../deploy/compose/eval.yml)).
It is a local-only, clearly-fenced build that removes the three things stopping
the shipped all-in-one from showing data on a laptop (it publishes no agent port,
ships no evaluation auth, and expects an external identity provider). Everything
here runs entirely inside Docker.

> **Eval-only, on purpose.** The eval stack runs the API in `dev` auth — every
> request is an unauthenticated, all-powerful admin — so the control plane
> **binds loopback only and is never published to your network**; you read it
> through an in-container helper. It also uses a plaintext bus and a self-signed
> certificate. Perfect for a laptop, never for production. The production-shaped
> stack is [`deploy/compose/probectl.yml`](../deploy/compose/probectl.yml) (see
> [`install.md`](install.md)).

### See first data — no enrollment, any OS

This brings up Postgres + Kafka + the control plane, plus an **eBPF agent in
fixture mode** that replays a recorded **SAMPLE** flow file onto the bus. The
control plane consumes it and folds the flows into the service-map (topology)
graph:

```sh
# Builds the local eval images on first run (a couple of minutes), then starts.
docker compose -f deploy/compose/eval.yml up --build -d

# Give the control plane ~20s to migrate + start, then read first data:
docker compose -f deploy/compose/eval.yml --profile tools run --rm viewer
```

The `viewer` is a tiny `curl` helper that **shares the control plane's network
namespace** — the only way to reach the loopback-only API. It prints the
`/v1/topology` graph: nodes and flow edges built from the sample connections
(e.g. `10.0.1.5 → 10.0.2.9:443`). That JSON is **real data through the real
pipeline** — agent → Kafka → consumer → topology — proving the loop end to end.
It is clearly *sample input*, not traffic on your machine. (If you get a
connection error, the control plane is still starting — wait a few seconds, or
watch `docker compose -f deploy/compose/eval.yml logs control` for
`agent gRPC listening` / `tenant isolation posture verified`.)

Tear it all down with `docker compose -f deploy/compose/eval.yml down -v`.

### Add synthetic probes — the canary, with enrollment

Active probes need an enrolled, mutually-authenticated agent, so they layer on
[`deploy/compose/eval-synthetic.yml`](../deploy/compose/eval-synthetic.yml),
which provisions the agent CA and turns on the control plane's agent gRPC
listener. Mint a join token, enroll the canary, run it, then read its results:

```sh
docker compose -f deploy/compose/eval.yml -f deploy/compose/eval-synthetic.yml up --build -d

# 1. mint a one-time join token (prints pjt_…):
docker compose -f deploy/compose/eval.yml -f deploy/compose/eval-synthetic.yml \
  exec control /usr/local/bin/app enroll-token \
  -tenant 00000000-0000-0000-0000-000000000001 -name laptop

# 2. enroll the canary with that token:
PROBECTL_JOIN_TOKEN=pjt_xxx docker compose -f deploy/compose/eval.yml \
  -f deploy/compose/eval-synthetic.yml --profile synthetic run --rm canary-enroll

# 3. start the canary, then read its synthetic results:
docker compose -f deploy/compose/eval.yml -f deploy/compose/eval-synthetic.yml \
  --profile synthetic up -d canary
docker compose -f deploy/compose/eval.yml --profile tools run --rm \
  -e URL=/v1/results/latest viewer
```

> **The synthetic overlay is the most intricate part of the eval and ships
> authored-but-unrun** — give it one real pass and expect to nudge a detail. If
> it misbehaves, the **from-source walkthrough below** is the fully
> ground-truthed canary path and needs none of this overlay.

You already have data — you can jump to [where to go next](#you-have-data--where-to-go-next).
The rest of this guide builds the same thing **by hand from source**, which is
worth reading if you want to understand every moving part, or to drive the real
production-shaped control plane rather than the eval build.

---

## Building it yourself from source (the ground truth under the eval stack)

This matters, because it changes the commands below — so read it once.

The **shipped all-in-one** ([`deploy/compose/probectl.yml`](../deploy/compose/probectl.yml))
is deliberately minimal: it runs **only the control plane (HTTPS on 8443) plus a
Postgres**. It does **not** publish the agent gRPC port, does **not** wire the
agent-transport TLS files, and runs a **release image** — which (by design) has
**no built-in evaluation auth**. It is the right thing for a production-shaped
control plane, and [`install.md`](install.md) is its home. But you cannot attach a
canary to it, or drive its API without an identity provider, *without extra
wiring* — so it is not the smoothest "see data today" path.

The **dev dependency stack** ([`deploy/compose/dev.yml`](../deploy/compose/dev.yml))
is the opposite shape: it brings up the **backing services** a fuller control
plane talks to — **Postgres + Kafka + ClickHouse + Prometheus** — but **no control
plane** (you run that from source against it).

The **eval stack above** is the one-command shortcut over exactly this shape. To
do it by hand — to see every moving part, or to drive the production-shaped
control plane rather than the eval build — **build the binaries from source
once**, run the dev dependency stack, and run the control plane **from source**
wired to it. That single control plane serves **all three** producer paths below.

> **Everything below assumes one tenant**, the built-in default tenant
> `00000000-0000-0000-0000-000000000001`. In a real multi-tenant or provider
> deployment you create tenants first (see [`admin.md`](admin.md)); the
> single-tenant case is just the one-tenant version of the same code.

### Shared setup — one control plane for all three paths

**1. Build the binaries** (Go 1.26+). `make build` produces every component in
`./bin`; `make build-devauth` produces a control plane with **evaluation auth**
compiled in (so you can drive the API without an IdP — see the warning below).

```sh
make build           # ./bin/probectl-control, probectl-agent, probectl-ebpf-agent, ...
make build-devauth   # ./bin/probectl-control-devauth  (LOCAL EVALUATION ONLY)
```

**2. Start the backing services** (Postgres + Kafka + ClickHouse + Prometheus):

```sh
make compose-up      # docker compose -f deploy/compose/dev.yml up -d --wait
```

**3. Run the control plane from source, wired to those services.** This single
environment turns on what every path below needs — the agent **gRPC/mTLS** listener
(for the canary) and the **Kafka** bus + **ClickHouse** stores (for the bus-based
producers):

```sh
# Apply the schema once.
PROBECTL_DATABASE_URL='postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable' \
  ./bin/probectl-control migrate

# Create the agent certificate hierarchy once (Path 1 uses it; harmless otherwise).
# The root key prints ONCE — copy it somewhere safe; runtime never needs it again.
PROBECTL_DATABASE_URL='postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable' \
  ./bin/probectl-control agent-ca init

# A self-signed server cert (tls.crt/tls.key/ca.crt). The control plane serves
# HTTPS with it, and Path 1's agent enrollment reuses it. SANs: localhost,127.0.0.1.
./bin/probectl-control gen-cert ./certs

# Run the control plane. (Run this in its own terminal; it stays in the foreground.)
PROBECTL_AUTH_MODE=dev \
PROBECTL_DEV_AUTH_ACK=i-understand \
PROBECTL_HTTP_ADDR=127.0.0.1:8443 \
PROBECTL_TLS_CERT_FILE=./certs/tls.crt \
PROBECTL_TLS_KEY_FILE=./certs/tls.key \
PROBECTL_DATABASE_URL='postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable' \
PROBECTL_REQUIRE_AT_REST_ENCRYPTION=false \
PROBECTL_BUS_MODE=kafka \
PROBECTL_BUS_BROKERS=localhost:9092 \
PROBECTL_BUS_ALLOW_PLAINTEXT=true \
PROBECTL_FLOWSTORE_MODE=clickhouse \
PROBECTL_FLOWSTORE_URL=http://localhost:8123 \
  ./bin/probectl-control-devauth
```

This control plane serves **HTTPS on loopback** (`https://127.0.0.1:8443`), with
the **Kafka bus** and **ClickHouse** wired (Path 2 needs them) but **without** the
agent gRPC listener yet — that listener needs a CA file that does not exist until
you enroll your first agent, so **Path 1 turns it on with a restart** once the file
exists. If you are only doing Path 2, you are already done; skip to it.

> ### ⚠️ `PROBECTL_AUTH_MODE=dev` is evaluation-only, and it is strict
>
> Dev auth gives **every** request an all-permissions principal with **no
> authentication**. It exists so you can poke the API on a laptop without standing
> up SSO. Because it is dangerous, the code makes it hard to enable by accident —
> all three of these are required, or the control plane **refuses to start**:
>
> 1. the binary must be **built with dev auth** (`make build-devauth` — the
>    shipped release image does **not** contain it, so `PROBECTL_AUTH_MODE=dev` on
>    the shipped compose just crashes with a clear error);
> 2. `PROBECTL_DEV_AUTH_ACK=i-understand` must be set; and
> 3. the listener must bind **loopback only** (`127.0.0.1:...`) — never a network
>    interface.
>
> This is why the shared setup binds `127.0.0.1`. For anything beyond a laptop,
> use the real path: `PROBECTL_AUTH_MODE=session` with an OIDC IdP (see
> [`install.md`](install.md) and [`admin.md`](admin.md)). The control plane is
> **HTTPS/TLS everywhere by design** — in production there is no plaintext or
> no-auth mode to lean on.

Dev auth and TLS are independent: the listener binds **loopback** (required for
dev auth) *and* serves **HTTPS** (from the cert you just generated). Confirm it is
up — pass the generated CA so `curl` trusts the self-signed cert:

```sh
curl --cacert ./certs/ca.crt https://127.0.0.1:8443/readyz   # -> {"status":"ready"}
```

That is your consumer, ready and empty. Now pick a path.

---

## Path 1 — Synthetic probes (the canary agent)

**Any OS, unprivileged, no Kafka.** The canary agent *sends* traffic on a schedule
— an HTTP GET, an ICMP ping, a DNS lookup — and times the answer. It streams
results **straight to the control plane over gRPC/mTLS**, so it needs **nothing on
the bus**: just the control plane reachable. This is the lightest possible "first
data."

### Why this needs the agent CA (the mTLS part)

The agent connection is **mutually authenticated**: the control plane verifies the
agent, *and* the agent verifies the control plane. The agent proves who it is with
a short-lived certificate — an **SVID** — whose identity names its tenant
(`spiffe://probectl/tenant/<t>/agent/<a>`). Those certificates are issued by an
**agent CA** that you created once in the shared setup (`agent-ca init`). The
control plane's gRPC listener checks every agent's certificate against that CA —
which is why the shared setup pointed `PROBECTL_AGENT_TLS_CA_FILE` at
`./certs/agent-ca.crt`. We will produce that file now, by enrolling an agent and
copying out the trust bundle it receives.

### 1. Mint a one-time join token

The token, not the agent, names the tenant. Run this against the control plane's
HTTPS API host (port 8443):

```sh
PROBECTL_DATABASE_URL='postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable' \
PROBECTL_TLS_CERT_FILE=./certs/tls.crt \
  ./bin/probectl-control enroll-token \
  -tenant 00000000-0000-0000-0000-000000000001 \
  -name laptop
```

It prints a `pjt_…` token **once** (single-use, expires in ~1h) and — because we
pointed it at the server cert — the server certificate **pin** for first contact.
Copy the token.

### 2. Enroll the agent (this also hands you the agent CA bundle)

`enroll` generates the agent's private key **locally** (it never leaves the host),
redeems the token over HTTPS, and writes three files into `--dir`:
`cert.pem` (the SVID), `key.pem`, and `ca.pem` (**the agent CA trust bundle**).

```sh
./bin/probectl-agent enroll \
  --server https://localhost:8443 \
  --token pjt_REPLACE_WITH_THE_TOKEN_YOU_MINTED \
  --dir ./identity \
  --ca-file ./certs/ca.crt
```

The `--ca-file ./certs/ca.crt` tells the agent how to trust the control plane's
self-signed certificate on first contact; alternatively pass `--ca-pin
<hex-sha256>` using the pin the mint step printed.

Now copy that trust bundle to where the control plane will read it as the gRPC
client-verification CA, then **restart the control plane with the four
`PROBECTL_AGENT_*` lines added** so the gRPC listener comes up:

```sh
cp ./identity/ca.pem ./certs/agent-ca.crt

# Stop the control plane from the shared setup (Ctrl-C), then start it again with
# the same environment PLUS the agent-transport lines below:
PROBECTL_AUTH_MODE=dev \
PROBECTL_DEV_AUTH_ACK=i-understand \
PROBECTL_HTTP_ADDR=127.0.0.1:8443 \
PROBECTL_TLS_CERT_FILE=./certs/tls.crt \
PROBECTL_TLS_KEY_FILE=./certs/tls.key \
PROBECTL_DATABASE_URL='postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable' \
PROBECTL_REQUIRE_AT_REST_ENCRYPTION=false \
PROBECTL_BUS_MODE=kafka PROBECTL_BUS_BROKERS=localhost:9092 PROBECTL_BUS_ALLOW_PLAINTEXT=true \
PROBECTL_FLOWSTORE_MODE=clickhouse PROBECTL_FLOWSTORE_URL=http://localhost:8123 \
PROBECTL_AGENT_GRPC_ADDR=127.0.0.1:9443 \
PROBECTL_AGENT_TLS_CERT_FILE=./certs/tls.crt \
PROBECTL_AGENT_TLS_KEY_FILE=./certs/tls.key \
PROBECTL_AGENT_TLS_CA_FILE=./certs/agent-ca.crt \
  ./bin/probectl-control-devauth
```

The gRPC listener needs **all four** `PROBECTL_AGENT_*` values, and it reads the
files at startup — so the `agent-ca.crt` you just copied must exist before this
restart, which is exactly why enrollment came first.

> **Why the copy?** Two independent trust checks happen on the gRPC handshake. The
> agent verifies the *control plane's* server cert against its `tls.ca_file`
> (here, the quickstart `ca.crt`). The control plane verifies the *agent's* client
> cert against `PROBECTL_AGENT_TLS_CA_FILE` (the agent CA — the `ca.pem` you just
> got). They are different CAs doing different jobs. In a real deployment you would
> mint a proper gRPC server certificate and distribute the agent CA bundle through
> your config management; on a laptop, reusing the quickstart server cert and
> copying `ca.pem` across is the shortest honest path.

### 3. Write a minimal agent config

Point the agent at the gRPC listener and the identity files, and give it one
inline probe — an `http` check against a public URL. Save as `agent.yml`:

```yaml
control_plane:
  grpc_addr: "localhost:9443"      # the control plane's PROBECTL_AGENT_GRPC_ADDR

tls:
  cert_file: ./identity/cert.pem   # the agent's SVID (proves the agent to the server)
  key_file:  ./identity/key.pem
  ca_file:   ./certs/ca.crt         # verifies the SERVER to the agent (the quickstart
                                     # server CA — see the note below, NOT identity/ca.pem)
  server_name: "localhost"         # must match a SAN on the server cert

agent:
  capabilities: ["http"]
  heartbeat_interval: 30s

canaries:
  - type: http
    target: "https://example.com/"
    interval: 30s
    timeout: 10s
    params:
      method: "GET"
      expect_status: "2xx,3xx"
```

The full set of probe types and per-probe parameters is in
[`deploy/agent/probectl-agent.example.yml`](../deploy/agent/probectl-agent.example.yml)
and [`configuration.md`](configuration.md). **Probes run straight from this config
— you do not have to create anything server-side first.**

> **One subtlety the `enroll` output glosses over.** The snippet `enroll` prints
> suggests `ca_file: <dir>/ca.pem`. That is correct in a *production* setup, where
> the gRPC server certificate is itself issued by the agent CA — so the agent CA
> bundle (`ca.pem`) verifies both directions. On this laptop we are reusing the
> quickstart **server** cert for the gRPC listener, which is signed by a *different*
> CA (`./certs/ca.crt`). So here the agent's `ca_file` must be `./certs/ca.crt`
> (the server CA), while the *control plane* trusts the agent CA (`agent-ca.crt`)
> via `PROBECTL_AGENT_TLS_CA_FILE`. Same handshake, two CAs, two jobs.

### 4. Run the agent

```sh
./bin/probectl-agent -config agent.yml
```

Within one `interval` (30s) it connects, runs the `http` probe, and streams the
result.

### 5. See the result

```sh
curl --cacert ./certs/ca.crt https://127.0.0.1:8443/v1/results/latest
```

You will see the latest synthetic result per target — your `https://example.com/`
probe with its DNS / connect / TLS / time-to-first-byte breakdown. In the UI, the
same data is on the **Targets / synthetic results** screen.

> **Why `curl`/UI and not the `probectl` CLI here?** The `probectl` CLI defaults to
> `http://localhost:8080`, expects a **Bearer token**, and uses a plain-HTTP client
> — so it is not the frictionless tool against a self-signed-HTTPS control plane on
> a different port. For this first-data check, `curl` (with `--cacert ca.crt` when
> you are on HTTPS) and the UI are the smooth path.

For the full enrollment lifecycle (rotation, revocation, the bootstrap threat
model), see [`agent/enrollment.md`](agent/enrollment.md).

---

## Path 2 — Real host flows (the eBPF agent)

**Linux with `CAP_BPF`** for live capture; **any OS** (including macOS) for the
recorded-sample path. The eBPF agent loads tiny, sandboxed observation programs
into the Linux kernel and watches **every real TCP connection** the host makes or
accepts — with the process and container behind it — and rolls those into a live
**service map** (the directed "who talks to whom" graph). It is strictly
**observe-only**: it never blocks or modifies a packet.

### Why this needs the bus (and where the data lands)

Unlike the canary, the eBPF agent **does not stream over gRPC**. It is a separate
process from the control plane, so the two cannot share an in-process channel —
they meet on the **message bus**. The agent publishes flow + service-edge batches
to the topic `probectl.ebpf.flows`; a control-plane consumer drains that topic and
folds the edges into the **topology graph**. That bus is **Kafka** (which is why
the shared setup runs `dev.yml` and wired the control plane to
`PROBECTL_BUS_MODE=kafka`).

> **Where eBPF data shows up — read this carefully.** The eBPF host agent feeds the
> **topology / service-map** plane (`GET /v1/topology`). The `/v1/flows/*`
> analytics views (top talkers, capacity, anomalies) are a **different** producer —
> the NetFlow/IPFIX/sFlow **flow collector** (`probectl-flow-agent`), which lands
> in ClickHouse and is covered in [`flow.md`](flow.md). Both are "flow data" in
> plain English, but they are distinct planes with distinct producers. This path is
> the eBPF service map.

### Option A — recorded sample flows (no kernel; works on a Mac)

The agent ships with a recorded flow fixture
([`internal/ebpf/testdata/flows.json`](../internal/ebpf/testdata/flows.json)) so
you can light up the service map with **clearly-labelled SAMPLE data** on any OS,
no privileges. Point the agent at that file and at the dev Kafka:

```sh
PROBECTL_EBPF_TENANT_ID=00000000-0000-0000-0000-000000000001 \
PROBECTL_EBPF_FIXTURE_PATH=internal/ebpf/testdata/flows.json \
PROBECTL_EBPF_BUS_MODE=kafka \
PROBECTL_EBPF_BUS_BROKERS=localhost:9092 \
PROBECTL_EBPF_BUS_ALLOW_PLAINTEXT=true \
  ./bin/probectl-ebpf-agent
```

The sample contains a few synthetic connections (`10.0.1.5 → 10.0.2.9:443`, `…→
10.0.3.3:5432`) — **not** real traffic on your machine. It is exactly enough to see
the pipeline work end-to-end.

> `PROBECTL_EBPF_BUS_ALLOW_PLAINTEXT=true` is required only because the dev Kafka
> broker is plaintext. Like the control plane, the agent **refuses** a plaintext
> broker unless you opt in explicitly — production Kafka is TLS (`*_BUS_TLS_ENABLED`).

### Option B — live flows (Linux + `CAP_BPF`)

The live kernel loader is compiled in only with the **`-tags ebpf` build**, which
needs a Linux host, a BTF-enabled kernel, and `clang` (the shipped
`probectl-ebpf-agent` container image is this live build). Build it and run with a
config:

```sh
make ebpf-agent      # builds ./bin/probectl-ebpf-agent WITH the live CO-RE loader
# needs CAP_BPF (+CAP_PERFMON); the plaintext-bus opt-in is env-only:
sudo PROBECTL_EBPF_BUS_ALLOW_PLAINTEXT=true ./bin/probectl-ebpf-agent -config ebpf.yml
```

A minimal `ebpf.yml` for the dev stack (see
[`deploy/agent/probectl-ebpf-agent.example.yml`](../deploy/agent/probectl-ebpf-agent.example.yml)):

```yaml
tenant_id: "00000000-0000-0000-0000-000000000001"
bus:
  mode: kafka
  brokers: ["localhost:9092"]
```

(The plaintext-bus escape hatch is **not** a config-file field — pass it as the
`PROBECTL_EBPF_BUS_ALLOW_PLAINTEXT=true` environment variable, as above. With a
real TLS broker you would instead set `PROBECTL_EBPF_BUS_TLS_ENABLED=true`.)

Either option emits batches every `flush_interval` (default 10s). The kernel,
capabilities, and hardening details are in [`ebpf-agent.md`](ebpf-agent.md).

### See the service map

```sh
curl --cacert ./certs/ca.crt https://127.0.0.1:8443/v1/topology
```

The response is the dependency graph — nodes for the hosts/services seen and
**flow edges** between them, built from the agent's batches. In the UI this is the
**Topology** view; the same edges power the change-aware what-if analysis.

---

## Path 3 — Combine both (the actual payoff)

Each path on its own is one plane. probectl's reason to exist is **cross-plane
correlation**: when something breaks, you want **one incident** that pulls evidence
from every plane at once, rather than five dashboards you have to mentally join.

Once you have done Path 1, the control plane runs the gRPC listener **and** the
Kafka bus — so you do not change it; just run **both producers at once**:

```sh
# terminal 1 — the control plane, already restarted with the four PROBECTL_AGENT_*
#              lines from Path 1 (so the gRPC listener is up) and the Kafka bus.
# terminal 2 — the canary
./bin/probectl-agent -config agent.yml
# terminal 3 — the eBPF agent (sample flows, any OS)
PROBECTL_EBPF_TENANT_ID=00000000-0000-0000-0000-000000000001 \
PROBECTL_EBPF_FIXTURE_PATH=internal/ebpf/testdata/flows.json \
PROBECTL_EBPF_BUS_MODE=kafka PROBECTL_EBPF_BUS_BROKERS=localhost:9092 \
PROBECTL_EBPF_BUS_ALLOW_PLAINTEXT=true \
  ./bin/probectl-ebpf-agent
```

Now you have **synthetic results** (Path 1) and a **service map** (Path 2) behind
one tenant, on one control plane. Confirm both planes are populated:

```sh
curl --cacert ./certs/ca.crt https://127.0.0.1:8443/v1/results/latest   # synthetic plane
curl --cacert ./certs/ca.crt https://127.0.0.1:8443/v1/topology          # eBPF service map
```

### See a correlated incident

The control plane continuously groups related signals **across planes** into a
single incident, tenant-scoped. List what it has correlated:

```sh
curl --cacert ./certs/ca.crt https://127.0.0.1:8443/v1/incidents
# then drill into one:
curl --cacert ./certs/ca.crt https://127.0.0.1:8443/v1/incidents/<id>
```

When a synthetic probe to a service starts failing **and** that service is a node
in the eBPF map, those signals land in **one incident** with evidence from both
planes — the canary failure and the affected service edge — instead of two
unrelated alerts. (The deepest demonstration of this is the cross-plane
correlation gate that the test suite runs against an injected multi-plane fault;
the same machinery is what you are watching here in miniature.) In the UI this is
the **Incidents** view, and each incident shows its cross-plane evidence and the
related change/topology context.

---

## You have data — where to go next

You have proven the loop end to end: producers observe, the control plane consumes
and correlates, the API and UI show it. From here:

- **Add more producers.** [`deploying-agents.md`](deploying-agents.md) is the
  catalog of every producer and which infrastructure each needs (gRPC-to-control
  vs. bus). The depth docs per plane:
  - synthetic — [`agent/enrollment.md`](agent/enrollment.md), [`configuration.md`](configuration.md)
  - device flow analytics (NetFlow/IPFIX/sFlow) — [`flow.md`](flow.md)
  - eBPF host/L7 — [`ebpf-agent.md`](ebpf-agent.md)
  - device / streaming telemetry (SNMP/gNMI) — [`device-telemetry.md`](device-telemetry.md)
- **Make it production-shaped.** Swap dev auth for OIDC SSO and run behind real
  TLS — start with [`install.md`](install.md) (the shipped all-in-one and the Helm
  chart) and [`admin.md`](admin.md) (tenants, roles, audit, SSO).
- **Tune every knob.** Every `PROBECTL_*` control-plane variable and every agent
  config key is documented in [`configuration.md`](configuration.md).
