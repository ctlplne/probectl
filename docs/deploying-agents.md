# Deploying agents & collectors

probectl's control plane never goes out and measures the network itself. It
**consumes**. The measuring is done by a small family of **agents and
collectors** that you deploy out where the truth lives — on probe hosts, next to
your routers, on the switches' management network, inside the kernel of your
servers, and on end-user laptops. Each one is a single static Go binary; each one
sends what it sees back to the control plane; each one is bound to exactly one
**tenant** so its data can never land in another tenant's view.

This page is the index: **what producers exist, and how do I deploy each one?**
Pick the producers for the planes you actually care about — you do not need all
of them. If you just want to see *any* data flow end-to-end first, start with the
hands-on [getting-started guide](getting-started.md) (it walks you from zero to a
first probe result), then come back here to add the rest.

> The deep "how each plane works" explanations live in the per-plane docs linked
> from each section below. This page stays at the "which binary, where does it
> run, how does it ship data, what's the one command" level on purpose.

## The two ways a producer ships its data

Before the catalog, the single most important distinction — because it decides
what backend infrastructure each producer needs. Think courier versus postal
system: one producer hands its parcel directly to the recipient (nothing else
has to exist), the others drop parcels at a depot the recipient empties on its
own schedule — which means the depot has to be standing.

- **Streams to the control plane over gRPC/mTLS.** The agent holds an
  authenticated, tenant-bound connection straight to the control plane (gRPC is
  the HTTP/2-based remote-procedure-call protocol the stream rides on; mTLS is
  *mutual* TLS — both ends present certificates, so the server proves itself to
  the agent and the agent proves itself to the server). It needs
  **nothing but the control plane** reachable. This is the **canary/synthetic
  agent** (and, optionally in future, roaming endpoints). This is the courier.
- **Publishes to the message bus.** The collector writes records onto a bus topic
  (`probectl.<type>.results` / `probectl.<type>.events`), and a control-plane
  consumer drains the topic into storage. In a real fleet that bus is **Kafka**
  (the open-source distributed message log: producers append, consumers read at
  their own pace, and the log absorbs bursts neither side could handle alone),
  and the high-cardinality planes land in **ClickHouse** (the column store built
  for billions of small event rows) — so these producers
  imply *"you are running Kafka + ClickHouse"* (or the lightweight in-memory bus,
  for a single-node dev box only). This is the **flow**, **device**, **eBPF**, and
  **endpoint** producers — the postal model, and the depot is Kafka.

So: a synthetic-only deployment can run with just the control plane and its
Postgres. The moment you want flow, device telemetry, eBPF, or endpoint data at
fleet scale, you are also standing up Kafka and ClickHouse. Each section below
says which camp its producer is in.

## Enroll once: how an agent gets its identity

Every agent that talks to the control plane proves who it is with a **short-lived
mTLS client certificate** — an **SVID** — whose SPIFFE identity names its tenant
and agent id (`spiffe://probectl/tenant/<t>/agent/<a>`; SPIFFE is the standard
URI naming scheme for workload identities, and an SVID is the certificate that
carries one). Until an agent has one,
the mTLS transport refuses its connection and nothing it sends lands anywhere.
You do **not** hand-distribute certificates; the trust root is managed by the
control plane, and the runtime rotates the certificate automatically forever
after.

The lifecycle is: set up the CA **once per deployment**, mint a **one-time join
token** per agent, and **redeem** it on the agent host.

**1. One-time, on the control host — create the certificate hierarchy:**

```sh
probectl-control agent-ca init
probectl-control agent-ca export /etc/probectl/agent-ca.crt
```

`init` prints the root private key **once** for offline custody and never stores
it; runtime operation never needs it. Re-running refuses to overwrite the trust
root. `export` writes the CA's **public** trust bundle (root + intermediate
certificates — never a key) to a file; point the control plane's
`PROBECTL_AGENT_TLS_CA_FILE` at it so the gRPC listener can verify enrolling
agents.

**2. Mint a join token (one per agent; the *token* names the tenant):**

From the web UI, go to **Admin & Settings → Agents → Enroll agent**. The modal
mints the tenant-scoped token, shows it once, and prints the
`probectl-agent enroll` command with either the current server certificate pin
or the `--ca-file` trust path.

```sh
probectl-control enroll-token -tenant <tenant-uuid> [-agent <id>] [-name "edge-probe-1"] [-ttl 1h]
```

The CLI path prints the same token (`pjt_…`) **once**; it is **single-use**,
expires (default 1h), and is tenant-scoped. The command also prints the control
plane's certificate **pin** for first contact when `PROBECTL_TLS_CERT_FILE` is
configured.

**3. Redeem it on the agent host:**

```sh
probectl-agent enroll \
  --server https://<control-host>:8443 \
  --token pjt_... \
  --dir /var/lib/probectl-agent/identity \
  --ca-pin <hex-sha256>          # for self-signed quickstarts
  # ...or, with a CA-issued control-plane cert:  --ca-file ca.crt
```

The agent generates its private key **locally** (it never leaves the host), sends
a CSR — a certificate signing request: the public half of the keypair, packaged
for the CA to sign — and writes the issued cert, the intermediate, and the
trust bundle (mode
`0600`) into `--dir`. A `--ca-pin` that mismatches **refuses** the connection —
there is no trust-on-first-use fallback. `enroll` then prints the exact `tls:` /
`identity:` config snippet to paste into the agent's config so it rotates
automatically.

For fleets where a separate enroll step is awkward (containers, cloud-init),
the canary agent also **enrolls itself on first boot**: hand it the token via
the `PROBECTL_AGENT_JOIN_TOKEN` environment variable or the `enroll.token_file`
config key, and it redeems the token before starting. This is idempotent — an
agent that already has an identity skips it — and fail-closed: a consumed or
invalid token stops the agent with a clear error instead of running
unauthenticated.

For SVID rotation (every ~24h, automatic), revocation, and the full bootstrap
threat model, see **[agent enrollment & rotation](agent/enrollment.md)**.

> The flow, device, and eBPF collectors in their *lightweight / single-tenant*
> form take an explicit `tenant_id` in config instead of deriving it from an SVID
> — convenient for a single-node deploy. In a multi-tenant or regulated
> deployment, bind them to a SPIFFE identity the same way (the enrollment flow
> above), so the tenant comes from the certificate, not a config field.

## The producers

### Canary / synthetic — `probectl-agent`

**What it observes.** Active, on-purpose probes you schedule: it *sends* traffic
and times the answer. Compiled-in probe types are **`icmp`** (loss / latency /
jitter — jitter being the variation *between* round-trips, what voice and video
feel), **`tcp`** (connect latency + reachability), **`udp`** (echo round-trip),
**`dns`** (resolution time, answer, DNSSEC validation, plus iterative
delegation traces — walking root → TLD → authority itself instead of trusting a
resolver's cache),
**`http`** (availability + DNS/connect/TLS/TTFB/total breakdown — TTFB is
time-to-first-byte — and on HTTPS the
TLS handshake details that feed the TLS-posture view), **`browser`** (scripted
transaction checks with per-step timings, using the Go-native HTTP transaction
driver by default), and **`voice`** (RTP media probes scored as MOS — the 1–5
mean-opinion-score call-quality scale — plus jitter / loss) — plus a `noop`
heartbeat. It can also do **agent-to-agent
(`a2a`)** two-way measurement (TWAMP-lite style: both ends timestamp, so each
direction's latency is measured separately) when you enable the `a2a:` block,
turning a pair of agents into a synthetic mesh. A2A is opt-in (`enabled: false`
by default), and every brokered probe/reply frame is authenticated with a
per-session HMAC key delivered over the existing agent mTLS channel.

**Where it runs.** Any OS, **unprivileged** by default — ICMP uses unprivileged
datagram sockets, so no `CAP_NET_RAW` and no root for the common case.

**How it ships data.** It **streams straight to the control plane over
gRPC/mTLS** — it does **not** use the bus. Point it at the control plane's gRPC
listener via `control_plane.grpc_addr` (required — there is no built-in default;
the shipped examples and stacks use port **9443**), using the mTLS identity from
enrollment. Results buffer to a local disk queue while the control
plane is unreachable and drain on reconnect, so a network blip never loses data.
**Infra it needs: just the control plane** (no Kafka, no ClickHouse).

**Deploy it.**

```sh
probectl-agent -config /etc/probectl/agent.yml
```

Config template: [`deploy/agent/probectl-agent.example.yml`](../deploy/agent/probectl-agent.example.yml).
Every key (and the per-probe parameters) is documented in
[`configuration.md`](configuration.md); voice specifics are in
[`voice.md`](voice.md), and the browser/transaction synthetic in
[`browser-synthetic.md`](browser-synthetic.md).

### Flow collector — `probectl-flow-agent`

**What it observes.** The passive, after-the-fact view of *real* traffic: routers
and switches summarize the packets they forwarded into **flow records** (the
5-tuple — source/destination address, source/destination port, protocol — plus
byte/packet counts) and export them. The collector decodes
**NetFlow v5/v9**, **IPFIX**, and **sFlow v5** — three export dialects of that
same idea — into one normalized, tenant-bound
record.

**Where it runs.** As a service on a host on (or adjacent to) your **management
network**. Flow export is **plaintext UDP with no authentication — by protocol
design** — so deploy the collector **next to its exporters** and never let those
datagrams cross an untrusted segment. It binds three UDP listeners: `:2055`
(NetFlow v5 **and** v9, version-sniffed on one socket), `:4739` (IPFIX), `:6343`
(sFlow). Disable any listener you don't run.

**How it ships data.** It **publishes to the bus** on `probectl.flow.events`; the
control plane's flow consumer verifies the tenant, optionally enriches ASN/geo
(ASN — the autonomous-system number, i.e. which network on the internet owns
the address — and its geolocation),
and writes rows into **ClickHouse**. **Infra it needs: the message bus
(`bus.mode: kafka` → Kafka) and ClickHouse.** A single-node dev box can set
`bus.mode: memory` instead.

**Deploy it.**

```sh
probectl-flow-agent -config /etc/probectl/flow-agent.yml
```

Config template: [`deploy/agent/probectl-flow-agent.example.yml`](../deploy/agent/probectl-flow-agent.example.yml).
Full plane walkthrough, the OTel field mapping, sampling correction, and the
query API: **[flow analytics](flow.md)**.

### Device / streaming telemetry — `probectl-device-agent`

**What it observes.** The health of the switches and routers *themselves* —
interface counters and oper-status, CPU, memory, and (opt-in) temperatures —
straight from the gear. It speaks two protocols and normalizes both into one
`DeviceMetric` with identical metric names: **SNMP** (the Simple Network
Management Protocol, v2c or v3 — the decades-old standard where the agent
*polls* on an interval) and **gNMI / OpenConfig** (the gRPC Network Management
Interface — the modern alternative where the device *streams* updates
over a TLS gRPC channel). Same metric names either way is the point: dashboards
and alerts don't care which protocol a given switch happened to speak.

**Where it runs.** As a service with line-of-sight to the devices' management
addresses. **gNMI dials TLS with certificate verification on by default** (system
roots, or pin a private CA with `ca_file`); there is no skip-verify, and the
lab-only `plaintext` opt-in is loudly logged. Credentials (SNMP communities,
SNMPv3 passphrases, gNMI passwords) are **referenced by name only** and resolved
at runtime — never written to config or git, never logged. A credential that
resolves to nothing **fails closed at startup**.

**How it ships data.** It **publishes to the bus** on `probectl.device.metrics`;
the control plane's device consumer lands the series in the **time-series
database**. **Infra it needs: the message bus (`bus.mode: kafka` → Kafka)** (plus
your TSDB, which the control plane already owns). Single-node dev: `bus.mode:
memory`.

**Deploy it.**

```sh
probectl-device-agent -config /etc/probectl/device-agent.yml
```

Config template: [`deploy/agent/probectl-device-agent.example.yml`](../deploy/agent/probectl-device-agent.example.yml).
Metric catalog, the SNMP↔gNMI unification, FIPS notes, and how device interfaces
correlate path and flow data: **[device telemetry](device-telemetry.md)**.

### eBPF host agent — `probectl-ebpf-agent`

**What it observes.** Network activity **from inside the host's kernel**, with
zero instrumentation — no sidecars, no app changes, no SDK. (eBPF lets the
kernel run small, sandboxed, pre-verified observation programs — the agent
attaches them to the kernel's own networking events instead of capturing
packets.) It captures every
TCP connection a host makes or accepts (the **L3/L4 flow** — addresses and
ports — plus the process and
container behind it) and builds a live **service map** of who-talks-to-whom. It
can additionally parse **L7** (application-layer) calls (HTTP/1.1+2, gRPC, DNS,
Kafka),
including over TLS via library **uprobes** — kernel hooks attached to a
user-space library's functions, here the TLS library, so data is visible before
it is encrypted — and reading application plaintext is
**off by default and triple-gated** (an enable flag **plus** a per-tenant consent
that must name this agent's tenant **plus** a non-empty workload allowlist;
host-wide capture is not expressible). It is **observe-only** — it loads no
enforcing program and blocks no packet, a guarantee enforced by a build-failing
test. It is **not** a CNI and **not** an inline IPS.

**Where it runs.** **Linux only**, on each host you want to see. It needs
**`CAP_BPF` + `CAP_PERFMON`** (kernels ≥ 5.8; `CAP_SYS_ADMIN` on 5.4–5.7) —
the two Linux capabilities that permit loading BPF programs and attaching to
perf events, granted without root — and a
**BTF-exposing kernel** (`/sys/kernel/btf/vmlinux`, mainstream from 5.8 — BTF
is the kernel's embedded type catalog, which lets one compiled agent adapt to
any kernel). On
macOS/Windows, run it inside a Linux VM. The shipped image is the live build;
fixture-replay mode exists only for CI / no-kernel boxes.

**How it ships data.** It **publishes to the bus** on `probectl.ebpf.flows`. The
shipped artifacts default to **`bus.mode: kafka`**. **Infra it needs: Kafka.**
Control-plane consumers (topology, segmentation, NDR) read these flows live;
raw flow-by-flow retention in ClickHouse is not wired yet, so there is no
queryable per-flow history — only what the consumers derive. The agent
**refuses plaintext Kafka** unless you explicitly opt in for a lab.

**Deploy it (VM / bare metal).**

```sh
sudo deploy/agent/install.sh ./bin/probectl-ebpf-agent
$EDITOR /etc/probectl/ebpf-agent.yaml      # set tenant_id + bus brokers
sudo systemctl start probectl-ebpf-agent
```

The installer is air-gap friendly (it downloads nothing and never self-updates),
creates a dedicated non-root `probectl-agent` system user, and installs the
**hardened systemd unit** (ambient `CAP_BPF`+`CAP_PERFMON`, a default-deny
syscall filter, namespace lockdown) shipped alongside it. The unit and its
matching container **seccomp profile** (seccomp — the Linux syscall filter; the
profile is the allowlist of kernel calls the process may make) live in
[`deploy/agent/`](../deploy/agent/) (`probectl-ebpf-agent.service`,
`seccomp.json`). Config template:
[`deploy/agent/probectl-ebpf-agent.example.yml`](../deploy/agent/probectl-ebpf-agent.example.yml).
The full plane — capture pipeline, the triple-gate, redaction modes, the
kernel/uprobe compatibility matrix, and the build: **[eBPF host agent](ebpf-agent.md)**.

### Endpoint / last-mile DEM — `probectl-endpoint`

**What it observes.** The **last mile** that server-side canaries physically
cannot see: a remote user's **Wi-Fi** link health, their local **gateway**, the
**ISP / last-mile path**, and **browser-session** timings — and then the headline
trick, it **attributes** a slowdown to the closest impaired layer (Wi-Fi → local
LAN → ISP → wider network), so you can answer *"is it us, or the user's
Wi-Fi / ISP?"*. It runs on the user's own device, so **data minimization is a
hard rule** (geolocatable identifiers — like the AP MAC, the Wi-Fi access
point's hardware address, enough to place a household on a map — and public hop
IPs are
dropped before a sample is ever emitted), and it **discloses exactly what it
collects at startup**.

**Where it runs.** **Cross-OS** (Linux / macOS / Windows), on end-user devices,
**no elevated privileges** — it uses the OS's own `traceroute`/`tracert` and
read-only Wi-Fi queries. Ship the single static binary via your MDM (mobile
device management — the tool IT already uses to push software to managed
laptops: Intune, Jamf).

**How it ships data.** It **publishes to the bus** on
`probectl.endpoint.results`, tenant-keyed, flowing through the same pipeline as
every other canary; it **never phones home**. **Infra it needs: the message bus**
— Kafka in a fleet, or the lightweight in-memory bus on a single-node dev box.

**Deploy it.**

```sh
probectl-endpoint -config /etc/probectl/endpoint.yml
```

The privacy model, the attribution engine, the per-OS collection matrix, and the
`/v1/endpoints` fleet surface: **[endpoint DEM](endpoint-dem.md)**.

## A producer-by-producer cheat sheet

| Producer | Binary | Runs on | Ships via | Backend it implies | Deploy |
| --- | --- | --- | --- | --- | --- |
| Canary / synthetic | `probectl-agent` | any OS, unprivileged | **gRPC/mTLS → control plane** (`:9443`) | control plane only | `probectl-agent -config agent.yml` |
| Flow | `probectl-flow-agent` | mgmt network (UDP `:2055/:4739/:6343`) | **bus** (`probectl.flow.events`) | Kafka + ClickHouse | `probectl-flow-agent -config flow-agent.yml` |
| Device | `probectl-device-agent` | reaches device mgmt | **bus** (`probectl.device.metrics`) | Kafka (+ TSDB) | `probectl-device-agent -config device-agent.yml` |
| eBPF host | `probectl-ebpf-agent` | **Linux**, `CAP_BPF`+`CAP_PERFMON`, BTF ≥5.8 | **bus** (`probectl.ebpf.flows`) | Kafka (+ ClickHouse) | `sudo deploy/agent/install.sh ./probectl-ebpf-agent` (cosign verification is default) |
| Endpoint / DEM | `probectl-endpoint` | Linux / macOS / Windows, unprivileged | **bus** (`probectl.endpoint.results`) | Kafka (or in-memory) | `probectl-endpoint -config endpoint.yml` |

## At scale

Running one agent by hand is the learning path. A fleet is run by your
orchestrator — probectl deliberately has **no agent self-update channel** (that
would be a fleet-wide remote-code-execution primitive), so update authority stays
with your tooling.

- **Kubernetes — the eBPF host agent as a DaemonSet** (Kubernetes's
  run-one-copy-on-every-node primitive — exactly the shape a per-host kernel
  observer needs). The supported chart is
  [`deploy/helm/probectl-agent`](../deploy/helm/probectl-agent). It declares the
  privilege contract in the manifest (drop **all** capabilities, add back only
  `CAP_BPF`/`CAP_PERFMON`, a seccomp profile, read-only root, the BTF host mount,
  resource limits) and **renders fail-closed** — no `tenantID`, or plaintext
  Kafka without an explicit opt-in, refuses to template.

  ```sh
  helm install probectl-agent deploy/helm/probectl-agent \
    --set tenantID=<tenant> \
    --set 'bus.brokers={kafka.probectl.svc:9093}' \
    --set bus.tls.existingSecret=probectl-bus-tls \
    --set-string image.tag='0.4.0@sha256:<digest>'
  ```

  > **Naming heads-up:** the chart is named `probectl-agent` but it deploys the
  > **eBPF host agent** (`probectl-ebpf-agent` image) — it is the per-node flow
  > agent, **not** the synthetic `probectl-agent` binary. The eBPF agent is the
  > one with a shipped Helm chart, systemd unit, and installer; the canary, flow,
  > and device agents ship example configs and run as ordinary services or
  > containers in your platform.

- **VMs / bare metal — the installer.** [`deploy/agent/install.sh`](../deploy/agent/install.sh)
  installs a **local** binary (air-gap friendly: downloads nothing, never
  self-updates), creates the non-root system user, installs the hardened systemd
  unit, and writes a fail-closed sample config. Re-run it with a new binary to
  update.

- **Staged fleet rollout.** Move a fleet to a new version in **waves** (canary →
  early → main) from **signed** artifacts, with the agent registry verifying each
  wave and any straggler **halting the train** — so a bad version stops at a small
  canary instead of taking out the whole fleet. The model, the operator flow, and
  halt/resume semantics are in **[staged fleet rollout](ops/fleet-rollout.md)**.

## See also

- [Getting started](getting-started.md) — zero to your first probe result, the
  "just try one" path.
- [Installation](install.md) — standing up the control plane the agents connect
  to.
- [Configuration reference](configuration.md) — every `PROBECTL_*` key and config
  field for every binary.
- [Agent enrollment & rotation](agent/enrollment.md) — the identity lifecycle in
  depth.
