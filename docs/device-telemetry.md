# Device / streaming telemetry — SNMP + gNMI

## What it is

The **device plane** is probectl's "how are the switches and routers themselves
doing?" layer — the interface counters, link states, CPU, memory, and
temperatures that a tool like LibreNMS watches. A network can look healthy from
the *outside* (your synthetic probes pass) while a switch is quietly dropping
packets on one port or running hot. This plane reads that truth straight from
the gear.

One agent, `probectl-device-agent`, talks to network devices three ways:

- **SNMP** (the Simple Network Management Protocol, v2c or v3) — the agent
  *polls*: every interval it asks the device a
  list of questions ("what's your uptime? how many bytes has port 7 sent?").
  The questions come from **MIBs** (Management Information Bases — the
  published catalogs of what a device can answer), and each question has an
  **OID** — its numeric address in that catalog (sysUpTime lives at
  `.1.3.6.1.2.1.1.3.0`).
- **gNMI / OpenConfig** (the gRPC Network Management Interface, speaking the
  vendor-neutral OpenConfig path schema) — the agent *subscribes*: the device
  *streams* updates as
  they change, over a gRPC channel.
- **SNMP traps** — the agent *listens* for device-pushed events such as link
  up/down and cold start. Traps are off by default and accepted only from
  configured sources with a matching v2c community or authenticated v3 USM user;
  accepted traps become tenant-scoped event and alert rows.

The shape difference is a nurse doing rounds versus a wearable monitor: SNMP
takes vitals on a schedule; gNMI reports the moment something changes.

Either way, both transports are normalized into a single `DeviceMetric` with the
**same metric names**, published to the bus, and landed in the time-series
database (TSDB) by the control plane — where alerts, the AI query engine, and
dashboards see them exactly like every other series.

```mermaid
%%{init: {'theme':'base','themeVariables':{'background':'#0d1117','primaryColor':'#161b22','primaryTextColor':'#e6edf3','primaryBorderColor':'#3b82f6','lineColor':'#8b949e','secondaryColor':'#21262d','tertiaryColor':'#0d1117','clusterBkg':'#161b22','clusterBorder':'#30363d','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'},'flowchart':{'curve':'basis','nodeSpacing':55,'rankSpacing':55,'padding':12}}}%%
flowchart LR
  D[switches / routers] -- "SNMP v2c/v3 (poll)" --> A[probectl-device-agent]
  D -- "SNMP traps (authenticated sources)" --> A
  D -- "gNMI Subscribe (stream, TLS)" --> A
  A -- "probectl.device.metrics (DeviceMetricBatch, tenant-keyed)" --> B[(bus)]
  A -- "SNMP trap events + alerts (tenant-scoped)" --> E[(trap store)]
  B --> P[control plane DeviceConsumer]
  P --> T[(TSDB: probectl_device_* series)]
  A -- "interface inventory (ifIndex, ifName, addresses)" --> C[Correlator]
  C -. "hop IP -> device/interface" .-> PathPlane[path plane]
  C -. "exporter+ifIndex -> interface" .-> FlowPlane[flow plane]
```

## How it works — one model, two transports

The trick that keeps everything downstream simple: **SNMP and gNMI emit the same
metric names**, so an alert rule or dashboard never has to care which transport
fed it. (Source of truth: `internal/device/model.go`.)

| Metric | Source (SNMP) | Source (gNMI/OpenConfig) | Unit |
| --- | --- | --- | --- |
| `probectl.device.uptime.seconds` | sysUpTime | — | seconds |
| `probectl.device.if.oper.status` | IF-MIB ifOperStatus | `state/oper-status` | 1 up / 0 not |
| `probectl.device.if.speed.mbps` | ifHighSpeed | — | Mbps |
| `probectl.device.if.{in,out}.octets` | ifHC{In,Out}Octets | `state/counters/{in,out}-octets` | octets (cumulative) |
| `probectl.device.if.{in,out}.{errors,discards}` | ifTable | `state/counters/...` | packets |
| `probectl.device.cpu.utilization` | hrProcessorLoad (avg) | — | percent |
| `probectl.device.memory.{used,total}.bytes` | hrStorageTable (RAM row) | — | bytes |
| `probectl.device.sensor.temperature.celsius` | ENTITY-SENSOR (opt-in) | — | °C |

These names live in the `probectl.device.*` namespace deliberately. probectl maps
its signals onto OpenTelemetry semantic conventions wherever a standard exists,
but **no OTel convention covers network-device telemetry**, so this is one of the
few places probectl owns the names. In the TSDB they become `probectl_device_*`
with labels `tenant_id, agent_id, device, device_name, source, if_index,
if_name` (`source` is `snmp` or `gnmi`).

**Why one model matters:** a counter like "interface 7 out-octets" should look
identical whether a 15-year-old switch coughed it up over SNMP or a modern box
streamed it over gNMI — two thermometers, one chart column. Unifying at the
*metric* layer means the rest of the
platform — alerting, AI, correlation — is written once.

### Graceful degradation over MIB variance

Not every device exposes every table. A cheap access switch may have no
HOST-RESOURCES MIB (so no CPU/memory), or no sensor table. probectl handles this
with **independent, best-effort table walks**: each walk fails on its own, so a
device that lacks HOST-RESOURCES simply yields no CPU/memory samples — the rest
still flow. Think of a survey whose sections are each optional: a skipped
section yields blanks, not a voided form — only an unreachable respondent
voids it. Only an unreachable or mis-authenticated device (the system group
itself fails) fails the whole poll. You get partial truth instead of an all-or-
nothing error.

## Correlation — tying device interfaces to the other planes

A device interface is the join point between planes — the way a flight number
joins the departure board, the baggage belt, and the crew roster. Each SNMP
poll also builds
an **interface inventory**: for every interface, its `ifIndex` (the interface's
numeric slot on the device — the same number flow exports use), its `ifName`
(falling
back to `ifDescr`), and the IP addresses from `ipAddrTable`. The
`device.Correlator` then joins the other planes on it:

- **path hop → interface**: a traceroute responder IP matches an interface
  address (or the device's management address gives a device-level match) — so a
  slow hop in a path test becomes "this hop is `core-sw1`".
- **flow → interface**: a flow record's `(exporter address, ifIndex)` pair
  matches the exporting device's named interface — turning the opaque
  "ifIndex 7" in a flow export into "`core-sw1` eth7".

This is what lets a cross-plane incident say *"the path test slowed at the same
interface where the flow plane sees a traffic spike and the device plane sees
rising discards"* — one interface, three views.

## Discovery and import review

The device agent can also run a **review-only discovery job**:

```bash
./bin/probectl-device-agent discover -job discovery.json -out review.json
```

Discovery is intentionally shaped like a flashlight, not a bulldozer. A job must
name one tenant, one or more **safe IPv4 ranges**, and one or more tenant-owned
credential references. Safe means private RFC1918, loopback, or link-local; a
public range such as `8.8.8.0/24` is rejected before any probe runs. Jobs also
have a `max_hosts` ceiling (default `1024`) so a typo cannot become a broad
scan.

Example job:

```json
{
  "id": "edge-rack-01",
  "tenant_id": "t-acme",
  "created_by": "netops@example.com",
  "ranges": ["10.10.40.0/28"],
  "max_hosts": 14,
  "credentials": [
    {"tenant_id": "t-acme", "name": "core-ro", "transport": "snmpv2c"}
  ],
  "classifier_rules": [
    {"role": "edge-router", "sys_name_contains": ["edge"], "confidence": 0.9},
    {"role": "access-switch", "sys_descr_contains": ["switch"], "min_interfaces": 8}
  ]
}
```

Credential entries are names only. The same `PROBECTL_DEVICE_CRED_<NAME>_*`
environment or secret-reference resolver used by normal polling resolves the
material at probe time. If a credential name is wrong or belongs to a different
tenant than the job, discovery fails closed.

Each answering device is classified from SNMP evidence: `sysName`, `sysDescr`,
and interface names/descriptions. Operator classifier rules run first; built-in
fallbacks label obvious routers, switches, and firewalls conservatively. The
output is a **review JSON** with `status: "review_required"` and each device in
`activation_state: "pending_review"`. In other words, discovery can suggest
targets, but it cannot activate monitoring by itself. An explicit review step
turns accepted candidates into ordinary device-agent `devices:` targets, and the
result carries audit events for job start, device discovery, review required,
and per-device approval.

For demos and tests, `-fixture fixture.json` drives the same workflow without
touching the network:

```json
{
  "devices": [
    {
      "address": "10.10.40.2",
      "sys_name": "edge-r1",
      "sys_descr": "router os",
      "interfaces": [
        {"index": 1, "name": "wan0", "oper_up": true, "addrs": ["10.10.40.2"]}
      ]
    }
  ]
}
```

## Credentials — referenced by name, never stored

Device credentials (SNMP communities, SNMPv3 passphrases, gNMI passwords) are
secrets, and probectl treats them like the guardrails demand: **config files
reference a credential by *name* only** — the secret material itself is resolved
at runtime through `device.CredentialSource` and is **never written to config or
git, and never logged** (the `Credential` type's `String()`/`GoString()` render
as `credential(redacted)`). Think coat check: the config holds only the
ticket; the cloakroom — the environment today, a secrets backend later — holds
the coat.

The default source reads the environment. For a credential named `core-ro`
(uppercased, with `-`/`.` mapped to `_`):

```text
PROBECTL_DEVICE_CRED_<NAME>_COMMUNITY      # SNMP v2c
PROBECTL_DEVICE_CRED_<NAME>_USERNAME       # SNMP v3 / gNMI metadata auth
PROBECTL_DEVICE_CRED_<NAME>_AUTH_PROTO     # sha (default) | sha256 | sha512 | md5
PROBECTL_DEVICE_CRED_<NAME>_AUTH_PASS
PROBECTL_DEVICE_CRED_<NAME>_PRIV_PROTO     # aes (default) | aes256 | des
PROBECTL_DEVICE_CRED_<NAME>_PRIV_PASS
PROBECTL_DEVICE_CRED_<NAME>_PASSWORD       # gNMI metadata auth
```

A credential name that resolves to *nothing* **fails closed at startup** — a
typo can't silently downgrade you to an unauthenticated poll; the agent refuses
to start instead. The named-credential seam is also the integration point for a
real secrets backend (Vault, CyberArk, a cloud KMS) plugging in later without
touching any device config.

A note for **FIPS deployments**: the SNMPv3 USM (User-based Security Model —
SNMPv3's built-in authentication/encryption layer) algorithms run
inside the SNMP library — they are protocol-mandated, exactly like a TLS
handshake, not a probectl crypto path. SNMPv3's older MD5 and DES options are not
FIPS-approved, so prefer SHA-2 + AES, or use gNMI over TLS.

## gNMI transport security

gNMI dials **TLS with certificate verification on by default** — using the system
root store, or a private CA via `ca_file`. Verification is **never disabled** in
a normal path (a core guardrail: every outbound channel validates certs). A
`plaintext: true` knob exists strictly as a lab-only opt-in, and when set it is
**loudly logged** so it can never hide in production. When a credential sets a
username/password, it rides gRPC metadata per the gNMI convention.

Each gNMI Subscribe response is capped at 4 MiB by an explicit client
`MaxCallRecvMsgSize`, matching the agent and OTLP gRPC safety ceiling. Hostile
or buggy devices that send an over-sized frame are rejected before normalization,
and the normalization path is covered by `FuzzGNMINormalize`.

## Configuration

See [`deploying-agents.md`](deploying-agents.md) for where the device agent
sits in the producer catalog (placement, service files, the full
producer-to-first-data path), `deploy/agent/probectl-device-agent.example.yml`
for the YAML form, and [`configuration.md`](configuration.md) for every key.
Quick start against one switch:

```bash
export PROBECTL_DEVICE_TENANT=t-acme
export PROBECTL_DEVICE_TARGET=192.0.2.1 PROBECTL_DEVICE_TRANSPORT=snmpv2c
export PROBECTL_DEVICE_CREDENTIAL=core-ro
export PROBECTL_DEVICE_CRED_CORE_RO_COMMUNITY=public
./bin/probectl-device-agent
```

Discovery quick start against a bounded private range:

```bash
export PROBECTL_DEVICE_CRED_CORE_RO_COMMUNITY=public
./bin/probectl-device-agent discover -job discovery.json -out review.json
```

## Testing

- The poller/normalizer is table-driven against canned-PDU fakes (a healthy
  device, degraded MIBs, an unreachable device), and the gNMI client runs against
  an in-process mock target over bufconn — both in `go test ./internal/device/...`.
- Discovery is pinned by fixture-network tests that classify devices, keep them
  pending review, build reviewed imports, and prove a tenant cannot list another
  tenant's discovery result.
- `TestSNMPIntegration` drives the **real** SNMP client against a live target
  when `PROBECTL_TEST_SNMP_TARGET` is set; CI starts a loopback `snmpd` target
  for it, and local runs can point at lab gear or another simulator.
- The correlation contract (hop IP ↔ interface, flow exporter+ifIndex ↔
  interface) is pinned by `TestCorrelatorHopToInterface` and
  `TestCorrelatorFlowToInterface`.
