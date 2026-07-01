# Passive telemetry planes — eBPF, OTLP, flow, and device

## What it is

Active testing sends traffic on purpose to see if a path works. The **passive
telemetry planes** are the opposite idea: they watch the traffic and the gear
that are *already there* and report what really happened. Four planes make up
this layer, and probectl normalizes all four into one shape so everything
downstream — dashboards, alerts, the AI assistant, incidents — treats them the
same:

- **The eBPF host and L7 agent** — watches every connection a host makes from
  inside the Linux kernel, and (when you turn it on, scoped to named workloads)
  reads application calls such as HTTP and gRPC. It is observe-only. See
  [glossary](../glossary.md) for eBPF (extended Berkeley Packet Filter).
- **The OpenTelemetry-aligned data model and OTLP ingest/export** — probectl's
  signals are shaped to the OpenTelemetry (OTel) standard from their first field,
  so it speaks the OpenTelemetry Protocol (OTLP) in both directions for all three
  signal types: metrics, traces, and logs.
- **Flow analytics** — decodes the flow summaries your routers, switches, and
  cloud accounts already export (NetFlow, IPFIX, sFlow, AWS VPC Flow Logs,
  Azure NSG Flow Logs, and GCP VPC Flow Logs) into one record per conversation.
- **Device telemetry** — reads the switches' and routers' own health (interface
  counters, link state, CPU, memory, temperature) over SNMP and gNMI.

## Why it exists

A network can look healthy from the outside while it is quietly unwell inside.
Your synthetic tests pass, but a switch is dropping packets on one port, a host
is opening a connection it should not, or one autonomous system is sending you
far more traffic than usual. Active testing alone cannot see any of that, because
it only measures the calls *you* place. The passive planes are the itemized phone
bill to active testing's test call: they tell you, after the fact, who actually
talked to whom, how the devices felt while it happened, and what the applications
said on the wire — without you having to instrument a single application.

Unifying the four planes at the data-model layer is the second reason this exists.
Because an "interface 7 out-octets" counter looks identical whether a 15-year-old
switch coughed it up over SNMP (Simple Network Management Protocol) or a modern
box streamed it over gNMI (gRPC Network Management Interface), the rest of the
platform is written once. The same join — one device interface — lets a single
incident say "the path test slowed at the same interface where the flow plane
sees a traffic spike and the device plane sees rising discards."

## How it works

**The eBPF agent.** The kernel is the privileged core of the operating system —
every packet, socket, and process passes through it. eBPF lets probectl load a
tiny, sandboxed program into the running kernel that fires when a TCP socket
changes state. The program records the connection's five-tuple (source address
and port, destination address and port, protocol) plus the process behind it,
writes it to a fixed-size queue shared with user space, and a Go reader folds raw
connections into a service map — the directed graph of who talks to whom.

The single most important property: the agent is **observe-only**. It loads only
observation programs and never enforcement. It watches; it never blocks,
redirects, or rewrites a single packet. It is not the Kubernetes networking layer
that routes pod traffic, and it is not an inline Intrusion Prevention System
(IPS) that drops traffic it dislikes. A build-failing check parses the agent's
kernel sources and refuses to ship if anyone adds a traffic-altering program, so
the guarantee holds in code, not just in convention.

The agent can also parse **L7** (layer 7, the application layer) calls — HTTP/1.1,
HTTP/2, gRPC, DNS, and Kafka — and roll per-call method, status, and latency onto
each service edge. For traffic encrypted with Transport Layer Security (TLS), it
reads the readable bytes that exist inside the application *just before* encryption
and *just after* decryption. There is no interception point inserted into the
network path and no forged certificate — it reads over the writer's shoulder, not
on the wire. This plaintext capture is **off by default** and requires three
independent statements before a single byte is read: a master switch, a per-tenant
consent that must match the agent's own tenant exactly, and a non-empty allowlist
of specific workloads (by process, executable path, or container). Host-wide
capture cannot be expressed. Even for an allowed workload, request and response
bodies are zeroed by default, and credential header values (Authorization, Cookie,
and common API-key and token headers) are blanked in place so bearer tokens never
reach the control plane.

**The OpenTelemetry data model and OTLP.** OTLP is the standard wire format for
telemetry. It carries metrics (numeric measurements over time), traces (the tree
of timed spans a request leaves behind), and logs (timestamped text records).
Because probectl's signals already follow OpenTelemetry naming, it both ingests
and exports OTLP without a translation layer. The ingest endpoint is TLS-only,
authenticated by a bearer token that maps to one tenant, and tenant-scoped: a push
that names a *different* tenant is rejected, and a push with *no* tenant is stamped
with the authenticated one. Ingested metrics land in the time-series database;
traces and logs are kept for correlation — bounded, retention-limited, and run
through a redactor that strips common personal data and secrets before storage. It
keeps the receipts, not the warehouse: enough of each span and log line to join
evidence across planes, never the full archive. It is not an
application-performance-monitoring (APM) replacement and not a log store.

**Flow analytics.** Routers and switches export flow records — a five-tuple plus
byte and packet counts — as UDP (User Datagram Protocol) datagrams to a small
collector. The collector decodes NetFlow v5/v9, IPFIX, and sFlow into one
normalized, tenant-bound record. Cloud networks export the same idea as logs:
AWS VPC Flow Logs, Azure NSG Flow Logs, and GCP VPC Flow Logs enter through a
local file/object-export connector and land in the same record shape, with the
provider resource kept as exporter provenance. Where operators want first-class
cloud onboarding, the cloud connector framework uses read-only AWS, Azure, or
GCP credentials over TLS to pull metric snapshots and flow-log object manifests,
caching the last good result so a down cloud API degrades instead of breaking the
flow plane. Two details matter:
template-based formats (v9, IPFIX) send the record's shape in a *template* the
exporter resends periodically, so data that arrives before its template is
counted as a miss and the gap self-heals; and high-rate links *sample* (say 1 in
1000), so every record keeps both the raw counters and the sampling rate and
carries pre-scaled estimates that all analytics read. The tenant on each record
comes from the collector's own binding or authenticated local import context,
never from anything the datagram or cloud log claims — source payloads cannot
assert which tenant they belong to.

**Device telemetry.** One agent reads devices two ways and emits the same metric
names from both. Over SNMP it *polls* on a schedule, asking each device a list of
questions; over gNMI it *subscribes* and the device *streams* changes. Table walks
are independent and best-effort, so a cheap switch that lacks a CPU or memory table
simply yields no CPU or memory samples while the rest still flow — partial truth
instead of an all-or-nothing error. Credentials are referenced by name only; the
secret itself is resolved at runtime and never written to config or logs, and a
name that resolves to nothing fails closed at startup rather than silently
downgrading to an unauthenticated poll.

probectl never phones home: the eBPF agent, the flow collector, and the device
agent fetch nothing on their own, and every channel uses TLS with certificate
validation that is not disabled in a normal path.

## Use it

Point a device at the flow collector and read the analytics back, tenant-scoped
(the tenant comes from your authenticated identity, never from the URL):

```sh
# Run the flow collector near the devices that export to it.
PROBECTL_FLOW_TENANT=t-acme \
PROBECTL_FLOW_BUS_MODE=kafka \
PROBECTL_FLOW_BUS_BROKERS=localhost:9092 \
  ./bin/probectl-flow-agent
# On a Cisco-style device: flow exporter EXP destination <collector-ip> transport udp 2055

# Ask the three questions operators actually ask of flow data:
curl -sS "https://localhost:8443/v1/flows/top?by=src_asn&window=15m&limit=5"
# Observe: the top source autonomous systems by sampling-corrected bytes/packets,
# scoped to your tenant. A capacity or anomalies query uses /v1/flows/capacity
# or /v1/flows/anomalies.
```

Poll one switch over SNMP:

```sh
export PROBECTL_DEVICE_TENANT=t-acme
export PROBECTL_DEVICE_TARGET=192.0.2.1 PROBECTL_DEVICE_TRANSPORT=snmpv2c
export PROBECTL_DEVICE_CREDENTIAL=core-ro
export PROBECTL_DEVICE_CRED_CORE_RO_COMMUNITY=public
./bin/probectl-device-agent
# Observe: probectl_device_* series (uptime, interface octets, oper-status)
# appear in the time-series database, labeled by tenant, device, and interface.
```

Listen for authenticated SNMP traps:

```yaml
apiVersion: probectl.io/device-agent/v1
tenant_id: t-acme
traps:
  enabled: true
  listen: ":9162"
  sources:
    - name: core-switches
      address: 192.0.2.10
      transport: snmpv3
      credential: core-traps
```

```sh
export PROBECTL_DEVICE_CRED_CORE_TRAPS_USERNAME=trap-user
export PROBECTL_DEVICE_CRED_CORE_TRAPS_AUTH_PROTO=sha256
export PROBECTL_DEVICE_CRED_CORE_TRAPS_AUTH_PASS='from-your-secret-store'
./bin/probectl-device-agent -config device-traps.yml
# Observe: accepted traps create tenant-scoped event and alert rows; duplicate
# replays are deduplicated by trap fingerprint.
```

Turn on eBPF L7 plaintext capture only for a named workload (it refuses to start
without a scope, so host-wide capture is impossible):

```yaml
l7_capture_enabled: true
l7_capture_consent_tenant: t-acme   # must equal this agent's bound tenant exactly
l7_capture_scope:
  - cgroup:/sys/fs/cgroup/system.slice/nginx.service
l7_capture_redaction: headers       # bodies and credential header values zeroed
# Observe: HTTP/gRPC/DNS calls roll onto service edges for nginx only; every other
# process is dropped in the kernel before a byte is copied.
```

## Pitfalls & limits

- **eBPF is Linux-only and observe-only.** It needs a recent kernel (the floor is
  Linux 5.8, which first shipped the type format and ring buffer it relies on). On
  macOS or Windows, run the agent inside a Linux virtual machine. It never blocks
  or rewrites traffic.
- **Go's own TLS is a known L7 blind spot.** The plaintext-capture hooks attach to
  the system TLS libraries (OpenSSL, BoringSSL, GnuTLS). Go programs ship their own
  TLS, so a Go process's L7 *plaintext* is not captured today. Its connections and
  service-map edges are still seen — only the decoded application calls are out of
  scope. Stripped or statically-linked binaries with no resolvable symbols fall
  back to cleartext-only capture for the same reason.
- **Flow export is plaintext UDP with no authentication, by protocol design.**
  Deploy the collector adjacent to its exporters (management network or same site)
  so datagrams never cross an untrusted segment. Every datagram is treated as
  untrusted input: malformed records are counted and dropped, never panicked on,
  and template state is capped so a misconfigured exporter cannot grow memory
  without bound.
- **Sampled flow undercounts if you read the raw counters.** Always read the
  sampling-corrected values; the raw counters are kept only for provenance.
- **Traces and logs are for correlation, not archival.** Bodies are capped,
  attributes are bounded, and retention is limited. probectl does not replace your
  APM tool or your log store, and it counts the metric point types it cannot store
  rather than dropping them silently.
- **Dropped telemetry is always counted, never hidden.** When a ring buffer or an
  ingest queue overflows, probectl increments a labeled counter and logs it, so an
  all-dropped window is visible rather than a silent gap.

## Reference

- Flow query endpoints: `GET /v1/flows/top`, `GET /v1/flows/capacity`,
  `GET /v1/flows/anomalies` (all require the flow read permission and are scoped to
  the caller's tenant first). Default UDP ports: NetFlow v5/v9 `:2055`, IPFIX
  `:4739`, sFlow v5 `:6343`. Cloud flow-log import reads local/exported AWS,
  Azure, or GCP log files; cloud metric and flow-object pulls require an
  explicit read-only cloud connector config and never run by default.
- OTLP ingest: gRPC services for metrics, traces, and logs, plus HTTP
  `POST /v1/metrics`, `/v1/traces`, `/v1/logs`. Query traces and logs back,
  tenant-scoped, at `GET /v1/otlp/traces` and `GET /v1/otlp/logs`. Mint a
  tenant-mapped ingest token with `POST /v1/otlp-tokens`; revoke with
  `DELETE /v1/otlp-tokens/{id}`.
- Device metric names live in the `probectl.device.*` namespace (for example
  `probectl.device.if.in.octets`, `probectl.device.if.oper.status`) because no
  OpenTelemetry convention covers network-device telemetry; everything else maps
  to standard OpenTelemetry resource and network attribute names.
- Common environment keys: `PROBECTL_FLOW_*` (collector), `PROBECTL_DEVICE_*`
  (device agent), `PROBECTL_EBPF_*` (eBPF agent), `PROBECTL_OTLP_*` (OTLP
  ingest/export). Setting an OTLP or MCP listener address without TLS files fails
  configuration validation on purpose.
- Related planes and terms: NetFlow / IPFIX / sFlow, SNMP / gNMI, OTel, OTLP, OBI
  (OpenTelemetry eBPF Instrumentation), and IPS in the [glossary](../glossary.md).

**Covers:** F11, F12, F17, F18
