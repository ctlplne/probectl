# Glossary

Plain-language definitions of the terms of art used across probectl's docs. Each
entry says what the thing is and why it matters, assuming you start with zero
knowledge. Acronyms are expanded on first use everywhere; this is the lookup.

### BGP — Border Gateway Protocol
The protocol the independent networks of the internet use to tell each other which
addresses they can deliver traffic to ("to reach this address block, send it to me").
It has no central map — every network gossips routes to its neighbors. probectl
watches it for announcements that touch *your* address blocks. See `bgp.md`.

### ASN — Autonomous System Number
The numeric ID of an "autonomous system": one independently-operated network on the
internet (e.g. `AS64500`). BGP announcements say which ASN *originates* an address
block. A change in the originating ASN for your block is a routing red flag.

### prefix
An address block written as a base address plus a length, e.g. `203.0.113.0/24` (256
addresses). BGP routes are advertised per prefix; a hijack often appears as a new,
*more-specific* (smaller) prefix that steals traffic from a larger one.

### origin AS
The autonomous system that a BGP route says is the source of a prefix. probectl
compares the observed origin AS against what *should* originate your prefixes.

### route leak
When a network re-announces routes it should have kept to itself, pulling traffic onto
a path it should never take. A correctness/loss problem rather than necessarily an
attack.

### RPKI — Resource Public Key Infrastructure
A signed, cryptographic registry of which autonomous system is *allowed* to originate
which prefix. It turns "is this announcement legitimate?" into a checkable yes/no/unknown.

### ROA — Route Origin Authorization
One signed RPKI record stating "AS *N* may originate prefix *P*." An announcement that
contradicts a ROA is "RPKI-invalid" — a high-confidence hijack signal.

### MRT — Multi-Threaded Routing Toolkit format
The standard binary file format (RFC 6396) used to record and exchange BGP routing
data, so historical routing state can be replayed and analyzed.

### RIS — Routing Information Service
RIPE's network of route collectors that record what BGP speakers around the world
announce. With RouteViews, it's a public vantage point probectl reads (read-only).

### NetFlow / IPFIX / sFlow
The three common "flow telemetry" formats network devices export: a summary record per
conversation (who talked to whom, how much, on which ports) rather than the packets
themselves. **NetFlow** is Cisco's original; **IPFIX** is its IETF-standard successor;
**sFlow** is a packet-sampling variant. probectl ingests all three. See `flow.md`.

### eBPF — extended Berkeley Packet Filter
A safe way to run small, sandboxed programs inside the Linux kernel to observe what's
happening (connections, latency, L7 calls) without changing the traffic. probectl uses
it observe-only — it never blocks or rewrites packets. See `ebpf-agent.md`.

### OTel — OpenTelemetry
The vendor-neutral open standard for describing telemetry (metrics, traces, logs) and
the names/attributes attached to it. probectl models its data on OTel so it speaks a
language other tools already understand.

### OTLP — OpenTelemetry Protocol
The wire protocol for shipping OpenTelemetry data in and out. probectl both ingests
OTLP and can export metrics, traces, and logs over it. See `otlp.md`.

### OBI — OpenTelemetry eBPF Instrumentation
The OpenTelemetry project that uses eBPF to produce telemetry from running programs
without code changes; probectl's eBPF signals align to it.

### SNMP / gNMI — device telemetry protocols
Two ways to read health and counters from network devices. **SNMP** (Simple Network
Management Protocol) is the long-established polling standard; **gNMI** (gRPC Network
Management Interface) is the modern streaming successor. See `device-telemetry.md`.

### NDR — Network Detection and Response
Spotting suspicious behavior from network telemetry (scans, beaconing, exfiltration).
probectl ships "NDR-lite": confidence-scored *signals* you tune and export — never an
inline blocker. See `ndr.md`.

### IPS — Intrusion Prevention System
An inline device that *blocks* traffic it deems malicious. probectl is deliberately
**not** an IPS: it detects and reports, it never sits in the traffic path or drops packets.

### RUM — Real User Monitoring
Measuring the experience of actual users from their browsers/apps (load times, errors)
rather than synthetic robots. See `rum.md`.

### DEM — Digital Experience Monitoring
Watching the end-to-end experience from the endpoint a real person uses — laptop, Wi-Fi,
ISP, the whole last mile — to answer "is it slow for the user, and where?" See `endpoint-dem.md`.

### SLO / SLI — Service Level Objective / Indicator
An **SLI** is a measured signal of health (e.g. % of requests under 200 ms); an **SLO**
is the target you hold it to (e.g. 99.9% over 30 days). probectl ties these to business
impact. See `slo.md`.

### RCA — Root-Cause Analysis
Working out *why* something broke. probectl's AI assistant proposes a grounded root
cause by correlating evidence across planes, with citations you can check. See `ai-rca.md`.

### MCP — Model Context Protocol
An open standard that lets an AI client call a tool/server in a structured, permissioned
way. probectl ships an MCP server so assistants can query it — tenant-scoped first, then
by role. See `mcp.md`.

### TLS / mTLS — Transport Layer Security / mutual TLS
**TLS** is the encryption that secures a network connection and proves the server's
identity. **mTLS** ("mutual") additionally proves the *client's* identity; probectl uses
it so an agent and the control plane each prove who they are.

### CT — Certificate Transparency
Public, append-only logs of issued TLS certificates. Watching them reveals certificates
issued for your names that you didn't expect. See `tls-observability.md`.

### RLS — Row-Level Security
A database feature that filters every query to only the rows a given tenant may see,
enforced by the database itself rather than trusting application code. One layer of
probectl's tenant isolation. See `isolation.md`.

### tenant
One isolated customer/organization within a probectl deployment. The tenant is the
outermost boundary: every record, query, agent, and metric is scoped to it first. See
`isolation.md`.

### FIPS — Federal Information Processing Standards
US government standards for cryptography; "FIPS mode" means using a validated crypto
module. probectl can be built to run in FIPS mode for regulated environments.

### BYOK — Bring Your Own Key
Letting a customer supply and control the encryption keys that protect their data, so
the operator can't read it without them. See `byok.md`.

### KEK / DEK — Key/Data Encryption Keys (envelope encryption)
Data is encrypted with a **DEK**; the DEK is itself encrypted ("wrapped") by a **KEK**.
This "envelope" lets you rotate or revoke access by changing one key instead of
re-encrypting everything.

### SPIFFE — Secure Production Identity Framework For Everyone
An open standard for giving workloads (not people) a verifiable identity. probectl's
agents use SPIFFE-style, tenant-bound identities so the control plane knows exactly who
is connecting.

### SIEM — Security Information and Event Management
The system a security team uses to collect and search events. probectl exports its
detections and audit events to your SIEM rather than trying to replace it. See `siem.md`.

### ITSM — IT Service Management
Ticketing/workflow systems (e.g. for incidents and changes). probectl integrates with
ITSM and on-call tools to route alerts. See `oncall-itsm.md`.

### SCIM — System for Cross-domain Identity Management
The standard for automatically provisioning and de-provisioning user accounts from your
identity provider. See `scim-abac.md`.

### RBAC / ABAC — Role- / Attribute-Based Access Control
**RBAC** grants permissions by role ("admin", "viewer"). **ABAC** refines that with
attributes/conditions ("only this team's projects"). probectl checks the tenant
boundary first, then RBAC, then ABAC. See `scim-abac.md`.

### OIDC / SSO — OpenID Connect / Single Sign-On
**SSO** lets users log in once with your corporate identity provider; **OIDC** is the
common protocol that makes it work. probectl authenticates against your own IdP. See
`auth/self-hosted-idp.md`.

### RTP — Real-time Transport Protocol
The protocol that carries voice/video media. probectl measures call quality (jitter,
loss, MOS) from it. See `voice.md`.

### DNSSEC — DNS Security Extensions
Signatures that let a resolver verify a DNS answer wasn't forged. probectl's DNS tests
can check DNSSEC validation, not just whether a name resolves.

### MOS — Mean Opinion Score
A 1–5 score estimating perceived voice/video call quality, derived from loss, jitter,
and delay. See `voice.md`.

### ICMP — Internet Control Message Protocol
The protocol behind `ping` and `traceroute`; probectl's network tests use it to measure
reachability and round-trip latency.

### DSCP — Differentiated Services Code Point
A marking on a packet that requests a quality-of-service class (e.g. prioritize voice).
probectl can test whether those markings survive a path.

### CMDB — Configuration Management Database
The system of record for your infrastructure inventory. probectl can federate with a
CMDB (and Grafana/Prometheus) rather than owning that inventory. See `ecosystem-integrations.md`.

### NHI — Non-Human Identity
An identity belonging to a workload, service, or agent rather than a person. Relevant to
how probectl's agents and AI broker authenticate.
