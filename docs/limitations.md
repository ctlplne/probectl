# Limitations & deliberate non-goals — what probectl does *not* do, on purpose

## What it is

This page is the honest list of things probectl deliberately does **not** do, and
things that are built but not yet wired into the running server. It exists because the
fastest way to lose a careful reader's trust is to imply a capability you don't ship.
The headline non-goal documented here is the **plugin / detection marketplace** (F49):
a hosted catalog where third parties publish and sell detections and plugins.

Treat this page as the counterpart to every feature page: those tell you what works;
this one draws the edges so you always know which side of the line you're on.

## Why it exists

A monitoring tool is only as useful as it is trustworthy, and trust is asymmetric — one
overstatement that a reader tests and disproves taints the pages that were accurate.
Regulated buyers in particular read the limitations page *first*. Stating non-goals
plainly also prevents wasted effort: you won't architect around a feature that was never
coming, and you won't file a bug for behavior that is working as designed.

## How it works

probectl sorts every capability into one of three honest states, and this page is where
the third state lives:

1. **Served live** — wired into the running control plane and agents today. Documented
   on its feature page.
2. **Built, not yet served** — present as library code but not exposed in the running
   server. Its feature page says so explicitly and links here.
3. **Deliberate non-goal** — intentionally out of scope. Listed below with the reason.

The **plugin/detection marketplace (F49)** is firmly in state 3 for general
availability. probectl supports detections and integrations as first-class, in-tree
capabilities; what it does *not* offer is a hosted, third-party marketplace for buying
and distributing them. That is a deliberate future bet, not a shipped feature, and the
product's surface map declares it "none-by-design" so the gap is explicit rather than
accidental.

## Built, not yet served edges

These are the honest state-2 edges: code or interfaces exist, but the running
product does not yet serve the capability as an operator-ready surface. Feature
pages can mention the local caveat, but they must link back here so there is one
canonical list to check before a rollout.

| Edge | What exists | What is not served yet | Live-safe behavior |
|---|---|---|---|
| Chaos injector API/control-plane surface | `internal/chaos.UDPProxy` and the dependency-chaos drill exercise controlled local faults. | No REST, UI, MCP, or agent control-plane action can trigger chaos against a live network. | Chaos stays an explicit local/test harness; production control-plane surfaces cannot mutate the network. |
| eBPF TLS posture ingest | The eBPF L7 design can observe TLS library read/write calls when plaintext capture is explicitly enabled, tenant-consented, and allowlisted. | eBPF TLS observations are not wired into the TLS posture inventory, and Go-runtime TLS remains a blind spot until Go-runtime uprobes land. | HTTP synthetic checks are the served inventory source; the eBPF path is not relied on for posture. |
| Raw eBPF flow retention | The eBPF agent publishes live flow records to the tenant-tagged bus for topology, segmentation, and NDR consumers. | Flow-by-flow ClickHouse retention and queryable per-flow history are not wired. | Derived consumers work from the live stream; there is no raw per-flow history surface to depend on. |
| Browser artifact S3 / MinIO backend | Browser synthetic artifacts write through a tenant-bound object-store interface. | An S3 / MinIO adapter is not shipped. | Filesystem and in-memory stores are the served options; tenant prefixes still enforce artifact isolation. |

Other standing non-goals (probectl is a network-observability platform, not these):

- **An inline IPS or firewall.** Detections are signals you tune and export; probectl
  never sits in the traffic path or blocks packets (see [ndr.md](ndr.md), [bgp.md](bgp.md)).
- **A SIEM or log-analytics platform.** It exports to your SIEM rather than replacing it
  (see [siem.md](siem.md)).
- **Autonomous remediation.** Any action layer is observe-only and human-gated by
  default (see [remediation.md](remediation.md)).
- **A vendor-hosted public SaaS.** probectl is self-hosted; the multi-tenant capability
  exists for partners/MSPs to run themselves (see [provider-plane.md](provider-plane.md)).

## Use it

Before you rely on a capability, confirm which state it's in — the editions surface
reports what your license enables:

```sh
curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
  https://probectl.example.com/v1/editions
```

The Admin → Editions view shows the same thing in the UI; the surface map declares each
capability's state. For the marketplace specifically, there is no marketplace command and
no registry endpoint to point at — a community detection bundle is simply not loadable.
Detections are authored in-tree instead; see the NDR-lite page ("Detection-as-code") for
how. That absence is by design, not a misconfiguration.

## Pitfalls & limits

- **"Non-goal" does not mean "coming soon."** Don't plan a rollout around a marketplace
  or an IPS mode; if priorities change, the feature page will say so.
- **"Built, not yet served" is not "served."** If a feature page flags library-only
  status, confirm it appears in the table above before you depend on it in production.
- **This page can lag reality.** If a feature page and this page disagree, the feature
  page (and the running server) win — please report the drift.

## Reference

- Deliberate GA non-goals: plugin/detection marketplace (F49); inline IPS/firewall;
  SIEM/log-analytics platform; autonomous remediation; vendor-hosted public SaaS.
- Authoring detections without a marketplace: [ndr.md](ndr.md) ("Detection-as-code").
- Capability states and licensing: Admin → Editions.

## See also

[NDR-lite](ndr.md) · [Guarded remediation](remediation.md) ·
[Provider plane](provider-plane.md) · [glossary](glossary.md) (IPS, SIEM, NDR)

**Covers:** F47, F49, and the built-not-yet-served eBPF TLS posture, raw flow
retention, and browser artifact backend edges.
