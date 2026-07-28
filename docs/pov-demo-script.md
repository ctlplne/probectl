# probectl — 10-minute demo script + PoV kit

This is the canonical, versioned talk track. It states behavior that can be
proved from the shipping product. Named competitor comparisons belong in the
dated competitive matrix; do not improvise an absence claim here without a
current source.

Two vehicles, know which one you are driving:

- **Product tour** — any built deployment, `…/ui/dashboards?demo=1`. It is
  static, transport-isolated, and safe on a call. `Shift+D` exits. The banner
  and Demo-data badges stay visible.
- **Fixture loop** — `cd web && npm run dev:fixtures` (development only). This
  is the real UI on realistic data: an interactive incident room, topology
  what-if, path-round comparison, and cited Ask answers.

The demo fiction in both vehicles is a checkout latency regression from
09:30–09:45 UTC. A routing-policy change at 09:32 is followed by an AS-path
change at 09:37, a 41% transit-traffic shift at 09:38, and checkout p95 moving
from 42 ms to 91 ms at 09:39.

## The 10 minutes

**0:00 — Opening.** “Network problems are usually diagnosed across tools that
do not share a clock: routing, flow, synthetics, and host telemetry. probectl
puts those planes in one self-hosted control plane, on one tenant-scoped
timeline, with an AI answer that cites its evidence.”

**0:45 — Dashboards** (`/dashboards?demo=1`). Point at the KPI row: steady
values are deliberately quiet text and only exceptions earn badges. Then use
the latency chart: checkout steps at 09:37 while payments stays flat. “The
incident is visible in the trend before any alert fires. The chart, legend,
crosshair, keyboard behavior, and themes are native probectl UI and require no
hosted dashboard or third-party SaaS asset.”

**2:30 — Incidents** (`/incidents`). Walk the clock left to right: change at
09:32, BGP at 09:37, flow at 09:38, and synthetic evidence at 09:39. “The
product-specific advantage is one operator-owned absolute axis across all four
planes. The change marker answers ‘what changed immediately before this?’”
Click a marker; selection stays synchronized with evidence rows and citations.

**4:30 — Path** (`/path`). Show the ECMP fan, the MPLS label at the edge, and
the lossy transit hop at TTL 6 in the loss tone. The same hop is cited at 3.8%
in the tables. “Rounds are immutable, and the live product compares the
current and previous path so a route change is visible without mentally
diffing traceroute text.”

**6:00 — Planes and Topology** (`/planes`, `/topology`). In Planes, show the
five producers, ingest freshness, and the late poller honestly marked Delayed.
In Topology, select `edge-r1`. “The observe-only what-if view reports that
three services in two regions are affected, with flow, path, and BGP evidence.
It stays on the same historical, tenant-scoped graph and never changes the
network.”

**7:30 — Ask** (`/ask`). “One question produces an RCA whose findings cite BGP
event `#204`, flow edge `#881`, and synthetic round `#771`. Tenant scope is
enforced before RBAC, over the same stores the screens read. The default
adapter is deterministic and in-process, so it works air-gapped. A remote
model is used only when an operator configures it and the tenant consents; the
request is redacted and audited.”

**8:30 — Security and Admin** (`/security`, `/admin`). “Detections are
confidence-scored, suppressible, SIEM-exportable signals—never inline IPS
actions. TLS posture feeds the same evidence pool.” In Admin: “Unlicensed
commercial features are hidden rather than lockware. After expiry they degrade
read-only; telemetry pipelines continue.”

**9:30 — Close.** “Self-hosted or MSP-hosted, it is one codebase. The default
deployment keeps telemetry local, makes no call home, and verifies licenses
with offline math. Any remote AI or export is operator-enabled, consent-gated
where tenant data is involved, redacted where applicable, and audited. The
core is MPL-2.0-licensed. A PoV uses your agents and tenants; success is a
measured incident workflow that beats your current diagnosis baseline.”

## Deep-dive moments

- Incident room: use the arrow keys across clock markers and watch evidence
  and citations track selection. Journey J2 remains within three interactions
  of a cited RCA.
- Topology what-if: select a node and show the cited blast-radius update.
- Path history: flip rounds and show the ECMP branch appear or disappear with
  the `+49 ms` delta.
- Explorer: run a saved question and use the real time-axis chart and
  crosshair.
- Themes: cycle dark → aurora → ember. Deployment theming is a token override,
  and all three themes pass the same contrast gate.

## Objection handling

- **“Is there a SaaS?”** No vendor-operated SaaS. An operator can run a
  sovereign single-tenant deployment or an MSP can host the same multi-tenant
  codebase.
- **“What leaves my network?”** By default, no probectl call-home or product
  telemetry egress occurs, and license verification is offline. Operator-enabled
  outbound paths are explicit and off until configured: remote AI (tenant
  consent, redaction, and audit), read-only public-data/threat/outage feed
  fetches, OTLP/SIEM/on-call exports, and active probes to their configured
  targets. Disabled or unreachable external feeds degrade gracefully.
- **“Is this an IPS or full NDR?”** No. Detections are confidence-scored
  signals and remediation is observe-only or human-gated. probectl feeds the
  operator’s SIEM; it does not replace it.
- **“Can we white-label it?”** No. MSPs resell under the probectl banner.
  Theming is a deployment-level token override, not tenant branding.
- **“What scale?”** Mechanics are proven at CI scale with hard floors.
  L/XL/XXL reference numbers remain provisional until reference-iron evidence
  lands; do not present them as customer capacity.
- **“AI privacy?”** The built-in deterministic adapter is local. Remote
  adapters require explicit operator acknowledgement plus tenant consent,
  redact the outbound request, and emit an audit receipt.

## Logistics

- Tour: open `/ui/dashboards?demo=1`. Exit with `Shift+D` or the banner button.
  The route outlet is unmounted and transport fails closed.
- Fixture loop: run `PROBECTL_WEB_FIXTURES=1 npm run dev` or
  `npm run dev:fixtures` as documented in `docs/development.md`. This mode is
  development-only and absent from release builds.
- Rehearse once with the command palette (`⌘K`) so route changes stay
  keyboard-first.
