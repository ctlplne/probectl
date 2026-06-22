# Topology & change intelligence

## What it is

A network has a *shape*: probes reach targets through a chain of router hops,
services call other services, networks on the internet announce blocks of
addresses, devices carry interfaces. probectl keeps a live model of that shape —
the **topology graph** — and lets you do three things with it:

- **Path visualization** — see the actual hop-by-hop route a probe takes to a
  target, drawn as a chain.
- **The live topology graph** — one picture that stitches together every plane
  (paths, the service map of who-talks-to-whom, routing, device telemetry) into a
  single graph of nodes (the things) and edges (who touches whom). It is
  **versioned** — it remembers when each thing existed, so you can rewind it — and
  it supports **what-if** simulation: "if this fails, what breaks?"
- **Change intelligence** — probectl pulls in *change events* (a deploy, a config
  edit, a route flip, an infrastructure-as-code apply) from the systems that
  already record them, keeps a per-tenant timeline, and **correlates** recent
  changes to incidents, so you can answer the question that resolves most outages:
  *"what changed?"*

Two properties hold throughout. First, **the graph is tenant-scoped**: every query
returns only your own tenant's shape, enforced below the query layer, so you never
see another tenant's topology. Second, **everything here predicts and explains, it
never acts** — what-if runs on a copy and changes nothing, and a change event is
*context*, never an alarm or a trigger for remediation. Terms of art (hop, prefix,
autonomous system, HMAC, and the rest) are defined in the [glossary](../glossary.md).

## Why it exists

Two recurring pains:

- **"Five dashboards, one outage."** When something breaks, the evidence is
  scattered: a path is failing here, a service is unreachable there, a route
  changed somewhere else. A human ends up mentally joining five screens under
  pressure. One shared graph lets a single failure be reasoned about across planes
  — "this hop went down, which broke these paths, which back these services, which
  back these service-level objectives" — instead of five disconnected alerts.
- **"What changed?"** Most outages have a human cause: someone deployed, edited a
  config, flipped a route, or ran an apply. The fastest path to a fix is usually
  the change that caused it. But the hard part is *not* collecting changes — it is
  not burying you under every deploy that happened that day. Change intelligence
  surfaces the *few likely* causes for a given incident, ranked, rather than the
  firehose.

The versioned graph exists because root-cause analysis needs the graph *as it was
at the incident moment*, not as it is now. A photo that gets repainted loses the
past; a ledger of sightings keeps it. probectl keeps the ledger.

## How it works

### The graph: one shape from many planes

Each node and edge has a **kind** and a **stable id derived from its identity** —
like a passport number rather than a visitor badge — so the same router or service
seen by two different planes folds into *one* vertex instead of appearing twice.

- **Nodes** include: `agent`, `hop` (a router along a traceroute), `host` (a
  probe target), `service` (a workload seen in the service map), `prefix` (a block
  of IP addresses announced by a network), `as` (an autonomous system — one
  independently-operated network, like an ISP), and `device` (a managed switch or
  router).
- **Edges** include: `path` (hop-to-hop adjacency), `flow` (service-to-service
  calls), `routing` (a network announcing a prefix), and `device` (a device to the
  hop it carries). Edge attributes follow open telemetry conventions where they
  exist — a `flow` edge, for instance, carries the destination port and protocol.

Path visualization is the simplest read of this graph: the chain of `hop` nodes
between an `agent` and a `host`, with the per-hop latency the path plane measured.

### Versioning: rewinding the graph

Every node and edge carries a **validity interval** — when it was first seen and
last seen. Re-observing something extends its interval and merges its attributes,
so the graph is a ledger, not a snapshot. You can ask for the graph **as it was at
time `t`**, or the full current graph. That is exactly what lets root-cause
analysis replay the network to the moment an incident opened.

### What-if: a fire drill on the floor plan

What-if simulation answers *"if node or link X fails, what breaks?"* — a fire
drill run on the floor plan, never the building. It runs on a *copy* of the graph
at a chosen moment, removes the failed element, recomputes reachability, and
returns: which agent→target paths broke, which rerouted (with the surviving route
shown), which services are impacted (by walking the call arrows *backward* to find
everyone that depends on the failed one), which prefixes a failed network would
stop announcing, and which nodes become disconnected.

Two honesty rules matter. An **unknown target is an error**, never a clean
"no impact" — a typo in a simulation must not look like a healthy result. And
because accuracy depends on how complete the graph is, every result carries a
**coverage block** — per-plane edge counts plus notes for missing planes ("no
service-map edges — service impact may be incomplete"). Read it like the number of
weather stations behind a forecast: trust the prediction in proportion to how much
reported. The simulation is strictly read-only; acting on a prediction is a
separate, human-decided step.

### Change intelligence: the webhook is an untrusted front door

A **webhook** is a POST that an external system (GitHub, GitLab, your continuous-
integration pipeline) sends to a URL you gave it whenever something happens. Since
that POST ends up feeding root-cause analysis, probectl treats every delivery as
**untrusted** and makes it clear all of these before anything is stored:

- **TLS.** The endpoint is HTTPS-only.
- **Signature verification, in constant time.** Depending on the provider, the
  sender either signs the body with a shared secret — a hash-based message
  authentication code (HMAC-SHA256), a wax seal only a holder of the secret can
  produce (generic, GitHub) — or presents a shared token verbatim in a header
  (GitLab). probectl verifies whichever applies against that webhook's configured
  secret, using a comparison that takes the same time whether the first or last
  byte differs, so response timing leaks nothing. An unsigned or forged delivery is
  rejected before the body is even parsed.
- **Tenant binding from the verified credential.** The tenant comes from the
  matched webhook secret, never from the payload — the wire format has no tenant
  field to spoof. The guarantee: one tenant cannot inject another tenant's change
  events, because doing so would require that tenant's secret.
- **Size-limited, validated parse.** Oversized bodies are capped and malformed
  entries are dropped, not stored.

Every change is normalized onto one record with a `kind` (`deploy`, `config`,
`route`, `iac`, `commit`, `release`, `other`), a title and summary, an `actor`, a
reference (commit or deploy id), and — crucially — a correlation **`target`** (a
host, service, or IP) and/or **`prefix`** (an address range). Those anchors are how
a change ties to an incident.

### Correlation: were you near the scene, and were you there just before?

When you ask for an incident's likely causes, probectl scores each recent change
the way a detective sizes up a suspect — two questions:

- **Topology proximity** — was the change *near the scene*? An exact target match
  scores highest, then an IP inside the incident's prefix, then overlapping
  prefixes.
- **Time proximity** — was the change there *just before* it happened? A change at
  the incident's start time scores highest; one a full window earlier scores near
  zero.

The two combine into a blended score. Only changes within the configured window
*before* the incident count, plus a few minutes of clock-skew grace so a
near-simultaneous deploy logged a moment after the incident still correlates. A
change that matches no targeted incident and falls outside the window is dropped.
The result: the root-cause analysis is fed the few likely causes, ranked — not the
firehose — and it *cites* the change within your tenant and authorization scope.

## Use it

**Read your live topology graph** (or the graph as it was at a past moment):

```sh
# the current graph for your tenant
curl https://control.example/v1/topology

# the graph as it existed at a specific time (rewind)
curl "https://control.example/v1/topology?at=2026-06-22T14:00:00Z"
```

What you should observe: a layout-agnostic list of nodes (each with `id`, `kind`,
`label`) and edges (each with `from`, `to`, `kind`), plus a coverage block telling
you which planes reported. If topology is not wired on a deployment, you get
`topology_running: false` with empty lists rather than an error.

**Run a what-if simulation** for failing one node or edge:

```sh
curl -X POST https://control.example/v1/topology/whatif \
  -H 'Content-Type: application/json' \
  -d '{"target": "service:payments-api"}'
```

What you should observe: lists of broken paths, rerouted paths (with surviving
routes), impacted services and prefixes, disconnected nodes, and a coverage block.
An unknown target returns a `404`, never an empty "no impact." In the web
interface this is the **Topology** page's what-if overlay: the failed element
dashed, the impacted elements highlighted.

**Send a change event** from a CI pipeline or automation tool, signed with that
webhook's secret:

```sh
BODY='{"kind":"deploy","title":"deploy payments-api to prod",
 "target":"api.example.com","actor":"ci","ref":"abc123"}'

curl -X POST https://control.example/ingest/changes/generic/my-webhook-id \
  -H "X-Probectl-Signature: sha256=$(compute_hmac "$WEBHOOK_SECRET" "$BODY")" \
  -d "$BODY"
```

What you should observe: a verified delivery returns `202 Accepted` with
`{"accepted": 1}`. An unsigned or forged delivery returns `401` and stores
nothing. A verified-but-empty delivery (such as a setup ping) returns success and
stores zero events.

**Ask an incident what changed near it:**

```sh
curl https://control.example/v1/incidents/<incident-id>/changes
```

What you should observe: the ranked candidate changes for that incident, scored by
topology proximity and recency. The full timeline of all changes is at
`GET /v1/changes`.

**Configure the webhooks** (one distinct id and secret per tenant; inject the
secret from a secret manager, never commit it):

```yaml
# control-plane configuration
# comma-separated  id:tenant:provider:secret  entries
PROBECTL_CHANGE_WEBHOOKS: "my-webhook-id:acme:generic:<secret>"
# how far before an incident a change is considered a candidate cause
PROBECTL_CHANGE_CORRELATION_WINDOW: "24h"
```

## Pitfalls & limits

- **The graph only shows what the planes emit.** probectl links what it observes
  and reports the gaps where it cannot. The coverage block is not decoration — a
  what-if result with missing planes is genuinely less complete, and it tells you
  so. Don't read "no impact" without reading the coverage.
- **Some links depend on the device telemetry exposing interface IPs.** Where
  today's device telemetry does not, the device node still exists but without its
  hop links, and that gap is reported as a coverage note rather than silently
  treated as complete.
- **A change event is context, not an alarm.** A deploy is a *candidate cause*,
  surfaced and ranked only when an incident opens near it in time and topology. It
  never raises an alert on its own and never triggers remediation.
- **A change needs an anchor to correlate well.** A change with neither a `target`
  nor a `prefix` can sit on the timeline, but it can only correlate to an
  untargeted incident — give automation events an explicit target or prefix.
- **An unsigned or misconfigured webhook is rejected, by design.** If changes are
  not appearing, the usual cause is a signature mismatch or a missing webhook
  credential — the front door fails closed rather than storing an unverifiable
  change.
- **What-if is a prediction on a model, not a guarantee about the live network.**
  It is read-only and never mutates the graph. Acting on the prediction is a
  separate, human-decided capability.
- **Tenant-scoped throughout.** Every topology read and every change correlation
  returns only your own tenant's data; an invalid or empty tenant scope returns
  nothing.

## Reference

- **Read the graph:** `GET /v1/topology` (live) or `GET /v1/topology?at=RFC3339`
  (as it was at a past moment); returns nodes, edges, and a coverage block.
- **What-if:** `POST /v1/topology/whatif` with `{"target": "...", "at": "..."}`;
  unknown target is a `404`; result is read-only.
- **Send a change:** `POST /ingest/changes/{provider}/{id}` with the provider's
  signature header (GitHub, GitLab, and a generic CI/infrastructure-as-code scheme
  are supported); verified delivery returns `202`, forged returns `401`.
- **Change timeline & correlation:** `GET /v1/changes` (full timeline);
  `GET /v1/incidents/{id}/changes` (ranked candidate causes for one incident).
- **Configure:** `PROBECTL_CHANGE_WEBHOOKS` (one `id:tenant:provider:secret` per
  tenant); `PROBECTL_CHANGE_CORRELATION_WINDOW` (default `24h`).
- **Related capabilities (separate pages):** Active testing (the path probes that
  feed this graph); Digital experience (the last-mile signals that can join an
  incident).

**Covers:** F3, F39, F40
