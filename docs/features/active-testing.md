# Active / synthetic network testing

## What it is

A **synthetic test** is a robot that pretends to be one of your users. On a
schedule you set, it *sends real traffic* across the network — a ping, a
connection attempt, a web request, a name lookup — and times the answer. probectl
calls one of these scheduled tests a **canary**, after the caged birds miners
once carried underground: a small, expendable sentinel that shows trouble before
the people behind it get hurt.

The thing that actually runs the canaries is the **canary agent** — a single
small program you deploy out where your users (or your services) really sit: in a
branch office, a cloud region, a data center, next to a particular customer. The
agent carries its test types compiled in, runs them on their intervals, and ships
each result back to the control plane. Four test families are the subject of this
page:

- **Reachability and latency** — Internet Control Message Protocol (ICMP, the
  protocol behind `ping`), Transmission Control Protocol (TCP), and User Datagram
  Protocol (UDP) probes that measure whether a host answers and how long it takes.
- **Web / Hypertext Transfer Protocol (HTTP)** tests that measure availability and
  break a page fetch into its phases.
- **Name resolution** — Domain Name System (DNS) lookups, including Domain Name
  System Security Extensions (DNSSEC) validation.
- **Agent-to-agent (A2A)** two-way measurement, where a pair of agents probe each
  other to measure each direction of a path separately.

probectl is **observe-only**: a canary sends test traffic and records what came
back. It never blocks, reroutes, or modifies your real traffic, and it never
phones home — every result stays inside your own network. Terms of art (ICMP,
TCP, jitter, DNSSEC, and the rest) are defined in the [glossary](../glossary.md).

## Why it exists

Imagine waiting for a smoke detector that only beeps *after* the house has
burned down. A dashboard built solely from real user complaints works that way:
by the time tickets arrive, customers are already unhappy. Synthetic tests are
the smoke detector you place *before* the fire — they probe continuously, so you
learn a login page is slow at 2 a.m. when nobody is watching, not at 9 a.m. when
everybody is.

Two specific problems they solve:

- **Catch problems before users do.** A canary runs every 30 seconds whether or
  not a human is looking. A target that starts failing trips an incident long
  before a support queue fills up.
- **Measure from where your users actually are.** A service can be perfectly
  healthy from the data center and miserable from a branch office two countries
  away — the difference is the network *between* them. Because you place agents at
  the vantage points you care about, a canary measures the path your users take,
  not an idealized one. Put an agent in each region and the same test reveals
  *which* location is slow.

A canary failure is a **signal**, not an action. probectl raises it, correlates
it with other planes, and shows it to you — it does not take the target down,
open a firewall, or reroute anything. Acting on a signal is always a separate,
human-decided step.

## How it works

The control plane never goes out and measures the network itself; it
**consumes**. The measuring is done by the agent you deploy. The agent is a
courier, not a postal depot: it holds a direct, authenticated connection to the
control plane and hands its results straight over, so it needs nothing else
standing up — no message bus, no extra datastore, just the control plane
reachable.

**The transport is mutually authenticated and encrypted.** The agent talks to the
control plane over gRPC (a connection protocol built on HTTP/2) wrapped in mutual
Transport Layer Security (mTLS). "Mutual" is the important word: the server proves
its identity to the agent *and* the agent proves its identity to the server, each
presenting a certificate. Until an agent holds a valid identity certificate, the
connection is refused and nothing it sends lands anywhere. There is no plaintext
mode for this channel.

**Each agent is bound to exactly one tenant.** A *tenant* is one isolated
customer or organization. The agent's identity certificate names its tenant, every
result it sends is stamped with that tenant, and the control plane verifies the
pairing before accepting anything. The practical guarantee: a result an agent
produces can only ever land in its own tenant's view — it is structurally unable
to write into another tenant's data, and a query you run only ever returns your
own telemetry.

**The test types, in plain terms.** Each canary type sends a specific kind of
traffic and reports a specific kind of result:

| Type | What it sends | What you get back |
| --- | --- | --- |
| `icmp` | `ping` echo requests | loss, latency, and jitter (the variation between round-trips — what voice and video feel) |
| `tcp` | a connection attempt | reachability plus connect latency |
| `udp` | an echo datagram | round-trip time, or a clear failure if nothing echoes |
| `dns` | a name lookup | resolution time, the answer, DNSSEC validation result, and an optional delegation trace (walking root → top-level domain → authority instead of trusting a cached answer) |
| `http` | an HTTP(S) request | availability plus a phase breakdown: DNS, connect, TLS handshake, time-to-first-byte (TTFB), and total |

For `http` over HTTPS, the canary also captures the TLS handshake details, which
feed the certificate-posture view so you can spot an expiring certificate before
it bites.

**Agent-to-agent (A2A)** turns a *pair* of agents into a two-way measurement.
Both ends timestamp each probe and reply, so each direction's latency is measured
on its own rather than guessed from a single round-trip — useful when a path is
asymmetric (fast one way, slow the other). A2A is off by default; you opt in, and
every brokered frame is authenticated with a per-session key delivered over the
existing mTLS channel.

**Results flow through one pipeline.** Whatever the type, a result lands in the
same place: the control plane stores it, plots its numbers as metrics, and feeds
it into incident correlation. When a canary to a service starts failing and that
service also appears in another plane (say, a service map), both signals land in
**one** correlated, tenant-scoped incident instead of two unrelated alerts.

**The agent never loses data to a network blip.** If the control plane is briefly
unreachable, results buffer to a local on-disk queue and drain on reconnect.

## Use it

Here is the whole loop: define a test, run the agent, read the result. Probes run
straight from the agent's configuration file — you do not have to create anything
server-side first.

A minimal agent configuration with one inline HTTP test. The `tls:` block points
at the identity files the agent received when it enrolled; the `canaries:` block
defines what to probe:

```yaml
control_plane:
  grpc_addr: "control.example:9443"   # the control plane's agent listener

tls:
  cert_file: ./identity/cert.pem      # the agent's identity (proves the agent to the server)
  key_file:  ./identity/key.pem
  ca_file:   ./trust/ca.crt           # verifies the SERVER to the agent
  server_name: "control.example"      # must match the server certificate

agent:
  capabilities: ["http", "icmp", "dns"]
  heartbeat_interval: 30s

canaries:
  - type: http
    target: "https://app.example/health"
    interval: 30s
    timeout: 10s
    params:
      method: "GET"
      expect_status: "2xx,3xx"
  - type: dns
    target: "app.example"
    interval: 60s
    params:
      type: "A"
      dnssec: "true"
```

Start the agent:

```sh
probectl-agent -config /etc/probectl/agent.yml
```

Within one interval (30 seconds for the HTTP test above) the agent connects, runs
the probe, and streams the result. Read the latest result per target from the
API:

```sh
curl https://control.example/v1/results/latest
```

What you should observe: one entry per target. The `http` result carries
`success: true` plus the phase breakdown (DNS, connect, TLS, TTFB, total), so a
slow page tells you *which* phase was slow. The `dns` result carries the
resolution time, the answer, and whether DNSSEC validation passed. The same data
renders on the **Targets / synthetic results** screen in the web interface.

You can also create a test from the command-line tool — for example a scripted
browser-style transaction (which runs as an HTTP transaction by default):

```sh
probectl test create \
  --name login-check \
  --type browser \
  --target https://app.example/login \
  --param 'script={"name":"login","start_url":"https://app.example/login","steps":[{"action":"goto"},{"action":"assert_status","status":200}]}'
```

## Pitfalls & limits

- **No agent, no data.** A freshly installed control plane observes nothing — it
  is a healthy, empty database. The fix is always to attach an agent. If a probe
  shows no results, the most common cause is that no agent is enrolled or running
  for that tenant.
- **The agent must have an identity first.** The mTLS channel refuses an
  un-enrolled agent. If results never arrive, confirm the agent enrolled
  successfully and its certificate has not expired. Certificates auto-rotate at
  roughly two-thirds of their lifetime *only* when an identity server is
  configured; with operator-managed certificates you rotate them yourself.
- **A UDP or voice target must actually echo.** UDP and RTP-style probes need the
  far end to reflect the datagrams. A target that does not echo shows up honestly
  as 100% loss with an explicit "unmeasurable" failure — the canary never invents
  a result from a silent target.
- **A canary failure is a signal, not a verdict on the whole world.** A single
  agent's probe reflects the path *from that agent*. To distinguish "the service
  is down" from "this one location's path is bad," run the same test from more
  than one vantage point and compare.
- **probectl is observe-only.** It does not block, throttle, or reroute traffic,
  and it is not an intrusion-prevention system. A canary tells you something is
  wrong; a human decides what to do about it.
- **A2A is opt-in.** Two-way agent measurement is disabled by default; you must
  enable it and have agents at both ends. For site-to-site testing, start a
  tenant-scoped mesh with site-labeled agents so every directed site pair gets a
  brokered A2A session and topology edge.
- **Probes fail closed.** A probe with a missing credential, an unverifiable
  target identity, or an unreachable control plane stops or reports failure rather
  than guessing — silence is never reported as success.

## Reference

- **Test types:** `icmp`, `tcp`, `udp`, `dns` (with DNSSEC and delegation tracing),
  `http` (with DNS/connect/TLS/TTFB/total breakdown), `browser` (scripted
  transaction), `voice` (call-quality scoring), plus agent-to-agent (`a2a`)
  two-way measurement and a `noop` heartbeat.
- **Transport:** agent → control plane over gRPC wrapped in mutual TLS; the agent
  is bound to one tenant by its identity certificate; results buffer to local disk
  during an outage and drain on reconnect.
- **Read results:** `GET /v1/results/latest` (latest result per target), or the
  Targets / synthetic results screen in the web interface.
- **Create a test from the CLI:** `probectl test create --name … --type … --target …`.
- **Related capabilities (separate pages):** Digital experience (last-mile, voice,
  real-user monitoring); Topology & change (the correlated picture a failing
  canary feeds into). See also the deployment and getting-started guides for
  standing up an agent end to end.

**Covers:** F1, F2, F4, F5
