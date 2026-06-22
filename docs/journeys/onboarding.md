# Onboarding: from zero to first data

This is a **journey**, not a feature tour. You walk one continuous path — install
the platform, attach the thing that actually watches the network, ask it to run a
test, and read real data back — and at the end you have proven the whole loop end
to end.

## Who this is for

A new operator or site-reliability engineer (SRE) standing up probectl for the
first time. You have a Linux or macOS machine, Docker, and an hour. You have never
run probectl before and you want to get from an empty install to **real data on
the screen** without guessing.

You do not need to understand every plane yet. You need one mental model: the
**control plane** is a *consumer* (it stores and serves data but observes nothing
itself), and an **agent** is a *producer* (it actually watches the network and
ships what it sees). No producer attached means no data — that is expected, not a
bug. Unfamiliar terms (agent, canary, mutual Transport Layer Security, tenant) are
defined in the [glossary](../glossary.md).

## Before you start

- A machine with Docker and a shell. The full from-source setup needs Go 1.26+;
  the one-command evaluation stack needs only Docker.
- The build and run commands for the control plane, certificates, and agent
  enrollment live in the [getting-started guide](../getting-started.md). This
  journey points you to the exact command in that guide for each step rather than
  repeating it, so you run one verified copy.
- A **tenant** to work in. A tenant is one isolated customer or organization — the
  outermost boundary every record, agent, and query is scoped by. This journey
  uses the built-in default tenant
  `00000000-0000-0000-0000-000000000001`; in a real multi-tenant deployment you
  create tenants first.

Throughout, the control plane is reachable at `https://127.0.0.1:8443` and you
trust its self-signed certificate by passing `--cacert ./certs/ca.crt` to `curl`.

## The path

1. **Install and start the control plane.** Follow the shared setup in the
   [getting-started guide](../getting-started.md) to build the binaries, start the
   backing services, and run the control plane from source on loopback. Confirm
   the consumer is up and empty:

   ```sh
   curl --cacert ./certs/ca.crt https://127.0.0.1:8443/readyz   # -> {"status":"ready"}
   ```

   You observe a ready control plane with no data behind it yet — a healthy, empty
   database waiting for a producer.

2. **Enroll a canary agent with a one-time join token.** A *canary* is a small
   agent that sends real test traffic on a schedule and times the answer; it
   streams results over mutual Transport Layer Security (mTLS), so each agent
   proves its identity and is bound to exactly one tenant. Mint a single-use join
   token for the agent's tenant by posting to the enroll-tokens route:

   ```sh
   curl --cacert ./certs/ca.crt -X POST https://127.0.0.1:8443/v1/agents/enroll-tokens \
     -H 'Content-Type: application/json' \
     -d '{"name": "laptop"}'
   ```

   You observe a `pjt_…` token that expires in about an hour and works once. Hand
   it to the agent, which generates its private key locally and enrolls itself (the
   enrollment commands are in the [getting-started guide](../getting-started.md)).
   This is the agent described in [active / synthetic testing](../features/active-testing.md).

3. **Define and run your first network / HTTP / DNS test.** Create a synthetic test
   — for example an HTTP check, an Internet Control Message Protocol (ICMP) ping, or
   a Domain Name System (DNS) lookup — by posting to the tests route:

   ```sh
   curl --cacert ./certs/ca.crt -X POST https://127.0.0.1:8443/v1/tests \
     -H 'Content-Type: application/json' \
     -d '{"name": "homepage", "type": "http", "target": "https://example.com/", "interval_seconds": 30, "params": {"method": "GET", "expect_status": "2xx,3xx"}}'
   ```

   You observe the test registered. Within one interval the enrolled canary runs it
   and streams a result back. The test types and their parameters are detailed in
   [active / synthetic testing](../features/active-testing.md).

4. **Read the first result and see the path map.** Read the latest result per
   target, then read the topology graph the result feeds into:

   ```sh
   curl --cacert ./certs/ca.crt https://127.0.0.1:8443/v1/results/latest
   curl --cacert ./certs/ca.crt https://127.0.0.1:8443/v1/topology
   ```

   You observe one entry per target — the HTTP result carries `success: true` plus
   a phase breakdown (DNS, connect, TLS handshake, time-to-first-byte, total) — and
   the topology response returns nodes and edges with a coverage block. That graph,
   and the hop-by-hop path your probe took, is [topology & change
   intelligence](../features/topology-and-change.md).

5. **(Optional) Add real host flows with the eBPF agent.** To see real connections
   alongside synthetic results, attach the extended Berkeley Packet Filter (eBPF)
   agent. It watches every Transmission Control Protocol connection the host makes
   and folds them into the same service map. On Linux it reads the live kernel; on
   any operating system you can replay a recorded sample. Run it per the
   [getting-started guide](../getting-started.md), then read the map again:

   ```sh
   curl --cacert ./certs/ca.crt https://127.0.0.1:8443/v1/topology
   ```

   You observe new flow edges between hosts and services. This agent is one of the
   [passive telemetry planes](../features/telemetry-planes.md).

## You're done when

You query `/v1/results/latest` and see a real synthetic result with its phase
breakdown, and `/v1/topology` returns a rendered graph of nodes and edges. The
loop is proven: a producer observed, the control plane consumed it, and the
application programming interface (API) served it back — all within your tenant.

## Next

With data flowing and a topology to reason over, walk the on-call path: turn that
data into objectives, alerts, and a cited root cause in
[from alert to root cause](./alert-to-root-cause.md).

**Journey:** J1 · **Visits:** F1, F2, F3, F4, F5, F11
