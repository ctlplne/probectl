# Digital experience monitoring (from the user's edge)

## What it is

A service can be perfectly healthy in the data center and still feel broken to a
person sitting in a coffee shop on weak Wi-Fi. **Digital experience monitoring
(DEM)** is the practice of measuring quality from where the *user* actually is —
the last few feet and the last few miles that your server-side tests physically
cannot see. It answers the question every help desk dreads: *"is it us, or is it
the user's connection?"*

probectl gives you several lenses on that question, and this page covers five of
them:

- **Browser synthetic monitoring** — a scheduled robot that walks through a
  scripted web transaction (a login, a checkout) and reports per-step timings.
- **The endpoint agent (DEM)** — a small program on the user's own device that
  measures their Wi-Fi, their home gateway, their internet service provider (ISP)
  link, and their browser sessions, then *attributes* a slowdown to the closest
  impaired layer.
- **Real user monitoring (RUM)** — passive timings collected from the browsers of
  your *actual* visitors, telling you whether real humans are being hurt.
- **Voice / Real-time Transport Protocol (RTP) call quality** — a probe that sends
  real voice-shaped packets and scores how a call would sound: jitter, loss, and a
  Mean Opinion Score (MOS).
- **Last-mile / Wi-Fi / ISP diagnostics** — the per-hop, per-layer detail behind
  the endpoint agent's verdict.

Everything here is **observe-only** and **sovereignty-respecting**: probectl
measures and reports, never blocks or reroutes, and telemetry never leaves your
network — the on-device agent emits to *your* systems and **never phones home**.
Terms of art are defined in the [glossary](../glossary.md).

## Why it exists

Server-side synthetic tests are like checking the water pressure at the street
main: useful, but they tell you nothing about the pressure at the kitchen tap. If
a remote employee's call keeps dropping, the main can read perfect while the tap
is bone dry. DEM moves the measurement to the tap.

The motivations, lens by lens:

- **Synthetics answer "can a robot reach it?"** — they probe on a timer, catching
  outages before tickets arrive. But a robot is not a person.
- **RUM answers "are humans actually hurting?"** — it watches real visitors, so a
  problem that only affects, say, one browser on one network shows up. RUM's blind
  spot is the inverse: nobody visiting a broken page means no RUM data, which is
  *not* proof of health.
- **The endpoint agent answers "whose fault is the last mile?"** — when a session
  is slow, it localizes the cause to Wi-Fi, the local network, the ISP, or the
  wider network, so you stop blaming "the network" for what is really a weak
  signal in someone's spare bedroom.
- **The voice probe answers "would a call sound good right now?"** — by sending
  call-shaped traffic instead of guessing from ping times.

The real value is **joining these witnesses**. A robot can say a page is slow; a
crowd of real users can confirm humans feel it; the endpoint agent can say the
fault is the user's Wi-Fi, not your service. probectl computes a *convergence
verdict* per (application, host) that puts the synthetic and real-user testimony
side by side.

## How it works

### Browser synthetic monitoring

You write a transaction as a short script — go to a page, fill a field, click a
button, assert that "Welcome" appeared — and a canary runs it on a schedule. The
default driver reads the script as a sequence of HTTP requests, so it runs
anywhere the agent runs (including air-gapped networks) with no browser engine
required. It reports a **waterfall**: a per-request timing ladder showing when
each resource's DNS lookup, connection, TLS handshake, and first byte happened — a
Gantt chart of the page load. A separate rendering-capable worker (built on a real
Chrome engine) can add paint timings and a screenshot; that worker is an optional
component, not the default path.

On failure, the failed page is captured and stored in an object store under a
**per-tenant prefix**, so one tenant's failure artifacts are isolated from
another's at the storage layer.

### The endpoint agent (DEM)

This is a small, cross-platform program (Linux, macOS, Windows) that runs on a
user's own device with **no elevated privileges** — it uses the operating system's
own `traceroute`/`tracert` and read-only Wi-Fi queries. It captures four things
from where the user sits:

| Signal | What it reads |
| --- | --- |
| **Wi-Fi** | signal strength (Received Signal Strength Indicator, RSSI, in dBm — negative, closer to zero is stronger), link rate, band, channel; the cellular equivalents where applicable |
| **Gateway** | reachability, round-trip time, and loss to the home router |
| **Last-mile** | per-hop round-trip and loss along the path, split into local / ISP-edge / beyond segments |
| **Session** | DNS, connect, TLS, and time-to-first-byte timings to each target |

The headline is **attribution**. A weak Wi-Fi link inflates the gateway, ISP, *and*
session numbers, because they are all measured *through* that link. So the agent
walks outward from the device — Wi-Fi → local network → ISP → wider network — and
blames the **closest** impaired layer. Checking your own tap before calling the
water company: if pressure is low at the tap, every reading downstream is low too,
and the nearest fault owns the verdict. The verdict (`wifi`, `local`, `isp`,
`network`, `none`, or `unknown`) carries a confidence score and a plain-language
summary.

Because the agent lives on someone's personal device, **data minimization is a
hard rule**. Measurements that diagnose experience (signal, round-trip, loss,
timings — none of which identify a person) are kept; geolocatable identifiers are
dropped *before* a sample ever leaves the device. The Wi-Fi access point's
hardware address and public hop IPs are not collected, because public databases
can map them to a physical address. The agent also **discloses exactly what it
collects every time it starts**.

### Real user monitoring (RUM)

A tiny browser script sends one small, fire-and-forget message — a **beacon** — as
the user leaves a page, carrying standard web-vitals timings: time-to-first-byte,
first and largest contentful paint, cumulative layout shift, interaction-to-next-
paint, and full load time. The beacon arrives at a write-only ingest endpoint that
treats every payload as **untrusted**:

- It carries a **public application key** (it ships in page source like every RUM
  product's site key). The key is a routing label, not a password: the server uses
  it to pick the configured tenant, rate-limit, and apply an origin allow-list. The
  payload never names its own tenant, and the key grants no read access to
  anything.
- Consent is required, unknown fields are rejected outright (so a payload cannot
  smuggle a user id or email), URLs are re-redacted server-side, and no IP or user
  agent is stored.

The beacon's `host` is the **join key**: a browser synthetic test run against the
same host is what completes the convergence verdict. RUM is only called *degraded*
with enough views in the window to be meaningful — a trickle is never an outage.

### Voice / RTP call quality

The voice canary sends **real RTP packets** — the same packet format, 20 ms
cadence, and priority marking a softphone uses — to a target that echoes them back,
then scores the echoes the way a phone's own quality meter would. A stunt double
for a call: dressed exactly like one, but nobody is talking. From the echoes it
computes three numbers operators recognize:

- **MOS** (Mean Opinion Score, roughly 1.0–4.5) — the headline call-quality score,
  derived from a standard transmission-quality model.
- **Jitter** — how unevenly packets arrived.
- **Packet loss** — how many packets never came back.

probectl uses a deliberately simplified, transport-only model and **says so on
every result**, so a *computed* score is never presented as a *measured* listening
test. It scores narrowband codecs (G.711, G.729); wideband / HD voice is out of
scope rather than approximated with the wrong formula.

### Where it all goes

Every lens funnels into the same pipeline as the rest of probectl. Each device,
beacon, and call score is tenant-stamped, stored, plotted as metrics, and fed into
incident correlation — so a last-mile problem and a service problem can land in
one correlated, tenant-scoped incident.

## Use it

**Define a voice test** against a target that echoes UDP (a probectl agent acting
as a responder works):

```json
POST /v1/tests
{"name": "voip to pbx", "type": "voice", "target": "pbx.example:5004",
 "interval_seconds": 60, "timeout_seconds": 3,
 "params": {"codec": "g711", "duration_seconds": "3", "dscp": "46"}}
```

What you should observe in the result: `voice.mos` up front (4.0+ good, 3.6+ fair,
below that poor), alongside `voice.jitter.ms`, `voice.loss.pct`, and the model
name. A silent target shows 100% loss and an explicit "voice path unmeasurable"
failure rather than a fabricated score.

**Turn on RUM** and drop the snippet into your pages after your consent banner
accepts. RUM ingest is opt-in because it is an inbound surface:

```yaml
# control-plane configuration
PROBECTL_RUM_ENABLED: "true"
# public app key -> tenant/app, with the browser origins allowed to send beacons:
PROBECTL_RUM_APPS: "pk_storefront=acme/storefront;origins=https://shop.example|https://www.shop.example"
PROBECTL_RUM_RATE_PER_MIN: "300"
```

```html
<script src="https://probectl.example/probectl-rum.js"
        data-key="pk_storefront"
        data-endpoint="https://probectl.example/ingest/rum" defer></script>
<script>
  // after your consent banner accepts:
  window.probectlRUM.consent()
</script>
```

What you should observe: `rum.*` metrics begin appearing, and `GET /v1/rum` shows
the convergence verdict per (app, host) plus per-tenant reject counters
(`rejected_no_consent`, `rejected_malformed`, `rejected_invalid_field`) so you can
see exactly what is being dropped.

**Deploy the endpoint agent** to managed laptops through your mobile-device-
management tool, pointed at your message bus with a tenant id. You are done when a
device appears in the fleet view with a verdict:

```sh
curl https://control.example/v1/endpoints
```

What you should observe: one entry per device, attribution verdict first ("slow:
WiFi / ISP / network"), with Wi-Fi strength, gateway and ISP-edge round-trip, and
per-layer scores. Identifiers the agent withheld render honestly as "withheld
(privacy)" — never a re-derived or fabricated value. A `collector_running: false`
flag distinguishes an unwired pipeline from a genuinely empty fleet.

## Pitfalls & limits

- **Absence of data is not proof of health.** RUM only sees opted-in users on
  instrumented pages; nobody visiting a broken page produces no beacons. Likewise,
  a device with no endpoint agent is invisible. Treat empty RUM or an empty fleet
  as "not measured," not "fine."
- **A RUM key is public, not a secret.** It ships in your page source. It cannot
  read anything and cannot name its own tenant — but do not treat it as a
  credential, and do set an origin allow-list in multi-tenant or regulated
  deployments (it is required there).
- **The voice MOS is a model, not a listening test.** It is a transport-only
  estimate, disclosed as such on every result, for narrowband codecs only. Bursty
  loss degrades real calls more than the formula credits.
- **A voice or UDP target must echo.** No echo means an honest 100% loss / "
  unmeasurable" result, not a guessed score.
- **The endpoint agent is best-effort and privacy-gated.** A wired device reports
  Wi-Fi as "unavailable" rather than faking it; a strict-privacy preset collects no
  identifiers at all. Gateway health is derived from the first hop of the trace,
  not a separate privileged ping.
- **The default browser driver does not render.** It reads the transaction as
  HTTP, so it captures real request timings but not paint timings or a visual
  screenshot unless you run the separate rendering worker. Some sites detect
  non-rendering clients; configure a realistic user-agent for those.
- **This is not full application performance monitoring.** No distributed traces,
  no session replay, no user-journey reconstruction — that is deliberately out of
  scope. RUM here is page-level vitals and errors converged with synthetics.
- **Observe-only, never phones home.** None of these lenses block, reroute, or act
  on traffic, and the on-device agent emits only to your own systems.

## Reference

- **Browser synthetic:** create with `probectl test create --type browser`; the
  default driver runs the transaction as HTTP and reports a request waterfall.
- **Endpoint agent (DEM):** runs unprivileged on Linux/macOS/Windows; deploy via
  your mobile-device-management tool; fleet at `GET /v1/endpoints`; attribution
  verdicts `wifi` / `local` / `isp` / `network` / `none` / `unknown`.
- **RUM:** opt-in via `PROBECTL_RUM_ENABLED`; public app keys mapped in
  `PROBECTL_RUM_APPS` (origins required under multi-tenant / regulated); beacon
  ingest at `/ingest/rum`; verdicts and reject counters at `GET /v1/rum`.
- **Voice / RTP:** `type: voice` test; params `codec` (`g711` / `g729`),
  `duration_seconds`, `dscp`; metrics `voice.mos`, `voice.jitter.ms`,
  `voice.loss.pct`, `voice.one_way.ms`; narrowband only.
- **Last-mile diagnostics:** the per-hop, per-layer detail (Wi-Fi, gateway,
  ISP-edge, beyond) behind the endpoint verdict, on the per-endpoint detail screen.

**Covers:** F15, F16, F20, F21, F46
