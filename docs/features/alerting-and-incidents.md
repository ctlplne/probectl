# Alerting and incidents

## What it is

A smoke detector does two jobs that feel like one: it *watches* for smoke, and
it *sounds* when it finds some. probectl splits those jobs and adds a third that
matters most when a real fire starts — it tells you the **kitchen, the hallway,
and the bedroom alarms all went off because of the same fire**, instead of
making you run between three beeping boxes.

So this page covers two connected things:

- **Alerting** — durable rules that watch your metrics and notify a human when a
  value crosses a line or drifts from its own normal. A rule can be *silenced*
  (hushed for a while) or *acknowledged* (claimed by an owner), and those
  operator actions survive a restart of the platform.
- **Dashboards and the incident timeline** — instead of a flood of disconnected
  alerts, probectl groups related signals from every observability plane
  (synthetic tests, routing, flow, device telemetry, host/kernel data) into a
  single, [tenant](../glossary.md)-scoped **incident** that carries
  cross-plane evidence. One fault becomes one incident, not five pages.

A *plane* here means one source of network truth — synthetic probing, Border
Gateway Protocol ([BGP](../glossary.md)) routing, flow analytics, device
telemetry, or host/Layer-7 data from the extended Berkeley Packet Filter
([eBPF](../glossary.md)). A *tenant* is one isolated customer or organization in
a deployment — the outermost boundary every record and query is scoped by.

## Why it exists

Two failures plague network operations. The first is the **noisy sample**: one
bad measurement pages a human at 3 a.m. for a blip that healed itself. The
second, worse, is the **alert storm**: a single underlying fault — say a routing
change — trips a dozen detectors at once, and the on-call engineer wastes the
first twenty minutes of an outage just figuring out that the twelve alerts are
*one* problem.

probectl answers the first with debounce and learned baselines (a rule must hold
for several evaluations before it fires). It answers the second with
**cross-plane correlation**: the control plane continuously folds related
signals into one incident, so the human reads a single story with evidence
attached, not a wall of red.

## How it works

probectl deliberately keeps **rules** (what you configured) separate from
**what is firing right now** (a live computation), because they have different
lifecycles. Rules are operator intent and must survive restarts, so they are
stored durably. "What is firing" is recomputed from the latest measurements on
every evaluation pass, so the screen can never show a stale "firing" badge — the
displayed state is always the engine's current truth, never a guess made in your
browser.

A rule is one of two kinds:

- a **threshold** rule — a value crosses a fixed line (for example, packet loss
  above 2%); or
- a **baseline** rule — a value deviates from its own learned normal, which
  catches "this is weird for *this* metric" without you hand-picking a number.

Each rule adds a debounce window (the condition must hold for N consecutive
evaluations before firing), a renotify cadence (how often a still-firing alert
repeats its notification), a severity, and delivery channels. The default
evaluation interval is 30 seconds.

Two operator actions on a firing alert, and they are deliberately different:

- **Silence** is the smoke alarm's hush button. The detector keeps detecting and
  the alert stays visibly firing — it just stops *notifying* (and stops feeding
  the incident timeline) until a deadline you set. When the underlying condition
  resolves, the silence clears and you still get the recovery notification.
- **Acknowledge** is signing the station logbook. It records *who owns* this
  alert and changes nothing about evaluation or delivery.

A new firing episode never inherits the previous episode's silence or
acknowledgement: when a series resolves, its operator state is wiped so the next
episode starts clean. And because a silence or acknowledgement is human input
that can't be re-derived from any data stream, **both survive a control-plane
restart** — losing them would re-page someone who had deliberately quieted an
alert. A restored silence is re-applied the first time that same alert fires
again, and an already-expired silence is skipped.

Delivery honesty, stated plainly: the **webhook** channel is the fully wired
path — an HTTPS POST whose body is signed so the receiver can verify it came
from your probectl. Incident-level paging, chat, and ticketing connectors
(for example PagerDuty, Opsgenie, Slack, Teams, ServiceNow, Jira) ride the
*incident* pipeline rather than individual alert rules.

When something does break, related signals across planes land in **one
incident**. If a synthetic probe to a service starts failing *and* that service
is a node in the host/kernel service map, those two facts attach to the same
incident as cross-plane evidence — the probe failure and the affected service
edge — instead of arriving as two unrelated alerts.

## Use it

Alert rules and active alerts are managed through the versioned REST API under
`/v1/alerts`, and incidents under `/v1/incidents`. Reading alert state needs the
`alert.read` permission; silencing or acknowledging needs `alert.write`. Both
operator actions are tenant-scoped (an unknown tenant fails closed and returns
nothing for another tenant) and written to the tamper-evident audit log.

List what is firing for your tenant, then hush one noisy series for two hours:

```sh
# What is firing right now (your tenant only).
curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
  https://probectl.example.com/v1/alerts/active

# Observe: each firing series carries an opaque "fingerprint" — its (rule,
# label-set) identity — plus its severity and operator state. The response also
# carries "evaluator_running": true|false, which distinguishes "quiet, nothing
# firing" from "the evaluator is not running here" — an empty list never lies
# about which it is.
```

```json
{
  "evaluator_running": true,
  "items": [
    {
      "fingerprint": "a1b2c3d4",
      "rule": "http-loss-edge",
      "severity": "warning",
      "labels": { "target": "https://shop.example.com/", "region": "us-east" },
      "state": "firing",
      "silenced_until": null,
      "acknowledged_by": null
    }
  ]
}
```

```sh
# Silence that series for 120 minutes (0 clears a silence; max is 7 days).
curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
  -X POST https://probectl.example.com/v1/alerts/active/silence \
  -d '{"fingerprint":"a1b2c3d4","duration_minutes":120}'

# Observe: the response is the engine's UPDATED view — the same series now shows
# a "silenced_until" timestamp and stays in the list, badged as silenced. It
# keeps evaluating; it just stops notifying until the deadline.
```

```sh
# List correlated incidents, then drill into one to see its cross-plane evidence.
curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
  https://probectl.example.com/v1/incidents
curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
  https://probectl.example.com/v1/incidents/<id>

# Observe: one incident object whose evidence list spans planes — e.g. a failing
# synthetic probe AND the affected service edge — plus related change/topology
# context, all scoped to your tenant.
```

In the web interface, the **Alerts** page shows the active-alert table (filter
by state and severity, with silence and acknowledge actions) over the rule table
(create, edit, delete with threshold and baseline forms). The active list
re-reads engine state every few seconds, and every action re-renders from the
engine's response. The **Incidents** view shows each correlated incident with
its cross-plane evidence and related change context.

## Pitfalls & limits

- **Silence is not acknowledge.** Silence stops the noise but the alarm light
  stays on; acknowledge claims ownership but the alarm keeps notifying. Reach for
  the right one — silencing to "claim" an alert means it goes quiet on the next
  person too.
- **A silence expires.** It is a snooze with a deadline (capped at 7 days), not a
  permanent dismissal. If the condition is still true when the silence lapses,
  notifications resume — by design.
- **`evaluator_running: false` is information, not a bug.** If a deployment has no
  in-process metric query backend wired, the evaluation loop is skipped and this
  flag tells you so honestly, rather than showing a falsely empty "all clear".
- **Email-channel honesty.** The webhook channel is the fully wired delivery
  path. If you configure an email channel where a mail sender is not wired, that
  rule's email notification is skipped with a logged warning rather than failing
  silently in a confusing way — prefer the webhook channel, or incident-level
  connectors, for paging.
- **Correlation needs more than one plane reporting.** A single-plane deployment
  still alerts perfectly, but "one incident with cross-plane evidence" only pays
  off once you have producers feeding more than one plane.

## Reference

| Capability | Surface | Permission |
|---|---|---|
| List firing alerts (with operator state) | `GET /v1/alerts/active` | `alert.read` |
| Silence a firing series | `POST /v1/alerts/active/silence` | `alert.write` |
| Acknowledge a firing series | `POST /v1/alerts/active/ack` | `alert.write` |
| Create / edit / delete rules | `/v1/alerts` | `alert.read` / `alert.write` |
| List correlated incidents | `GET /v1/incidents` | `incident.read` |
| One incident's cross-plane evidence | `GET /v1/incidents/<id>` | `incident.read` |

Properties you can rely on: the displayed firing state is always the engine's
current truth (never computed in the browser); silences and acknowledgements
persist across a restart and never leak from one firing episode into the next;
every silence and acknowledgement is tenant-scoped and audited; and one
underlying fault surfaces as one tenant-scoped incident with evidence drawn from
every plane that observed it.

## See also

Getting started (bringing up producers so the planes have data); the security
and threat page (how confidence-scored detections become incident signals); the
glossary for any term above.

**Covers:** F8, F9
