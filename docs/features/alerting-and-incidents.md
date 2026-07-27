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
- **Dashboards and the incident room** — instead of a flood of disconnected
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

The evaluator keeps a native, deterministic **state timeline** so the operator
can see why one series moved from normal to pending to firing and back to
resolved. Threshold receipts show the observed value and trip line; baseline
receipts show warmup progress and the learned lower/upper band. The ledger is
not a log platform: it stores only state transitions (plus bounded baseline
warmup steps), expires after seven days, caps each series at 64 rows and each
rule at 256, and returns at most 100 rows. PostgreSQL forced RLS plus an explicit
tenant predicate protect every write, prune, read, and rule deletion. Receipts
omit the ambient tenant ID and expose no SQL or physical query plan.

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
again, and an already-expired silence is skipped. Planned maintenance windows
are durable for the same reason: a restart must not unexpectedly page during an
approved change window.

Delivery honesty, stated plainly: the **webhook** channel is the fully wired
path — an HTTPS POST whose body is signed so the receiver can verify it came
from your probectl. Incident-level paging, chat, and ticketing connectors
(for example PagerDuty, Opsgenie, Slack, Teams, ServiceNow, Jira) ride the
*incident* pipeline rather than individual alert rules.

When something does break, related signals across planes land in **one
incident**. Its incident room is one workbench: the summary, one absolute clock,
five evidence groups, ranked changes, affected entities, a plane inspector, and
human-gated next actions stay together. If a synthetic probe to a service starts
failing *and* that service is a node in the host/kernel service map, those two
facts attach to the same incident as cross-plane evidence — the probe failure
and the affected service edge — instead of arriving as two unrelated alerts.

The **Find likely cause** action runs the tenant- and RBAC-scoped RCA inside the
same room. It needs no typed question and does not navigate to another page. Its
citations and the evidence tables share the same URL-safe selection contract:
selecting a clock marker, exact plane row, or citation selects that same source
row in the inspector. The URL carries only bounded investigation context; it
never carries a tenant identifier because the authenticated server session owns
tenant scope.

After a cited answer exists, **Copy cited share link** creates one fixed,
redacted evidence snapshot. The snapshot preserves the absolute time window,
filters, selected source row, exact citations, and the reasoning-provenance
receipt; its URL contains only a random `share_...` artifact ID. It is not a
public bearer link. Every replay requires an authenticated session with
`incident.read`, then reads through the caller tenant's forced Postgres RLS
scope. Missing, expired, revoked, and other-tenant IDs all return the same
not-found result, so the ID cannot be used to discover another tenant's data.
Creation also requires `ai.query`, runs a fresh authoritative RCA, strips
tenant fields and secrets, applies the configured privacy redaction before
persistence, and records `incident.share_create` in
the tamper-evident audit log; successful replay records
`incident.share_read`. A snapshot expires after seven days or sooner when the
tenant's `object_retention_days` policy is tighter. Live resolve/remediation
actions are disabled when viewing the fixed snapshot.

The live room also contains a native **investigation journal**. Think of it as
a tenant-owned lab notebook attached to one incident:

- a **human note** is bounded plain text for a hypothesis, observation, or
  conclusion;
- a **cited checkpoint** is the same inert text plus one exact evidence ID from
  a live redacted share artifact.

`GET /v1/incidents/<id>/journal` lists at most 200 live entries oldest-first.
`POST /v1/incidents/<id>/journal` appends one entry and needs
`incident.write`. The server first resolves the incident from the authenticated
tenant. For a checkpoint it then re-authorizes the share in that same forced-RLS
scope, verifies that the share belongs to this incident, and resolves the exact
evidence ID. Missing, expired, revoked, wrong-incident, and other-tenant
references all produce the same not-found result. The read path repeats that
authorization: if a formerly valid source later expires or is revoked, the
human note remains but the evidence details become explicitly `unavailable`.

Journal text has `format: plain_text`. It is never passed to a model, parsed as
markup, exposed as a tool call, executed as a runbook, or connected to the
remediation service. Appends record `incident.journal_append` in the immutable
tenant audit chain. Entries expire after 90 days by default or sooner when the
tenant's `object_retention_days` policy is tighter; expired entries are
unreadable and opportunistically pruned. Tenant erasure cascades the table, and
subject export/erasure includes matching note/author content.

The room is deliberately honest about coverage. All five plane groups remain
visible even when a producer returned no evidence, and an empty group says
**coverage gap**, never “zero” or “healthy.” An incident detail read returns at
most 500 signals. `signal_count` remains the total, while
`signals_truncated: true` and `signals_limit` explicitly say the evidence list
was bounded. Candidate changes use the separately tenant-authorized
`/v1/incidents/<id>/changes` read and report unavailable or empty data as another
coverage gap.

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
  -d '{"fingerprint":"a1b2c3d4","duration_minutes":120,"reason":"database rollout"}'

# Observe: the response is the engine's UPDATED view — the same series now shows
# a "silenced_until" timestamp and stays in the list, badged as silenced. It
# keeps evaluating; it just stops notifying until the deadline.

# Read the closed-loop receipt. Supplying incident_id asks the server to
# authorize that incident inside the same tenant before joining its persisted
# on-call/ticket receipts; a missing or other-tenant ID returns not found.
curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
  'https://probectl.example.com/v1/alerts/active/a1b2c3d4/workflow?incident_id=<id>'
```

```sh
# List correlated incidents, then drill into one to see its cross-plane evidence.
curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
  https://probectl.example.com/v1/incidents
curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
  https://probectl.example.com/v1/incidents/<id>

# Observe: one incident object whose bounded evidence list spans planes — e.g. a
# failing synthetic probe AND the affected service edge. Compare signal_count
# with signals_truncated/signals_limit before concluding that coverage is whole.

# Read candidate changes ranked by topology proximity and recency.
curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
  https://probectl.example.com/v1/incidents/<id>/changes

# Keep a human hypothesis in the local incident journal.
probectl incident journal-append <id> \
  --body '{"kind":"note","body":"Route policy change is the leading hypothesis."}'

# After creating a cited share, pin one exact evidence item as a checkpoint.
probectl incident journal-append <id> \
  --body '{"kind":"checkpoint","body":"Origin change preceded impact.","citation":{"share_id":"share_...","evidence_id":"E..."}}'

# Read the bounded oldest-first notebook, including citation availability.
probectl --json incident journal <id>
```

In the web interface, the **Alerts** page shows the active-alert table over
durable rules and maintenance windows. One detail workbench carries the operator
from the exact native evaluation timeline through acknowledge, bounded silence,
immutable actor/reason/start/expiry receipts, on-call or ticket delivery status,
and the linked incident/postmortem context. Missing persistence, stale history,
an empty ledger, and truncation are explicit states rather than a false “no
problem.” A state change does not close the workbench merely because the table
is filtered to `firing`; an expired silence visibly returns to firing. The
**Incidents** view then opens the unified five-plane room. A firing incident is
auto-selected, and one **Find likely cause** interaction renders cited RCA
inline.

## Pitfalls & limits

- **Silence is not acknowledge.** Silence stops the noise but the alarm light
  stays on; acknowledge claims ownership but the alarm keeps notifying. Reach for
  the right one — silencing to "claim" an alert means it goes quiet on the next
  person too.
- **A silence expires.** It is a snooze with a deadline (capped at 7 days), not a
  permanent dismissal. If the condition is still true when the silence lapses,
  notifications resume — by design.
- **`evaluator_running: false` is information, not a bug.** If a deployment has
  neither an in-process TSDB nor a Prometheus/VictoriaMetrics instant-query
  backend wired, the evaluation loop is skipped and this flag tells you so
  honestly, rather than showing a falsely empty "all clear".
- **Email-channel honesty.** The webhook channel is the fully wired delivery
  path. If you configure an email channel where a mail sender is not wired, that
  rule's email notification is skipped with a logged warning rather than failing
  silently in a confusing way. The canonical built-not-yet-served entry is in
  the [limitations table](../limitations.md#built-not-yet-served-edges); prefer
  the webhook channel, or incident-level connectors, for paging.
- **Correlation needs more than one plane reporting.** A single-plane deployment
  still alerts perfectly, but "one incident with cross-plane evidence" only pays
  off once you have producers feeding more than one plane. The room names each
  missing plane as a coverage gap so absence is never presented as health.
- **Incident evidence reads are bounded.** The detail endpoint returns at most
  500 signals. Check `signals_truncated` and `signal_count`; use a refined or
  exported investigation before drawing a conclusion from a truncated set.
- **A checkpoint is not permanent authority.** Its human text remains through
  journal retention, but source evidence is shown only while the cited share is
  live and still authorized. `citation.state: unavailable` is an explicit
  fail-closed state, not a healthy zero.
- **Journal text is inert.** It can describe a runbook, but it cannot execute
  one. Network changes still require the separate human-gated remediation
  proposal and approval path.

## Reference

| Capability | Surface | Permission |
|---|---|---|
| List firing alerts (with operator state) | `GET /v1/alerts/active` | `alert.read` |
| Read bounded threshold/baseline state transitions | `GET /v1/alerts/<rule-id>/evaluations` / `probectl alert evaluations <rule-id>` | `alert.read` |
| Read alert operation, incident, and delivery receipts | `GET /v1/alerts/active/<fingerprint>/workflow` | `alert.read` |
| Silence a firing series | `POST /v1/alerts/active/silence` | `alert.write` |
| Acknowledge a firing series | `POST /v1/alerts/active/ack` | `alert.write` |
| Manage planned maintenance windows | `/v1/alerts/maintenance*` | `alert.read` / `alert.write` |
| Create / edit / delete rules | `/v1/alerts` | `alert.read` / `alert.write` |
| List correlated incidents | `GET /v1/incidents` | `incident.read` |
| One incident's bounded cross-plane evidence | `GET /v1/incidents/<id>` | `incident.read` |
| Ranked candidate changes | `GET /v1/incidents/<id>/changes` | `incident.read` |
| List the bounded investigation journal | `GET /v1/incidents/<id>/journal` | `incident.read` |
| Append an inert note or cited checkpoint | `POST /v1/incidents/<id>/journal` | `incident.write` |
| Create a redacted cited snapshot | `POST /v1/incidents/<id>/shares` | `incident.read` + `ai.query` |
| Replay an authenticated snapshot | `GET /v1/incident-shares/<share-id>` | `incident.read` |

Properties you can rely on: the displayed firing state is always the engine's
current truth (never computed in the browser); its explanation timeline is
server-authored, tenant-scoped, and bounded; silences and acknowledgements
persist across a restart and never leak from one firing episode into the next;
maintenance windows are reusable, durable, tenant-scoped planned suppressors
with preview and audit on change; every silence and acknowledgement is
tenant-scoped, reasoned, and audited; and one underlying fault surfaces as one
tenant-scoped incident with evidence drawn from every plane that observed it.

## See also

Getting started (bringing up producers so the planes have data); the security
and threat page (how confidence-scored detections become incident signals); the
glossary for any term above.

**Covers:** F8, F9
