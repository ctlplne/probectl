# Alerting

**What this is.** The part of probectl that watches metrics and tells a human when
something is wrong. It has two halves that together form one truth:

- **Alert rules** — durable config in Postgres. A rule is a **threshold**
  condition (value crosses a fixed line) or a **baseline** condition (value
  deviates from its own learned normal) over any metric in the TSDB (the
  time-series database), with **debounce** (`for_n` — the condition must hold
  for N consecutive evaluations before firing, so one noisy sample can't page
  anyone), a **renotify cadence** (how often a still-firing alert may repeat its
  notification), a severity, and delivery channels (HMAC-signed webhook — a
  webhook is an HTTP POST to a URL you choose; the HMAC is a signature computed
  over the body with a shared secret so the receiver can verify the sender — or
  email). Full CRUD at `/v1/alerts` (RBAC `alert.read` / `alert.write`).
- **Active alerts** — the engine's live truth: what is firing *right now*. The
  evaluator engine (`internal/alert`) is the single source of truth. The API and
  the web UI only *render* its state and *forward* operator actions; nothing about
  what is firing is computed client-side.
- **Maintenance windows** — reusable planned hush rules for known work. Think
  "we are patching the database every Thursday at 02:00, so matching alerts stay
  visible but do not page during that window." They are tenant-scoped, can match
  rule IDs and/or resource labels, support daily/weekly recurrence, have a
  preview API, and create audit events when changed.

Two honesty notes on delivery. The **webhook** channel is the fully-wired path
(HTTPS POST, body signed with HMAC-SHA256 in `X-Probectl-Signature`). The
**email** channel type exists end to end (a plain-text message via an SMTP
sender), but the shipped control plane does not yet wire a mail sender or
expose SMTP configuration — a rule with an email channel is skipped with a
logged warning until one is wired. And per-rule channels are only half the
notification story: incident-level paging, chat, and ticketing connectors
(PagerDuty, Opsgenie, Slack, Teams, ServiceNow, Jira) ride the *incident*
pipeline, not alert rules — see [`docs/oncall-itsm.md`](oncall-itsm.md).

Why split it this way? Rules are operator intent and must survive restarts, so
they live in the database. "What is firing" is a live computation over the latest
samples — deriving it from the engine on every read means the UI can never drift
from reality or show a stale "firing" badge.

```mermaid
%%{init: {'theme':'base','themeVariables':{'background':'#0d1117','primaryColor':'#161b22','primaryTextColor':'#e6edf3','primaryBorderColor':'#3b82f6','lineColor':'#8b949e','secondaryColor':'#21262d','tertiaryColor':'#0d1117','clusterBkg':'#161b22','clusterBorder':'#30363d','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'},'flowchart':{'curve':'basis','nodeSpacing':55,'rankSpacing':55,'padding':12}}}%%
flowchart LR
  R[(alert rules\nPostgres)] --> E[evaluator engine\nper tenant]
  T[(TSDB)] --> E
  O[(alert_ops\nsilences/acks · RLS)] -. restore on boot .-> E
  M[(maintenance windows\nplanned work)] --> E
  E -- notify --> C[channels: webhook/email]
  E -- sink --> I[incident correlator]
  E -- "Active / Silence / Ack / Maintenance" --> A["/v1/alerts/active* · /v1/alerts/maintenance*"]
  A --> W[web: Alerts page]
```

The evaluator ticks every `PROBECTL_ALERT_EVAL_INTERVAL` (default `30s`),
re-reading the tenant's enabled rules through the row-level-security choke
point (RLS — the database itself filters every query to one tenant's rows) on
each pass. Two scope limits worth knowing, both surfaced honestly as
`evaluator_running: false` rather than hidden: the default deployment wires the
evaluator for the default tenant (per-tenant fan-out across many tenants is a
noted follow-up), and the evaluator needs an in-process TSDB to query — in
`PROBECTL_TSDB_MODE=prometheus` (remote-write-out) mode there is no in-process
query backend, so the loop is skipped.

## Active-alert API

| Route | Perm | Meaning |
| --- | --- | --- |
| `GET /v1/alerts/active` | `alert.read` | Every firing series for the caller's tenant, with operator state. `evaluator_running=false` distinguishes "quiet" from "not evaluating". |
| `POST /v1/alerts/active/silence` | `alert.write` | `{fingerprint, duration_minutes}` — suppress notifications until the deadline (`0` clears; max 7 days). |
| `POST /v1/alerts/active/ack` | `alert.write` | `{fingerprint}` — record the caller as owning the alert. |
| `GET /v1/alerts/maintenance` | `alert.read` | Reusable planned windows for the caller's tenant evaluator. |
| `POST /v1/alerts/maintenance` | `alert.write` | Create/update a window: `{name, starts_at, ends_at, recurrence, match, rule_ids}`. |
| `POST /v1/alerts/maintenance/preview` | `alert.read` | Preview matching saved or draft windows over a bounded range (`<=90d`). |
| `DELETE /v1/alerts/maintenance/{id}` | `alert.write` | Remove a reusable planned window. |

Each firing series carries an opaque `fingerprint` — the `(rule, label-set)`
identity, which is the handle for actions. Both actions are:

- **tenant-scoped** — the caller's tenant selects its own evaluator engine; an
  unknown tenant fails closed (503 / not-found, never another tenant's engine);
- **audited** — `alert.silence` / `alert.acknowledge` go to the tamper-evident
  log; and
- they return the engine's *updated* view, so the UI re-renders from engine truth.

## Semantics (the operator contract)

Silence and acknowledge are the two things an operator can do to a firing
alert, and they are deliberately different: **silence is the smoke alarm's hush
button** — the detector keeps detecting and the light stays on, it just stops
sounding for a while; **acknowledge is signing the station logbook** — it says
"this one is mine" and changes nothing about the alarm itself.

- **Silence** suppresses channel notifications *and* the incident sink for one
  series until the deadline. Mechanically, a silenced series short-circuits the
  notify path in the engine (`transition()` returns "no alert"), so neither the
  webhook/email channels nor the incident correlator fire. The series keeps
  evaluating and stays visibly firing (badged as silenced). When it resolves, the
  silence clears and the recovery notification is still sent.
- **Acknowledge** is bookkeeping: who has seen / owns it. Evaluation and delivery
  are unchanged; the ack clears on resolve.
- **Maintenance window** is a calendar hush rule: it suppresses matching firing
  notifications while the window is active, but the alert still shows in the
  active list with `silenced_until` set to the occurrence end. When the window
  expires, a still-breaching series can notify immediately because the original
  firing notification was deliberately suppressed.
- A new firing episode never inherits the previous episode's silence/ack — when a
  series resolves, the engine wipes its operator state so the next episode starts
  clean.

### Silences and acks survive a restart

Firing state itself is engine-derived: it re-computes on the first evaluation
after a control-plane restart, so it is never persisted. But a **silence or ack is
operator input** that cannot be re-derived from any stream — losing it on restart
would re-page someone who had deliberately quieted an alert. So silences and acks
*are* persisted, in the `alert_ops` table (migration `0043`, tenant-RLS), as the
one sanctioned exception to "alerting state is volatile" (see
`docs/adr/volatile-stores.md`).

The mechanics are restart-safe without leaking across episodes:

- On boot, the API layer loads each tenant's persisted ops and seeds the engine
  (`Engine.RestoreOps`). A restored silence/ack is **re-applied the first time its
  fingerprint fires again** (an expired silence is skipped) — so it never
  resurrects an episode that had already ended.
- When an episode resolves, a resolve hook (`Engine.SetResolveHook`) deletes the
  persisted row, so a *future* episode of the same series starts with no inherited
  state.

## The web surface

`/alerts` on the app shell: the active-alert table (state + severity filters,
detail with silence/acknowledge actions) sits over the rule table (create / edit /
delete with threshold/baseline forms). It is built entirely from the shared
design-system components and tokens (the WCAG 2.2 AA gate covers it). The active
list polls the engine every 15s, and every action re-renders from the engine's
response — the UI shows engine truth, not a client-side guess.

## Testing

`go test ./internal/alert ./internal/control` covers the engine state machine
(episode start, silence suppression including renotify windows + expiry, resolve
clearing operator state, fail-closed errors), restart restore-and-cleanup of
silences/acks, planned-window suppression/expiry/recurrence/tenant isolation, and
the handlers (RBAC perms, tenant fail-closed, preview, 404/422/503 paths). The
integration-tagged control test proves maintenance-window audit events land in
the tenant audit trail. `cd web && npx vitest run` covers the surface: list + filters, silence/ack
rendering engine truth, rule create, tenant scoping (no client-side tenant
selection), evaluator-off honesty, and the axe a11y pass.
