# MCP server

## What it is

**MCP (Model Context Protocol)** is the open standard that lets AI applications
call external tools. A language model on its own can only produce text; MCP gives
it a disciplined way to _do_ things: an AI client connects to an MCP **server**,
asks what tools it offers, and invokes them with structured arguments. Think of
MCP as a USB-C port for AI — one standard plug, so any compliant client can talk
to any compliant server without bespoke integration code.

probectl ships an MCP server so AI clients — Claude Desktop, an agent framework,
your own tool-using app — can query probectl directly, in the client's own "call
a tool" idiom: _your_ AI asking _your_ self-hosted platform about _your_ network.
It exposes tools scoped by **tenant,
RBAC, and ABAC** over two transports (a **transport** is simply the channel the
messages travel over):

- **stdio** — local; the client spawns the probectl binary and talks over
  stdin/stdout (how Claude Desktop runs it).
- **HTTP** — network-reachable; TLS-only and bearer-authenticated.

HTTP browser clients also need an explicit trusted Origin in
`PROBECTL_MCP_ALLOWED_ORIGINS`, a comma-separated list of serialized HTTP(S)
origins such as `https://mcp-client.example`. The default refuses every present
Origin. Native clients may omit Origin and still authenticate normally. The
policy compares canonical scheme/host/port tuples; request Host and forwarded
headers never grant trust. Duplicate, opaque/null, wildcard, credential-bearing,
path/query/fragment and unlisted origins fail before credential or data reads.
Invalid configuration fails closed. Redacted diagnostics report only the
configured entry count. This guard does not change the advertised protocol
revision or enable another listener.

Under the hood it's a thin, dependency-free **JSON-RPC 2.0** server. The released
baseline speaks MCP revision `2024-11-05`; modern development work is described
in the native preview section below. JSON-RPC is the minimal remote-procedure-call convention
MCP builds on: each message is a small JSON document naming a `method` and its
`params`, and each reply carries the matching `id` — that is the entire wire
format. The initial catalog reads data and files human-gated proposals. The native flow
preview also manages authorized saved-query configuration and personal preferences.

## Security model: tenant first, then RBAC, then ABAC

```mermaid
%%{init: {'theme':'base','themeVariables':{'background':'#0d1117','primaryColor':'#161b22','primaryTextColor':'#e6edf3','primaryBorderColor':'#3b82f6','lineColor':'#8b949e','secondaryColor':'#21262d','tertiaryColor':'#0d1117','clusterBkg':'#161b22','clusterBorder':'#30363d','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'},'flowchart':{'curve':'basis','nodeSpacing':55,'rankSpacing':55,'padding':12}}}%%
flowchart LR
  C["MCP client"] -->|stdio or HTTPS| T["Transport<br/>(authenticate → principal)"]
  T --> S["MCP server<br/>tenant FIRST, then RBAC, then ABAC,<br/>then rate-limit, then egress gate"]
  S -->|"tools/list"| L["only the tools the<br/>caller may use"]
  S -->|"tools/call"| B["Backend (tenant-scoped)<br/>stores + query engine + RCA"]
  B --> S
```

Two words of vocabulary first. A **tenant** is one organization's hard-isolated
slice of a probectl deployment — its agents, telemetry, incidents, and users;
cross-tenant leakage is the platform's highest-severity failure. **RBAC**
(role-based access control) is the permission system _inside_ a tenant: which of
that tenant's users may read tests, read incidents, or run AI queries. **ABAC**
(attribute-based access control) is the final deny-override: a tenant policy may
narrow an RBAC grant using subject attributes such as department. The order in
the heading is the point — the tenant selects the building, RBAC decides which
rooms the badge normally opens, and ABAC may mark a room off-limits for that
particular badge holder.

An MCP caller is **bound to a single tenant** — the token it presents determines
which one. Every call enforces the boundary at the MCP layer
(`internal/ai/mcp/server.go`), in order:

1. **Tenant first.** A principal with no tenant is rejected. No tool takes a tenant
   argument, so a call _cannot express_ "another tenant's data" (the same
   by-construction property as the query layer — see `docs/ai-query.md`).
2. **Then RBAC.** `tools/list` returns only the tools the caller's permissions
   allow — an out-of-scope caller doesn't even _see_ a tool it can't use.
   `tools/call` re-checks the tool's permission (out of scope → `forbidden`, never
   data).
3. **Then ABAC.** The server loads policies within that same tenant and applies
   their deny overrides to both discovery and invocation. A denied tool is hidden
   from `tools/list` and refused by `tools/call`. If policies cannot be loaded and
   there is no previously loaded, known-good cache entry, authorization fails
   closed with a temporary-unavailable error rather than silently using RBAC alone.
4. **Then rate-limit and fairness-admit.** Tool calls are rate-limited per
   tenant (default `120`/minute, `PROBECTL_MCP_RATE_PER_MIN`), and query tools
   enter the shared per-tenant fairness gate before touching a store, so one
   tenant can't exhaust the server. A denial from either the rate limiter or the
   fairness gate is returned as the JSON-RPC error `-32003` (`rate limit
exceeded`), and over HTTP it also carries status `429` with a `Retry-After`
   header — distinct from a genuine tool failure (an `isError` tool result), so a
   client's backoff keys cleanly on the code / status.
5. **Then the egress gate.** Returning tool output to an external AI client _is_
   tenant data leaving the platform, so each `tools/call` passes the shared egress
   gate — per-tenant consent, redaction, audit (its own section below).
6. **Then the backend** runs through the **tenant-scoped stores + the semantic
   query engine**, which enforce tenant → RBAC _again_. That's defense in depth: a
   tool can't return another tenant's data even if a layer above had a bug.

The practical consequence: the AI never gains powers of its own. Whatever it may
see is exactly what the human who minted its token may see — the model _inherits_
one person's view of one tenant; there is no service-account superview to steal.
A confused or compromised model is bounded by the same walls as its owner.

## Tools (initial catalog)

A **tool**, in MCP terms, is one named operation the server advertises: a name, a
human-readable description the model reads to decide when to call it, a
machine-readable input schema, and — in probectl — the RBAC permission a caller
must hold. The catalog is deliberately small and legible: eight tools.

| Tool                  | Permission            | Description                                                             |
| --------------------- | --------------------- | ----------------------------------------------------------------------- |
| `list_tests`          | `test.read`           | List at most 200 tenant tests, with `limit` + `truncated` metadata.     |
| `get_path`            | `test.read`           | Most recently discovered path to a target (hops, per-hop loss/latency). |
| `get_bgp_events`      | `events.read`         | Recent BGP/routing events for a prefix.                                 |
| `query_flows`         | `events.read`         | Network flow / service-map records (eBPF).                              |
| `get_incident`        | `incident.read`       | One incident with its full cross-plane timeline.                        |
| `correlate_incident`  | `incident.read`       | Which planes contributed to an incident, plus the signal timeline.      |
| `explain_degradation` | `ai.query`            | RCA on a natural-language question → a cited, RBAC-scoped root cause.   |
| `propose_remediation` | `remediation.propose` | **Propose-only.** Files a `proposed` suggestion a human must approve.   |

Each tool advertises a documented JSON-Schema input (`internal/ai/mcp/tools.go`),
which is the stable contract — **JSON Schema** is the standard way to declare
"this tool takes a `target` string, that one a required `id`", so the model knows
exactly what shape to produce and the server can reject anything else. Tools
whose backing store isn't wired in a deployment (e.g. flows/BGP without
ClickHouse) return an empty result with a note rather than failing — so a client
gets a clean "nothing here" instead of an error.

Initial-catalog tool results use a 1 MiB ceiling after redaction, including
the MCP text and `structuredContent` representations together. Oversized
results fail closed instead of being materialized on the wire. `list_tests`
also uses the shared query-fairness gate and fetches only one 201-row sentinel
page so its 200-row truncation receipt is exact without loading the full tenant
catalog.

**About `propose_remediation`.** This tool only creates a guarded proposal. It only ever creates a `state=proposed`
suggestion — a reroute suggestion, a traffic-shift suggestion, a ticket, or a
trustctl renewal request — that a human must approve through the authenticated UI.
Think of it as a suggestion box bolted to the wall: the AI can drop a note in, but
the box has no wires running to the network. The MCP path can never approve or
execute; probectl never executes autonomously (see `docs/remediation.md`). So the
worst an injected prompt can do through this tool is _file a suggestion someone
then has to look at_. `TestProposeRemediationToolIsProposalOnly`
(`internal/ai/mcp/mcp_test.go`) pins that guarantee — including a structural check
that the remediation catalog contains **no** approve/execute/apply tool. Note: the
proposal backend is the commercially licensed guarded-remediation feature, attached
at the editions seam — it is live only on the **HTTP** transport of a licensed
server. On the lightweight **stdio** transport (and on an unlicensed deployment)
the tool is inert: calling it returns a clear "remediation is not enabled" error
result instead of acting. That inertness is wiring, not policy — the stdio process
is simply never handed a remediation backend to call, so there is nothing a clever
prompt could switch back on.

If an attached license dynamically ages past its grace period, the HTTP
`propose_remediation` tool returns an error result before its proposal delegate
runs. Existing proposal review remains available over REST; MCP exposes no
review or decision tool. This shares the same attach-seam write capability as
REST, so a long-running process cannot retain an MCP-only write path.

## Transports and auth

**Tokens.** A **bearer token** is a secret string that _is_ the authentication:
whoever presents ("bears") it on a request is treated as its owner, with no
further challenge. Treat one like a visitor badge that grants exactly one
employee's access — it opens the doors that person's badge opens, in that
person's building, and nothing else. In probectl, a control-plane bearer token
(table `mcp_tokens`) maps to a tenant plus the owning user's effective RBAC and
tenant-scoped ABAC subject attributes. As with sessions, only the token's
**hash** is stored (never the token itself), so a database leak yields no usable
badges. The lookup happens before the tenant is known, but only through an
exact-hash `SECURITY DEFINER` function; direct application-role table access
without a tenant GUC returns zero rows. The reserved `mfa` subject attribute is
always derived by the control plane after mutable
directory attributes are copied; an MCP bearer token carries no interactive MFA
proof, so a SCIM-supplied `mfa=true` cannot turn it into one. Mint one with:

```sh
probectl-control mcp-token --user <user-uuid> [--tenant <id>] [--name laptop]
```

The secret is printed once. The token acts _as that user_ — it carries exactly that
user's permissions, no more.

### stdio (local — e.g. Claude Desktop)

**stdio** (standard input/output) is the pair of text pipes every process is born
with. On this transport there is no network socket at all: the client spawns the
binary as a child process and the two exchange JSON-RPC through those pipes. The
token comes from `PROBECTL_MCP_TOKEN`. Logs go to **stderr** so stdout stays a
clean JSON-RPC channel.

The local-trust model is worth being explicit about. The **binary authenticates the
token before it serves anything**: `mcp-stdio` resolves `PROBECTL_MCP_TOKEN` against
the `mcp_tokens` store and refuses to start on a missing or invalid token
(`runMCPStdio` in `cmd/probectl-control/mcp.go`). It authenticates the same
credential again before every nonblank request frame, applying current token,
user, tenant-lifecycle, MFA and permission state. The stream remains bound to its
initial tenant and user; a changed identity or failed refresh refuses the request
without falling back to old grants. Client metadata cannot change that identity.
When the tenant lifecycle source has no known state and returns an error,
authentication fails closed with a retryable unavailable response. HTTP returns
503; stdio returns the negotiated protocol's unavailable error. The shared
lifecycle cache retains its normal last-known-state behavior. A bad credential
remains unauthorized, and a known suspension, offboarding or MFA policy refusal
remains forbidden. Dependency diagnostics are never returned to the client.
What stdio _deliberately_ trusts
is the **local invoking process**: anyone who can spawn the binary with that env var
**is** the principal the token names — workstation process isolation is the
boundary, exactly like any local CLI credential (think `kubectl`'s kubeconfig).
That trust is reasonable precisely because nothing listens: there is no port to
scan and no remote surface — an attacker would already need to run code as you, on
your machine, at which point they hold the badge anyway. Tenant scoping and RBAC
still apply to every call; the transport grants no extra privilege.

```sh
PROBECTL_MCP_TOKEN=<token> PROBECTL_DATABASE_URL=... probectl-control mcp-stdio
```

Worked end-to-end (every value real except the secrets):

```sh
# 1. mint a token for the user the AI client should act as (prints ONCE — copy it):
PROBECTL_DATABASE_URL='postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable' \
  ./bin/probectl-control mcp-token --user 7b1e6c9a-0000-4000-8000-000000000001 --name laptop-claude
# → prints the token secret once; only its hash is stored.
```

```json
// 2. Claude Desktop → Settings → Developer → Edit Config (claude_desktop_config.json):
{
  "mcpServers": {
    "probectl": {
      "command": "/usr/local/bin/probectl-control",
      "args": ["mcp-stdio"],
      "env": {
        "PROBECTL_MCP_TOKEN": "<the value mcp-token printed>",
        "PROBECTL_DATABASE_URL": "postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable"
      }
    }
  }
}
```

The same `command`/`args`/`env` triple works in any MCP client that launches a
local stdio server (Claude Code, IDE integrations, agent frameworks). Restart the
client; the eight probectl tools appear in its tool list. The token acts as that
user — what they can't see, the AI can't see.

### HTTP (network-reachable)

The HTTP transport puts the same server behind a URL, for clients that can't
spawn a local process. The moment a listener is reachable over the network,
anyone on the path could read or impersonate plaintext traffic — so this
transport is enabled by config and **TLS-only and bearer-authenticated** — never
plaintext when network-reachable (the platform's TLS-everywhere guardrail; **TLS**
is the encryption-and-identity layer under HTTPS). Set
`PROBECTL_MCP_HTTP_ADDR` together with `PROBECTL_MCP_TLS_CERT_FILE` and
`PROBECTL_MCP_TLS_KEY_FILE`; setting the address without the TLS files **fails
config validation** on purpose, so the endpoint can't come up anonymous — a
half-configured server refuses to start rather than start insecure. Then POST
a JSON-RPC request with `Authorization: Bearer <token>`. See
[`configuration.md`](configuration.md) for the `PROBECTL_MCP_*` keys.

Worked example — enable the bridge, then prove it answers:

```sh
# control plane env (alongside the usual keys):
PROBECTL_MCP_HTTP_ADDR=:9444
PROBECTL_MCP_TLS_CERT_FILE=./certs/tls.crt
PROBECTL_MCP_TLS_KEY_FILE=./certs/tls.key

# list the tools (token from `mcp-token`; --cacert trusts the quickstart CA):
curl -sS --cacert ./certs/ca.crt \
  -H "Authorization: Bearer <token>" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  https://localhost:9444/
```

A consent-gated call behaves honestly rather than silently: invoking
`explain_degradation` against a **remote** model before the tenant has consented
returns a tool **error** carrying the exact denial text from
[`ai-egress.md`](ai-egress.md) — nothing is sent, and the denial is the signal to
run that page's enablement chain.

## Methods

Standard MCP, nothing custom: `initialize` (the opening handshake, where client
and server agree on the protocol revision and capabilities), `tools/list`,
`tools/call`, `ping`, and the `notifications/initialized` notification — a
**notification** being a JSON-RPC message sent without an `id`, which expects,
and gets, no reply. A tool result carries both a text rendering and
`structuredContent` (the same data as a machine-readable object). The error split
matters to a model: a **tool-level** failure comes back as an `isError` result
(so the model can read the message and recover — say, retry with a valid
argument), while **protocol/auth** failures are JSON-RPC errors (the conversation
itself is malformed or unauthorized). A tenant-policy dependency failure is the
server-defined JSON-RPC error `-32004` with the stable message `authorization
policy is temporarily unavailable`; clients may retry, but the server does not
run or advertise protected tools until it has a safely loaded policy set.

## External-AI egress: consent, redaction, audit

**Egress** is data leaving the platform's boundary. An MCP caller is an
**external AI client** — typically the front end of a model probectl doesn't
operate — so returning tool output means tenant telemetry is leaving the
platform. Every `tools/call` therefore rides **the same egress gate** as the
remote RCA model and the authoring model (`internal/ai.EgressGate`, built by the
control plane's one gate constructor — the same consent source, redaction policy,
and audit sink on every surface; see `docs/ai-egress.md`). Picture a mailroom
every outgoing parcel must pass through: it first checks the sender has opted in
to shipping at all, then blacks out the sensitive lines, then logs the parcel —
three checks, every time:

- **Consent (default deny).** The tenant must have opted in via
  `tenant_governance.ai_remote_egress` — the _same_ per-tenant consent that gates
  remote-model RCA; silence means no. Without it, `tools/call` returns an
  `isError` result explaining the requirement, the tool never runs, and the
  denial is audited. (`tools/list` and `initialize` still work — _discovery_
  isn't egress.)
- **Redaction.** A result is rendered to JSON once, masked by the redaction policy
  (secrets always; IPs/PII by default; hostnames + custom patterns per config), and
  the **redacted** form is what reaches the client — both the text and the
  `structuredContent`. Masking runs on the JSON encoding with tenant-scoped,
  keyed-HMAC tokens — the same tenant + value gets the same mask — so the document
  stays valid and the model can still tell "this address here is that address
  there" without ever seeing it. A token from one tenant does not build a useful
  dictionary for another tenant.
- **Audit.** Every call — allowed or denied, and _why_ — lands in the tenant's
  tamper-evident audit stream as `mcp.tool_call` (actor, tool, outcome), plus an
  `ai.remote_egress` event (`surface = mcp`) on each allowed call that returns
  data. Both appends are fail-closed. The call audit must commit before the tool
  runs; the egress audit must commit before the bounded, redacted result is
  returned. A missing or failed audit sink yields JSON-RPC `-32004` with no tool
  result, so a database outage cannot silently turn an audited egress path into
  an unaudited one.

MCP dependency failures log a bounded `error_class` alongside the known tenant,
tool and phase. Raw backend, policy, authentication and audit error text is
excluded from those logs and from generic client failures because it can contain
credentials, SQL or private source details.

Crucially, the egress gate is a **required constructor argument** of `mcp.New` —
there is no gate-less constructor, and a nil gate denies every tool call (fail
closed). A gate-less MCP server simply can't exist, so no future transport can
bypass consent/redaction/audit. The mailroom is load-bearing: you can't build the
building without it.

## What it deliberately does not do

Three absences, each deliberate:

- **No tenant argument, anywhere.** Isolation is by construction, not by a
  parameter a caller could set.
- **No autonomous network action.** Saved-query writes change configuration or
  personal preferences. Remediation stays proposal-only and human-gated.
- **No anonymous network exposure.** The HTTP transport refuses to start without
  TLS, and every call is bearer-authenticated and consent-gated.

## Native flow preview

The colocated HTTP server binds native flow tools to its existing control-server
services. These use the same registry, tenant-scoped readers, source permissions,
private frozen snapshots and configuration stores as REST, CLI and the native UI.
The server advertises these tools only when that native binding exists. All
require an authenticated user plus both `ai.query` and `flow.read` for discovery
and invocation. A current ABAC denial of either permission also applies.

| Operations                          | Tools                                                                  | Additional permission                                                 |
| ----------------------------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Stateless natural-language proposal | `flow_explorer_plan`                                                   | No execution/history; same joined-field grants and model consent gate |
| Registry, query, comparison         | `flow_explorer_schema`, `flow_explorer_query`, `flow_explorer_compare` | Source-specific grants for selected joined fields                     |
| Complete CSV records                | `flow_explorer_csv`                                                    | Current original grants and creator identity                          |
| Frozen continuation                 | `flow_explorer_page`, `flow_explorer_comparison_page`                  | Current original grants and creator identity                          |
| Reusable filter reads               | `flow_filter_list`, `flow_filter_get`                                  | Current grants for referenced fields                                  |
| Reusable filter writes              | `flow_filter_save`, `flow_filter_delete`                               | `flow.filters.write`                                                  |
| Saved-query reads/execution         | `flow_view_list`, `flow_view_get`, `flow_view_run`                     | Private owner or explicit tenant sharing, with current source grants  |
| Saved-query writes                  | `flow_view_save`, `flow_view_delete`                                   | `flow.views.write` and ownership for updates/deletion                 |
| Personal preference                 | `flow_view_favorite`                                                   | Affects only the authenticated subject                                |

Save operations create without an ID/revision and update with the exact observed
revision. Revision tokens and measurement values are decimal strings. Shared
read access does not grant configuration writes. Native input schemas derive from
the committed API; unknown fields, duplicates, case aliases and trailing JSON are
refused. No input carries tenant, source permissions, SQL or resource-budget authority.
Saved-view results represent pinned tenant tag identities as ordered
`tag_ids` entries with `field` and `id`; a save request supplies those
identities as the API's `tag_ids` field-to-ID object. The server revalidates
every identity under the authenticated tenant before updating the view.

Results project selected registry dimensions and measurements into explicit
ordered entries. For example, a measurement is
`{"metric":"bytes:total","value":"9007199254740993","defined":true}`.
A missing source measurement has `defined:false`; an observed zero has the exact
value `"0"`. Original timestamps retain nanoseconds. Independent source totals,
Other, matrix axes and both comparison periods remain separate. Internal storage
clocks, tenant IDs, SQL previews and cache/filesystem paths are excluded.

Native requests admit the full API grammar within a 4 MiB authenticated HTTP
body and the shared 2 MiB plan/configuration grammar budget. Initial-catalog HTTP
requests retain their 1 MiB body limit. Native output has server-owned 32 MiB
source, 128 MiB combined wire and 4,194,304 structural-node ceilings; the final JSON-RPC
encoding preserves these budgets. Oversized work refuses atomically. Query
admission remains held through encoding and releases on errors/cancellation.
Consent, redaction and durable audits apply to every native invocation. No
response is published after the handler observes request cancellation.

Native failures include a fixed public code and guidance for query budgets,
source coverage, invalid grammar, missing/expired private results and stale
configuration revisions. Messages never echo dependency text or source values.
A transport-budget refusal asks for smaller pages or coarser buckets; it does
not publish a partial result. Legacy tool failure messages remain unchanged.

`flow_explorer_csv` accepts `snapshot_id`, `record_offset` (default0) and
`page_size` (default/max5000). It returns CSV `columns` and complete `records`;
follow `next_record` until absent to export every selected group, Other and totals.
Comparison exports include one record per group/metric. The server privately
prepares and validates the complete CSV on every call; records are projected
while its read lease holds and source validity is checked again afterward.
Pages also have a2MiB record encoding budget and can contain fewer than
`page_size` records; `next_record` always identifies the next complete record.
Cells are never split or encoded as opaque binary, so mandatory redaction still
inspects each value. Reconstruct CSV by writing the columns once, then each
page's records with a CSV writer. `source_bytes` and `source_sha256` identify
the complete original authenticated CSV, before MCP redaction; they are source
provenance, not checksums of the redacted MCP response. The API/CLI byte export
continues to supply an exact byte digest.

Native rendering costs are operator-configurable with
`PROBECTL_FLOW_MCP_SOURCE_BYTES` (32 MiB), `PROBECTL_FLOW_MCP_WIRE_BYTES`
(128 MiB complete RPC), `PROBECTL_FLOW_MCP_RESULT_NODES` (4 Mi nodes), and
`PROBECTL_FLOW_MCP_CSV_PAGE_BYTES` (2 MiB of encoded records per page).
All must be positive and sentinel-safe; zero never disables admission. REST
and MCP registry `render_cost` reports the effective values. HTTP and stdio
use the same immutable policy. Clients cannot override it. A refusal returns
no partial telemetry; complete response framing is checked before successful
egress audit. Legacy tools retain their existing smaller limits. These costs
do not change the query grammar, retention range or total paged/CSV row reach.

This preview has local declared-projection, tenant/owner, large-grammar and
full-page checks, plus paired actual TLS native50k-page and revocation proofs
with real PostgreSQL/FS and durable audits (reference telemetry fixtures).
The development transport implements modern `2026-07-28` metadata/discovery
and legacy `2025-11-25` initialization over TLS HTTP and stdio. Existing
`2024-11-05` behavior remains. Local TLS and pipe tests cover the wire boundaries;
external client interoperability, the current real-store replay and the combined
real-sender/SSO/store receipt remain in progress. Natural-language flow queries
use the stateless planning path; private conversation history is parked. These
development results are not a release support claim. The existing `query_flows`
tool continues its eBPF/events role.

Modern HTTP requires matching version/method/name headers and per-request
metadata. Closing its response cancels that request. Versioned stdio uses a
bounded worker pool and queue, refreshes the bound credential on every frame
and before queued execution, and accepts explicit cancellation without waiting
for stdout. Active IDs and progress tokens cannot collide; EOF cancels work.
Legacy stdio requires initialize/initialized before tool reads and cannot cancel
its initialize request. Modern requests remain independent when interleaved.

Legacy HTTP uses temporary per-request contexts, without issuing session IDs or
server-to-client requests. It accepts notifications with an empty202 response;
GET/DELETE return405. Legacy disconnect does not cancel work. Explicit
cancellation targets only the same authenticated tenant/user/credential and
request ID on the handling process; unknown requests on another replica are
ignored. No distributed cancellation or replay is promised. Native query limits
and tenant fairness still apply, together with the operator work deadline and
active-request budget documented in configuration.md. A disconnected stream
receives no further output.

Before legacy HTTP tool output and successful egress audit, the transport
rechecks the real credential and its tenant/user/MFA/grants/attributes. The tool
also compares a frozen authority snapshot of the tenant ABAC policies against
the current policy set, including policies for joined metadata. Changed or
unavailable authority refuses the complete result with a fixed audited reason.
Display names, policy row order and duplicate grants do not create false
permission changes. Protocol metadata never supplies identity or resource costs.

## Incumbent NMS import

The native import tools use the authenticated principal's tenant and the
selected routing context. They have no `tenant_id` input. Storage joins and
FORCE-RLS confine source rows, applied device provenance and agent assignments
before any result or write. `nms_import_rows` and `nms_import_dry_run` page
redacted review data; `nms_import_poll_proposals` and `nms_import_poll_target`
show inert polling proposals. `nms_import_alert_target` verifies one finite,
disabled LibreNMS port-down candidate against the current operator-owned
agent target. These reads require `nms.import.read`; target previews also
require `entities.read` in the context.

`nms_import_alert_apply` requires `nms.import.write`, `entities.read` and
`alert.write` in that same context. It accepts the exact plan, snapshot and
canonical target returned by preview. It uses the same reviewed, audited
tenant transaction as REST and creates only a disabled native rule with no
notification channels. A configured source must pass a fresh rules-endpoint
receipt check; without deployment-owned source policy and credentials, the
write fails closed. It cannot import source SQL, source delivery operations,
or enable an alert. A separate human-authorized alert operation is required
for activation.

`nms_import_export_start`, `nms_import_export_page` and
`nms_import_export_seal` require `nms.import.write` on the selected context.
They capture operator-supplied Orion SWIS or PRTG API v2 JSON as an inert,
labelled preview. The page tool accepts one bounded object or array and
returns only its redacted receipt hash; source-only credentials and
predicates are never returned. A seal verifies submitted pages, not the
completeness of an unseen live source. The same explicit review and dry-run
tools show every unmapped row before any destination write.

## See also

- `docs/ai-query.md` — the semantic query engine the tools read through.
- `docs/ai-rca.md` — the RCA that `explain_degradation` invokes.
- `docs/ai-egress.md` — the consent/redaction/audit gate every tool call rides.
- `docs/remediation.md` — the human-gated proposal workflow `propose_remediation` files into.
- `docs/configuration.md` — the `PROBECTL_MCP_*` keys.

## Tenant tag metadata

`tag_definition_list`, `tag_rule_list` and `tag_assignment_list` are read-only,
user-only tools requiring `tags.read`. Context reads require an owned routing
context and its current ABAC grant. Assignment results omit imported source
references and the encoded exporter target. No argument selects a tenant.

`tag_definition_write`, `tag_rule_write` and `tag_assignment_write` require
an authenticated user with `tags.write`. Each accepts `action` as `create`,
`update` or `delete`. Creates require `input`; updates require `id` and `input`;
deletes require `id` and `confirmed:true` and forbid `input`. Rule and assignment
operations also require `context_id` and its current resource ABAC grant. The
nested input has the same fields and validation as the corresponding REST API.
For example, creating a key uses
`{"action":"create","input":{"key":"customer"}}`; renaming it uses
`{"action":"update","id":"<tag UUID>","input":{"key":"contract"}}`.
Deleting a definition also removes its owned rules and assignments, including
reviewed imports. The manual assignment tool cannot change imported assignments
or set provenance. Writes recheck tenant lifecycle, MFA when required and current
authorization, and commit the metadata revision and domain audit together.

Metadata write arguments have a 384 KiB JSON byte budget, including the envelope
and JSON escapes. Tag values retain the API's 24,000-character limit; SNMP exact
matches retain its 1,024-byte field limit and significant whitespace. Duplicate,
unknown or noncanonical field names, mixed action fields and tenant/provenance
hints are refused. Results contain only declared metadata fields. These tools
are available only with the configured control service and metadata store; the
same consent, redaction and call-audit gates apply on HTTP and stdio.

CIDR rule sides include `src`, `dst`, `exporter`, `interface`, `device`, `agent`,
`test` and `prefix`. Internal rule evaluation considers every admitted
address; a prefix matches only a rule covering its entire range. Rule inputs
do not supply those underlying facts. Complete live subject and flow association
proof remains required before the full tagging capability leaves preview.

For an operator-managed canonical prefix, `entity_create` accepts optional
`network_prefix`. The user-only `entity_network_prefix_set` takes `id`,
`context_id` and required `network_prefix`, requiring `agent.write` plus current
context authorization. An explicit empty string clears the range; omission or
null is refused. It updates the same owned prefix ID, with an atomic audit
that omits the raw CIDR. Entity get/list return the normalized range under
`entities.read` and current context authorization. No caller tenant hint or
range on a non-prefix kind is accepted. The range is explicit operator metadata,
never inferred from a label or claimed as a live routing observation.

When NetBox is configured, `tag_netbox_preview` additionally requires
`cmdb.read`; it is hidden without either grant. Its inputs match the preview
API plus `context_id`: an immutable tag ID, registered exporter agent/source
pair, and `field` set to `role` or `site`. The backend resolves the unique owned
exporter before any external read and freshly attests both the IP CI and its
related device/VM under the deployment tenant mapping. Cached enrichment never
authorizes the preview. The result contains the checked CI/value/provenance and
an exact decimal tag revision, while omitting the packet address and encoded
exporter target. Source errors, ambiguous ownership or current permission
denials return no candidate. The operation writes no assignment.

`tag_netbox_apply` requires `tags.write` in addition to both read grants and
an authenticated user. Supply `confirmed:true`, the original registered
`exporter_agent_id` / `exporter_source_ref` and the unchanged preview result as
`preview`. It uses the control server's same reviewed apply service: current
context authorization, an uncached source comparison, target/revision recheck
under the tenant write lock, and atomic assignment/audit. A changed candidate
or revision refuses the write. The declared result contains the assignment ID,
tag/value, provenance and review time, omitting the exporter address and encoded
target. The tool is installed only with the configured audited control service;
the existing MCP consent/redaction and admission/terminal audits also apply.

This source preview remains labelled preview until its real NetBox receipt
passes. The shared MCP consent, response redaction and tenant audit gates apply
on HTTP and stdio.

Effective subject tags are available through `tag_subject_resolve` for a tenant
user with `tags.read`, the subject's read grant and current context policy. The
input names `context_id`, `target_kind` and either `target_id` or the exact
registered exporter pair. Fact and tenant hints are rejected. The response
contains curated effective tags, exact decimal-string revision and snapshot
time; it omits raw facts, source lineage and exporter identity. Existing egress
redaction and query budgets still apply. See [tenant tag semantics](flow.md#tenant-tags-and-routing-contexts).
