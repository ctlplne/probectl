# MCP server

## What it is

**MCP (Model Context Protocol)** is the open standard that lets AI applications
call external tools. A language model on its own can only produce text; MCP gives
it a disciplined way to *do* things: an AI client connects to an MCP **server**,
asks what tools it offers, and invokes them with structured arguments. Think of
MCP as a USB-C port for AI — one standard plug, so any compliant client can talk
to any compliant server without bespoke integration code.

probectl ships an MCP server so AI clients — Claude Desktop, an agent framework,
your own tool-using app — can query probectl directly, in the client's own "call
a tool" idiom: *your* AI asking *your* self-hosted platform about *your* network.
It exposes a small catalog of **read-and-propose**, **tenant- and RBAC-scoped**
tools over two transports (a **transport** is simply the channel the messages
travel over):

- **stdio** — local; the client spawns the probectl binary and talks over
  stdin/stdout (how Claude Desktop runs it).
- **HTTP** — network-reachable; TLS-only and bearer-authenticated.

Under the hood it's a thin, dependency-free **JSON-RPC 2.0** server speaking MCP
revision `2024-11-05`. JSON-RPC is the minimal remote-procedure-call convention
MCP builds on: each message is a small JSON document naming a `method` and its
`params`, and each reply carries the matching `id` — that is the entire wire
format. The tools are mostly read-only; the one write-ish tool is
**proposal-only** and can never act on its own (details below).

## Security model: tenant first, then RBAC

```mermaid
%%{init: {'theme':'base','themeVariables':{'background':'#0d1117','primaryColor':'#161b22','primaryTextColor':'#e6edf3','primaryBorderColor':'#3b82f6','lineColor':'#8b949e','secondaryColor':'#21262d','tertiaryColor':'#0d1117','clusterBkg':'#161b22','clusterBorder':'#30363d','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'},'flowchart':{'curve':'basis','nodeSpacing':55,'rankSpacing':55,'padding':12}}}%%
flowchart LR
  C["MCP client"] -->|stdio or HTTPS| T["Transport<br/>(authenticate → principal)"]
  T --> S["MCP server<br/>tenant FIRST, then RBAC, then rate-limit, then egress gate"]
  S -->|"tools/list"| L["only the tools the<br/>caller may use"]
  S -->|"tools/call"| B["Backend (tenant-scoped)<br/>stores + query engine + RCA"]
  B --> S
```

Two words of vocabulary first. A **tenant** is one organization's hard-isolated
slice of a probectl deployment — its agents, telemetry, incidents, and users;
cross-tenant leakage is the platform's highest-severity failure. **RBAC**
(role-based access control) is the permission system *inside* a tenant: which of
that tenant's users may read tests, read incidents, run AI queries. The order in
the heading is the point — as with building security, "may you enter this
building at all?" is settled before "which rooms does your badge open?", never
the other way around.

An MCP caller is **bound to a single tenant** — the token it presents determines
which one. Every call enforces the boundary at the MCP layer
(`internal/ai/mcp/server.go`), in order:

1. **Tenant first.** A principal with no tenant is rejected. No tool takes a tenant
   argument, so a call *cannot express* "another tenant's data" (the same
   by-construction property as the query layer — see `docs/ai-query.md`).
2. **Then RBAC.** `tools/list` returns only the tools the caller's permissions
   allow — an out-of-scope caller doesn't even *see* a tool it can't use.
   `tools/call` re-checks the tool's permission (out of scope → `forbidden`, never
   data).
3. **Then rate-limit.** Tool calls are rate-limited per tenant (default
   `120`/minute, `PROBECTL_MCP_RATE_PER_MIN`), so one tenant can't exhaust the
   server.
4. **Then the egress gate.** Returning tool output to an external AI client *is*
   tenant data leaving the platform, so each `tools/call` passes the shared egress
   gate — per-tenant consent, redaction, audit (its own section below).
5. **Then the backend** runs through the **tenant-scoped stores + the semantic
   query engine**, which enforce tenant → RBAC *again*. That's defense in depth: a
   tool can't return another tenant's data even if a layer above had a bug.

The practical consequence: the AI never gains powers of its own. Whatever it may
see is exactly what the human who minted its token may see — the model *inherits*
one person's view of one tenant; there is no service-account superview to steal.
A confused or compromised model is bounded by the same walls as its owner.

## Tools (initial catalog)

A **tool**, in MCP terms, is one named operation the server advertises: a name, a
human-readable description the model reads to decide when to call it, a
machine-readable input schema, and — in probectl — the RBAC permission a caller
must hold. The catalog is deliberately small and legible: eight tools.

| Tool                  | Permission             | Description                                                              |
| --------------------- | ---------------------- | ------------------------------------------------------------------------ |
| `list_tests`          | `test.read`            | List the tenant's synthetic tests/canaries.                              |
| `get_path`            | `test.read`            | Most recently discovered path to a target (hops, per-hop loss/latency).  |
| `get_bgp_events`      | `events.read`          | Recent BGP/routing events for a prefix or origin AS.                     |
| `query_flows`         | `events.read`          | Network flow / service-map records (eBPF).                               |
| `get_incident`        | `incident.read`        | One incident with its full cross-plane timeline.                         |
| `correlate_incident`  | `incident.read`        | Which planes contributed to an incident, plus the signal timeline.       |
| `explain_degradation` | `ai.query`             | RCA on a natural-language question → a cited, RBAC-scoped root cause.     |
| `propose_remediation` | `remediation.propose`  | **Propose-only.** Files a `proposed` suggestion a human must approve.     |

Each tool advertises a documented JSON-Schema input (`internal/ai/mcp/tools.go`),
which is the stable contract — **JSON Schema** is the standard way to declare
"this tool takes a `target` string, that one a required `id`", so the model knows
exactly what shape to produce and the server can reject anything else. Tools
whose backing store isn't wired in a deployment (e.g. flows/BGP without
ClickHouse) return an empty result with a note rather than failing — so a client
gets a clean "nothing here" instead of an error.

**About `propose_remediation`.** This is the one tool that writes anything, and it
is built so it *cannot* be dangerous. It only ever creates a `state=proposed`
suggestion — a reroute suggestion, a traffic-shift suggestion, a ticket, or a
trustctl renewal request — that a human must approve through the authenticated UI.
Think of it as a suggestion box bolted to the wall: the AI can drop a note in, but
the box has no wires running to the network. The MCP path can never approve or
execute; probectl never executes autonomously (see `docs/remediation.md`). So the
worst an injected prompt can do through this tool is *file a suggestion someone
then has to look at*. `TestProposeRemediationToolIsProposalOnly`
(`internal/ai/mcp/mcp_test.go`) pins that guarantee — including a structural check
that the catalog contains **no** approve/execute/apply tool at all. Note: the
proposal backend is the commercially licensed guarded-remediation feature, attached
at the editions seam — it is live only on the **HTTP** transport of a licensed
server. On the lightweight **stdio** transport (and on an unlicensed deployment)
the tool is inert: calling it returns a clear "remediation is not enabled" error
result instead of acting. That inertness is wiring, not policy — the stdio process
is simply never handed a remediation backend to call, so there is nothing a clever
prompt could switch back on.

## Transports and auth

**Tokens.** A **bearer token** is a secret string that *is* the authentication:
whoever presents ("bears") it on a request is treated as its owner, with no
further challenge. Treat one like a visitor badge that grants exactly one
employee's access — it opens the doors that person's badge opens, in that
person's building, and nothing else. In probectl, a control-plane bearer token
(table `mcp_tokens`) maps to a tenant plus the owning user's effective RBAC. As
with sessions, only the token's **hash** is stored (never the token itself), so a
database leak yields no usable badges — and the lookup happens before tenant
scoping is applied. Mint one with:

```sh
probectl-control mcp-token --user <user-uuid> [--tenant <id>] [--name laptop]
```

The secret is printed once. The token acts *as that user* — it carries exactly that
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
(`runMCPStdio` in `cmd/probectl-control/mcp.go`). What stdio *deliberately* trusts
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
itself is malformed or unauthorized).

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
  `tenant_governance.ai_remote_egress` — the *same* per-tenant consent that gates
  remote-model RCA; silence means no. Without it, `tools/call` returns an
  `isError` result explaining the requirement, the tool never runs, and the
  denial is audited. (`tools/list` and `initialize` still work — *discovery*
  isn't egress.)
- **Redaction.** A result is rendered to JSON once, masked by the redaction policy
  (secrets always; IPs/PII by default; hostnames + custom patterns per config), and
  the **redacted** form is what reaches the client — both the text and the
  `structuredContent`. Masking runs on the JSON encoding with tenant-scoped,
  keyed-HMAC tokens — the same tenant + value gets the same mask — so the document
  stays valid and the model can still tell "this address here is that address
  there" without ever seeing it. A token from one tenant does not build a useful
  dictionary for another tenant.
- **Audit.** Every call — allowed or denied, and *why* — lands in the tenant's
  tamper-evident audit stream as `mcp.tool_call` (actor, tool, outcome), plus an
  `ai.remote_egress` event (`surface = mcp`) on each allowed call that returns
  data.

Crucially, the egress gate is a **required constructor argument** of `mcp.New` —
there is no gate-less constructor, and a nil gate denies every tool call (fail
closed). A gate-less MCP server simply can't exist, so no future transport can
bypass consent/redaction/audit. The mailroom is load-bearing: you can't build the
building without it.

## What it deliberately does not do

Three absences, each deliberate:

- **No tenant argument, anywhere.** Isolation is by construction, not by a
  parameter a caller could set.
- **No autonomous action.** The only write tool is proposal-only and human-gated;
  the server never executes a remediation.
- **No anonymous network exposure.** The HTTP transport refuses to start without
  TLS, and every call is bearer-authenticated and consent-gated.

## See also

- `docs/ai-query.md` — the semantic query engine the tools read through.
- `docs/ai-rca.md` — the RCA that `explain_degradation` invokes.
- `docs/ai-egress.md` — the consent/redaction/audit gate every tool call rides.
- `docs/remediation.md` — the human-gated proposal workflow `propose_remediation` files into.
- `docs/configuration.md` — the `PROBECTL_MCP_*` keys.
