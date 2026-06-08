# MCP server (S25)

probectl ships a **Model Context Protocol** server so AI clients (e.g. Claude
Desktop) can query probectl directly. It exposes **read-only**, **tenant- and
RBAC-scoped** tools over two transports — **stdio** (local) and **HTTP** (network,
TLS + bearer-authenticated). It is a thin, dependency-free JSON-RPC 2.0 server.

## Security model — tenant first, then RBAC

```mermaid
%%{init: {'theme':'base','themeVariables':{'background':'#0d1117','primaryColor':'#161b22','primaryTextColor':'#e6edf3','primaryBorderColor':'#3b82f6','lineColor':'#8b949e','secondaryColor':'#21262d','tertiaryColor':'#0d1117','clusterBkg':'#161b22','clusterBorder':'#30363d','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'},'flowchart':{'curve':'basis','nodeSpacing':55,'rankSpacing':55,'padding':12}}}%%
flowchart LR
  C["MCP client"] -->|stdio or HTTPS| T["Transport<br/>(authenticate → principal)"]
  T --> S["MCP server<br/>tenant FIRST, then RBAC, then rate-limit"]
  S -->|"tools/list"| L["only the tools the<br/>caller may use"]
  S -->|"tools/call"| B["Backend (tenant-scoped)<br/>stores + S23 engine + S24 RCA"]
  B --> S
```

An MCP caller is **bound to a single tenant** (the token determines it). Every
call enforces the boundary at the MCP layer:

1. **Tenant first** — a tenantless principal is rejected; no tool takes a tenant
   argument, so a call cannot cross tenants.
2. **Then RBAC** — `tools/list` returns only the tools the caller's permissions
   allow, and `tools/call` re-checks the tool's permission (an out-of-scope caller
   gets `forbidden`, never data).
3. The backend then runs through the **tenant-scoped stores + the S23 query layer**
   (which enforces tenant→RBAC again — defense in depth), so a tool can never
   return another tenant's data.

Tool calls are **rate-limited per tenant**. The tools are **read-only** (no action
tools — CLAUDE.md §7 guardrail 8); write/remediation is deferred to S-EE5 as
proposal-only.

## Tools (initial catalog)

| Tool                  | Permission      | Description                                                        |
| --------------------- | --------------- | ----------------------------------------------------------------- |
| `list_tests`          | `test.read`     | List the tenant's synthetic tests/canaries.                       |
| `get_path`            | `test.read`     | Most recent discovered path to a target (hops, loss, latency).    |
| `get_bgp_events`      | `events.read`   | Recent BGP/routing events for a prefix or origin AS.              |
| `query_flows`         | `events.read`   | Network flow / service-map records (eBPF).                        |
| `get_incident`        | `incident.read` | One incident with its full cross-plane timeline.                  |
| `correlate_incident`  | `incident.read` | Which planes contributed to an incident + the timeline.          |
| `explain_degradation` | `ai.query`      | RCA on a natural-language question → a cited, RBAC-scoped cause.  |

Each tool advertises a documented JSON-Schema input. The catalog + schemas + auth
model are the stable contract other sprints append tools to (security/cost/SLO/
topology, then S-EE5's proposal-only `propose_remediation`). Tools whose backing
store is not wired in a deployment (e.g. flows/BGP without ClickHouse) return an
empty result with a note rather than failing.

## Transports & auth

**Tokens.** A control-plane bearer token (`mcp_tokens`) maps to a tenant + the
owning user's effective RBAC. Like sessions, only the token's **hash** is stored
(never the token), and the lookup is pre-tenant. Mint one with:

```
probectl-control mcp-token --user <user-uuid> [--tenant <id>] [--name laptop]
```

**stdio** (local — for Claude Desktop). The client spawns the binary; the token
comes from `PROBECTL_MCP_TOKEN`. Logs go to stderr so stdout stays a clean JSON-RPC
channel.

*Local-trust model (RED-007, verified):* the **binary entry authenticates the
token before serving anything** — `mcp-stdio` resolves `PROBECTL_MCP_TOKEN`
against the `mcp_tokens` store and refuses to start on a missing/invalid
token (pinned by `TestMCPAuthRequiredBeforeServing`). What stdio deliberately
trusts is the **local invoking process**: anyone able to spawn the binary
with the env var IS the principal that token names — process isolation on the
workstation is the boundary, exactly like any local CLI credential. Tenant
scoping + RBAC still apply to every call; the transport adds no extra
privilege.

```
PROBECTL_MCP_TOKEN=<token> PROBECTL_DATABASE_URL=... probectl-control mcp-stdio
```

Example Claude Desktop config:

```json
{
  "mcpServers": {
    "probectl": {
      "command": "probectl-control",
      "args": ["mcp-stdio"],
      "env": { "PROBECTL_MCP_TOKEN": "...", "PROBECTL_DATABASE_URL": "..." }
    }
  }
}
```

**HTTP** (network-exposed). Enabled by config; **TLS-only and bearer-authenticated**
— never exposed as plaintext when network-reachable (CLAUDE.md §7 guardrail 12).
POST a JSON-RPC request with `Authorization: Bearer <token>`. See
[`configuration.md`](configuration.md) for the `PROBECTL_MCP_*` keys.

## Methods

Standard MCP: `initialize`, `tools/list`, `tools/call`, `ping`, and the
`notifications/initialized` notification. Tool results carry both a text rendering
and `structuredContent`; a tool-level failure is an `isError` result (so the model
can read it), while protocol/auth failures are JSON-RPC errors.


## External-AI egress: consent, redaction, audit (Sprint 20 — AIRCA-001/002/003)

The MCP caller is an **external AI client**, so returning tool output is
tenant telemetry egressing the platform. Since Sprint 20 every `tools/call`
rides **the same egress gate** as the remote RCA model and the authoring
model (`internal/ai.EgressGate` — one instance, constructed once):

- **Consent (default deny):** the tenant must have opted in via
  `tenant_governance.ai_remote_egress` — the SAME per-tenant consent that
  gates remote-model RCA. Without it, `tools/call` returns an `isError`
  result explaining the consent requirement, the tool never runs, and the
  denial is audited. (`tools/list` and `initialize` still work — discovery
  is not egress.)
- **Redaction:** results are rendered to JSON once, masked by the C8 policy
  (secrets always; IPs/PII by default; hostnames + custom patterns per
  config), and the redacted form is what reaches the client — text and
  `structuredContent` both.
- **Audit (AIRCA-003):** every call lands in the tenant's tamper-evident
  audit stream as `mcp.tool_call` (actor, tool, allowed/denied + reason),
  plus an `ai.remote_egress` event (surface=`mcp`) on each allowed call.

The gate is a REQUIRED constructor argument of `mcp.New` — a gate-less MCP
server is not constructible, so no future transport can bypass it.
