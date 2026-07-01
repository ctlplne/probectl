# The AI assistant — grounded RCA, query, MCP, and authoring

## What it is

probectl's AI assistant is four capabilities that share one rule: the model never
gets to decide what you are allowed to see. It enforces the tenant boundary first,
then your role, *before* any model is involved, and it cites the evidence behind
every claim so you can check it. The four capabilities:

- **Root-cause analysis (RCA)** — you ask a plain-English question ("why is
  checkout slow for the EU region?") and get back a probable cause, a confidence
  level, and findings where every statement links to a real underlying signal you
  are allowed to see. RCA is working out *why* something broke.
- **Natural-language query** — the single shared read layer underneath everything.
  It turns "events about this host in the last hour" into a scoped, structured
  read, and it is the one place where tenant and role are enforced.
- **The MCP server** — an interface that lets an outside AI client (Claude Desktop,
  an agent framework, your own tool-using app) call probectl as a small catalog of
  tenant- and role-scoped tools. MCP is the Model Context Protocol, the open
  standard for letting an AI client call external tools.
- **AI authoring and discovery** — you describe a check in plain English, or
  probectl mines what it already observed, and it *proposes* a ready-to-go test
  configuration that you approve. It never creates a test on its own.

See [glossary](../glossary.md) for RCA, MCP, RBAC (Role-Based Access Control), and
tenant. The stance running through all four: the model is the *least* trusted
component — useful for fluent prose, never relied on for truth or for isolation.

## Why it exists

Cross-plane root cause is slow by hand. The symptoms of one problem scatter across
metrics, routing events, flow data, change records, and topology, and stitching
them together under pressure is exactly the work people are worst at during an
incident. The assistant does that gathering and ranking for you — but the reason
it is *safe* to let an AI near your network data is the architecture, not the
model. Two questions decide whether such a feature can be trusted: what stops it
from reading another tenant's data, and what stops it from inventing an answer?
probectl answers both structurally, so swapping or upgrading the model cannot
weaken either guarantee.

It also exists to make the AI sovereign instead of SaaS-bound. The default RCA
engine is not a large language model (LLM) at all — it is ordinary probectl code
that runs inside the control plane, makes no network call, and works on a machine
with no internet path. If you want fuller prose, local Ollama or vLLM keeps that
assistant path inside your network; a remote model is explicit opt-in and must
pass consent, redaction, and audit before tenant evidence can leave
infrastructure you control.

## How it works

**The query layer has no tenant field — this is the load-bearing decision.** Every
read across the platform goes through one engine, and the request type it takes
simply has no field in which to name a tenant. The engine takes the tenant from the
authenticated caller instead. So a request — including one a model helped build, or
one assembled from attacker-controlled text — cannot even *express* "give me another
tenant's data." It is not blocked at runtime; it is impossible to say. This is the
difference between checking a tenant parameter (which can be forgotten, spoofed, or
fuzzed) and there being no tenant parameter to get wrong. Inside the chosen tenant, a
second gate checks the per-domain read permission for your role. For tenant-scoped
durable data the database itself filters every row by tenant through Row-Level
Security, so even a buggy query cannot see foreign rows — two independent fences
enforcing the same rule.

**RCA is a four-step pipeline, and each step buys one guarantee:**

1. **Plan (deterministic).** probectl code — never a model — reads your question,
   extracts the subject (a host, IP, address range, hostname, or URL), picks a time
   window, and selects which planes to gather from based on keywords. Untrusted
   question text cannot widen the query scope, because the thing that decides scope
   is a fixed switchboard, not an operator who can be sweet-talked into dialing
   anywhere.
2. **Gather (tenant first, then role).** Each planned query runs through the query
   layer above. Planes you cannot read are skipped, so an answer is grounded only in
   what you are permitted to see. Each returned row becomes a piece of evidence with a
   stable, per-request-randomized identifier — and those identifiers are the only
   things any later claim is allowed to cite.
3. **Synthesize (a model with no tools).** The question plus the gathered evidence go
   to the model, whose only job is to write prose over evidence it was handed. It is
   never given tools and cannot issue its own queries or take actions — a writer
   locked in a room with a stack of photocopies. So even hostile evidence content (a
   prompt-injection payload riding in a log line) cannot drive behavior; the worst it
   can do is produce a claim the next step throws away.
4. **Citation integrity (the trust backstop).** The pipeline drops any finding whose
   citations do not resolve to real gathered evidence — a fact-checking editor who
   walks every footnote back to its source before publication. The root-cause
   headline itself must also be grounded; an uncited one is rejected and confidence
   drops. If nothing grounded survives, the answer is an honest "insufficient
   evidence" rather than a guess. Because the evidence identifiers are randomized per
   request, injected text cannot pre-write a citation to an identifier that will
   exist later.

**The MCP server applies the same order in five steps:** tenant first (a caller with
no tenant is rejected, and no tool takes a tenant argument), then role (the tool list
shows only tools your permissions allow; calling an out-of-scope tool returns a
forbidden error, never data), then a per-tenant rate limit, then an egress gate
(below), then the tenant-scoped backend that re-enforces tenant and role again. The
practical consequence: the AI never gains powers of its own. Whatever it may see is
exactly what the person who minted its token may see — it inherits one person's view
of one tenant; there is no service-account superview to steal.

**Returning data to an outside AI client is data leaving the platform, so it is
gated.** Every MCP tool call — and every remote-model RCA or authoring call — passes
one mailroom: consent (the tenant must have opted in to remote AI egress; silence
means no), then redaction (secrets always masked, addresses and personal data masked
by default, using stable per-tenant tokens so the model can still tell "this address
is that address" without ever seeing the real value), then audit (every call,
allowed or denied and why, lands in the tenant's tamper-evident audit log). The gate
is a required ingredient of the server — a gate-less server cannot be built — so no
future transport can bypass consent, redaction, or audit.

**Authoring and discovery are propose-only.** You type a request ("monitor the
Salesforce login page") or let discovery mine the telemetry probectl already observed
for things worth monitoring that have no test yet. Either way you get a *proposal* — a
complete, schema-validated configuration pending *your* confirmation. probectl never
creates a test on its own: it fills in the whole form and hands you the pen, but never
signs. An invalid configuration — including a malformed answer from a model — is
rejected before you ever see it, so you cannot accidentally approve garbage because
garbage never reaches the review step. The default authoring engine is a deterministic
rule-based parser that needs no model and makes no network call; a model handles
open-ended requests only when you connect one, and its output is treated as untrusted
input, validated exactly like everything else.

probectl never phones home: the default RCA and authoring engines are fully local,
and any remote model is opt-in and gated. The model cannot touch the network or take
actions — there is no agentic loop. Remediation is a separate, human-gated,
proposal-only path; the assistant only ever files a suggestion a person must approve.

## Use it

The shipped posture is air-gapped — with no AI keys set at all, the assistant runs
the deterministic local engine. To run a fully local model instead, point it at a
loopback endpoint (no egress acknowledgment or per-tenant consent is needed, because
nothing leaves the host):

```sh
ollama pull llama3.1
PROBECTL_AI_MODEL_PROVIDER=ollama \
PROBECTL_AI_MODEL_ENDPOINT=http://127.0.0.1:11434 \
PROBECTL_AI_MODEL_NAME=llama3.1 \
  ./bin/probectl-control
# Observe: the Ask (AI) page now answers with this local model; data stays on-box.
```

Ask a grounded question over the API (the answer is scoped to your tenant and your
role; the question cannot name another tenant):

```json
// POST /v1/ai/ask  (requires the ai.query permission)
{ "question": "why is checkout slow for the EU region?", "subject": "checkout.eu.acme.example" }
// Observe: a cited Answer — a root cause, a confidence badge, and findings whose
// citation chips each resolve to a real signal you are allowed to see. The same
// question asked by another tenant returns "insufficient evidence", never your data.
```

Connect an outside AI client (such as Claude Desktop) to the local MCP server. Mint a
token that acts as one user, then register the server — the eight probectl tools
appear in the client and inherit exactly that user's view:

```json
{
  "mcpServers": {
    "probectl": {
      "command": "/usr/local/bin/probectl-control",
      "args": ["mcp-stdio"],
      "env": {
        "PROBECTL_MCP_TOKEN": "<the value mcp-token printed once>",
        "PROBECTL_DATABASE_URL": "postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable"
      }
    }
  }
}
// Observe: tools/list shows only tools this user may use; a remote-model tool call
// before the tenant has consented returns a clear denial, and nothing is sent.
```

## Pitfalls & limits

- **A remote model means tenant data leaves the platform.** It is off by default and
  requires two things: an egress acknowledgment on the control plane and per-tenant
  consent. Until both are set, a remote-model RCA, authoring, or MCP call is denied
  with a clear message, and the denial is audited. A plaintext (non-HTTPS, non-loopback)
  model endpoint is refused at startup, so a misconfiguration never serves even one
  answer.
- **The default engine trades prose fluency for determinism.** The built-in engine
  ranks the evidence it was handed and names the most likely cause; it cannot
  hallucinate because it only ever points at rows it was given, but its wording is
  plainer than an LLM's. That is the deliberate sovereign default.
- **An honest "insufficient evidence" is a feature, not a bug.** If no grounded
  finding survives citation integrity, the assistant says so rather than guessing.
  Small deployments degrade the same way: a store that is not attached simply
  contributes no evidence for that plane.
- **The assistant never acts.** No tools given to the model, no autonomous loop, no
  network changes. The one write-capable MCP tool is proposal-only and human-gated;
  it can file a suggestion but has no wires to the network. Authoring and discovery
  likewise stop at a proposal — the worst outcome of a confused model or a prompt
  injection is a suggestion you decline.
- **Discovery proposes hosts, not address ranges.** A whole prefix is monitored by
  watching routing, not by pinging it, so a bare range is deliberately never proposed
  as a synthetic test.
- **Answers are bounded and fair.** Queries are capped in rows and time, RCA caps how
  much evidence it gathers, and a per-tenant budget stops one tenant's heavy questions
  from starving another's. A clipped answer is labeled as clipped.

## Reference

- RCA API: `POST /v1/ai/ask` (body `{question, subject?}`) and
  `POST /v1/ai/feedback` (body `{answer_id, rating, comment?}`), both requiring the
  `ai.query` permission. Evidence is then further scoped per plane by your read
  permissions, so two users with different roles correctly get differently-grounded
  answers. Both actions are written tenant-scoped to the tamper-evident audit log.
- Authoring API: `POST /v1/ai/author` (body `{prompt}`) returns a proposal; you apply
  it with `POST /v1/tests`. Discovery: `POST /v1/ai/discover`. Both require the
  `test.write` permission, checked after the tenant boundary, and are audited.
- MCP transports: local stdio (the client spawns the binary; token from
  `PROBECTL_MCP_TOKEN`) and network HTTP (TLS-only and bearer-authenticated —
  setting the address without TLS files fails configuration validation). Mint a token
  with `probectl-control mcp-token --user <user-uuid>`; the secret prints once and
  only its hash is stored. The initial tool catalog is eight read-and-propose tools,
  each gated by a role permission.
- Model providers: a deterministic built-in engine (the default; air-gapped), a local
  server reached over loopback, or a cloud provider — selected with
  `PROBECTL_AI_MODEL_PROVIDER`, `PROBECTL_AI_MODEL_ENDPOINT` (always the base URL),
  `PROBECTL_AI_MODEL_NAME`, and a secret-reference `PROBECTL_AI_MODEL_TOKEN`. A remote
  provider additionally needs `PROBECTL_AI_EGRESS_ACK` plus per-tenant consent.
- Related terms: RCA, MCP, RBAC / ABAC, RLS (Row-Level Security), tenant, and IPS in
  the [glossary](../glossary.md).

**Covers:** F13, F14, F45
