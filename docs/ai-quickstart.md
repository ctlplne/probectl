# Using the AI: first question → your own model → your own tools

This is the task-ordered walkthrough of probectl's AI surface. The reference
depth lives in [`ai-rca.md`](ai-rca.md), [`ai-query.md`](ai-query.md),
[`ai-egress.md`](ai-egress.md), and [`mcp.md`](mcp.md) — this page walks you
through *doing* it, in the order an operator actually does, assuming nothing
beyond a running control plane.

**What you need before step 1:** a control plane you can curl — the from-source
dev rig from [`getting-started.md`](getting-started.md) is perfect (its
`./certs/ca.crt` and `https://127.0.0.1:8443` are what the examples below use).
Each later step states its own extra prerequisite at the top. Total time, all
five steps: ~15 minutes.

**The honesty contract first**, because it explains everything below: the
assistant answers with **citations to real signals you are allowed to see**, it
runs **air-gapped by default** (no language model is contacted until you
configure one), and it **never acts** — it explains, and at most *proposes* (a
human approves). Tenant first, then RBAC, on every path: the model never sees
data the asking user couldn't query directly.

## Choosing your rung (you can climb later)

Two words you'll see throughout: an **LLM** (large language model) is the kind
of AI that writes text — ChatGPT and Claude are LLMs; **deterministic** means
"same inputs, same answer, every time" — ordinary code, no AI randomness.

| Rung | What it is | Needs | Data leaves your network? |
| --- | --- | --- | --- |
| **Builtin** (default) | a deterministic in-process engine — ranks and cites evidence; not an LLM | nothing | never |
| **Ollama** | an app that runs open LLMs on ordinary hardware (laptop/server, CPU is fine) | install Ollama | never (same machine) |
| **vLLM** | a high-throughput LLM server for GPU boxes; speaks the OpenAI-compatible API | a Linux host with an NVIDIA GPU | never (same machine) |
| **Cloud model** | OpenAI/Anthropic/Azure | an API key + the consent chain | yes — gated + audited |

## 1. Ask your first question (zero setup)

Nothing to install, nothing to enable: the **builtin** engine answers the moment
the control plane is up. In the UI it's **Ask (AI)** in the nav (`/ask`). Over
the API:

```sh
curl -sS --cacert ./certs/ca.crt -H 'Content-Type: application/json' \
  -d '{"question": "why is checkout slow?", "subject": "checkout"}' \
  https://127.0.0.1:8443/v1/ai/ask
```

The body takes `question` (required, 1–2000 chars) and an optional `subject` to
focus the evidence search. On the dev rig this works with plain curl; a
production deployment authenticates this like any `/v1` call.

**What just happened (no magic):** the builtin engine is a *librarian, not an
author*. It pulled the evidence you're allowed to see (correlated incidents +
change events), ranked it by **cause-likelihood × severity × recency** (a change
usually outranks a latency metric, because metrics are symptoms and changes are
causes), named the top-ranked signal as the probable cause, and cited the rest.
No LLM ran. That's why it cannot hallucinate — it can only point at rows that
exist.

## 2. Read the answer like an operator

The response is a cited verdict, not prose. The fields that matter (shape
abridged):

```json
{
  "root_cause": "…one line naming the probable cause…",
  "root_cause_grounded": true,
  "root_cause_citations": [ … ],
  "confidence": "…scored, not vibes…",
  "findings": [ …each claim, each citing a signal… ],
  "evidence": [ …the underlying rows, with IDs you can open in the UI… ],
  "insufficient_evidence": false,
  "degraded": false
}
```

- `root_cause_grounded: false` means a model's headline claim cited nothing
  real, so probectl **rejected and replaced it** — an ungrounded claim is never
  shown.
- `insufficient_evidence: true` is the assistant saying *"I don't know."* That's
  a feature: when the planes are quiet it refuses to invent a story. (A fresh
  install with no producers will answer exactly this — attach a producer first;
  see [`getting-started.md`](getting-started.md).)
- `degraded: true` — your remote model was unreachable and the air-gapped
  builtin answered instead. A dead AI provider can never take RCA down.

## 3. Upgrade the prose: a model on your own hardware

The builtin's answers are correct but terse. A **local** model adds fluent
narrative — and changes nothing about sovereignty, because of one rule worth
understanding: probectl treats an endpoint on `127.0.0.1` / `localhost` / `::1`
(**loopback** — network-speak for "this same machine; the traffic never touches
a wire") as local, so it needs **no acknowledgment and no consent**. Anything
else is "remote" and goes through step 4's gates.

**Option A — Ollama (the laptop-friendly path).** Ollama is a free app that
downloads open models and serves them over a local HTTP API on port `11434`.

```sh
# 1. install it: https://ollama.com/download  (macOS: `brew install ollama`)
# 2. make sure it's running — the desktop app starts the server for you;
#    on a headless server, run `ollama serve` in its own terminal.
# 3. download a model (~4–5 GB the first time) and confirm it's there:
ollama pull llama3.1
ollama list

# 4. point probectl at it — three env vars on the control plane:
PROBECTL_AI_MODEL_PROVIDER=ollama \
PROBECTL_AI_MODEL_ENDPOINT=http://127.0.0.1:11434 \
PROBECTL_AI_MODEL_NAME=llama3.1 \
  ./bin/probectl-control
```

`NAME` is exactly the tag you pulled (`ollama list` shows it). Under the hood,
probectl now POSTs the question *plus the evidence it already gathered* to
Ollama's `/api/chat`, lets the model write the narrative — and then **still
validates every citation** before showing you anything. The model proposes
prose; probectl enforces the grounding.

**Option B — vLLM (the GPU-server path).** vLLM serves bigger models faster on
NVIDIA GPUs and speaks the **OpenAI-compatible** API on port `8000`. There is
deliberately **no `vllm` provider in probectl** — you use the `openai` adapter
pointed at your own box, which is the whole trick:

```sh
# on the GPU host (Linux + NVIDIA driver; vLLM docs: https://docs.vllm.ai):
pip install vllm
vllm serve mistralai/Mistral-7B-Instruct-v0.3     # OpenAI-compatible on :8000

# on the control plane:
PROBECTL_AI_MODEL_PROVIDER=openai \
PROBECTL_AI_MODEL_ENDPOINT=http://127.0.0.1:8000 \
PROBECTL_AI_MODEL_NAME=mistralai/Mistral-7B-Instruct-v0.3 \
  ./bin/probectl-control
```

`PROBECTL_AI_MODEL_TOKEN` stays unset unless your vLLM enforces auth. (If the
GPU box is a *different* machine, its address isn't loopback anymore — that's a
remote endpoint by the rule above: it must be `https`, and step 4 applies.)

All five recipes — including OpenAI, Anthropic, and Azure — live in
[`ai-rca.md` → Copy-paste recipes](ai-rca.md#copy-paste-recipes).

## 4. A cloud model is a decision, not a config value

Pointing at a non-loopback endpoint means tenant evidence **leaves your
network**, so probectl makes you say so twice, on purpose:

1. **The operator acknowledges it at boot** —
   `PROBECTL_AI_EGRESS_ACK=yes-send-tenant-data-to-the-remote-model` (yes, the
   exact sentence: nobody enables this by typo).
2. **Each tenant consents individually** — the
   `tenant_governance.ai_remote_egress` bit, default **deny**. How to set it in
   each edition (governance API, or SQL on core) is the runbook in
   [`ai-egress.md` → Turning it on](ai-egress.md#turning-it-on).

Until both gates are open, remote calls fail with a denial message naming this
exact mechanism — nothing is sent. Every call after they open is appended to
the tenant's tamper-evident audit stream (`ai.remote_egress`: what *categories*
went, never the content).

## 5. Hand the map to your own AI (MCP)

**MCP** (Model Context Protocol) is the open standard that lets AI apps —
Claude Desktop, Claude Code, agent frameworks — call external *tools*. probectl
ships an MCP server, so your AI can query *your* network: eight tenant-scoped
tools (six read-only queries, one gated analysis, one proposal-only
remediation). The token you mint decides what the AI sees — it acts **as that
user**, never more.

```sh
# prerequisite: the probectl-control binary on the same machine as the AI app,
# with PROBECTL_DATABASE_URL reachable. Mint the token (prints ONCE — copy it):
PROBECTL_DATABASE_URL='postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable' \
  ./bin/probectl-control mcp-token --user <user-uuid> --name laptop-claude
```

Then add probectl to the AI app's MCP config (Claude Desktop: **Settings →
Developer → Edit Config**) — the filled-in JSON, the network-reachable HTTPS
variant, and what a consent-denied tool call looks like are all in
[`mcp.md`](mcp.md). Restart the app and the tools appear; ask it *"list my
failing tests and explain the worst one."*

## 6. What it deliberately will not do

No autonomous actions (proposals only, human-gated). No cross-tenant reads —
structurally, not by prompt. No silent egress — the gates above, audited. No
answer persistence unless you opt in (`PROBECTL_AI_PERSIST_ANSWERS`, default
off). No hallucinated citations — ungrounded claims are replaced, and "I don't
know" is a first-class answer.

## See also

[`ai-authoring.md`](ai-authoring.md) — describe a test in plain English, get a
validated config proposal. [`ai-query.md`](ai-query.md) — the semantic query
layer underneath all of this and its two-level scoping.
