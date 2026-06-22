# Control plane

## What it is

Think of the control plane as the **air-traffic control tower** for your network
observability. The aircraft — agents and collectors out on your hosts and
routers — do the flying and the looking. The tower receives everything they
report, keeps the records, correlates the picture, and answers questions. The
tower itself flies nothing: it is a **consumer** of observations, not a
producer. Its tagline is *see everything, send nothing* — meaning your telemetry
never leaves your network, not that the tower magically sees traffic on its own.

This page is about how you *drive* that tower programmatically. The control plane
exposes two ways in and one way to script it:

- a **versioned REST API** described by an OpenAPI 3.1 contract (REST is the
  ordinary "URLs and JSON over HTTPS" web-API style; OpenAPI 3.1 is the
  machine-readable specification of every route, so you can generate clients and
  validate requests);
- a **gRPC** interface used by agents to stream their observations (gRPC is the
  HTTP/2-based remote-procedure-call protocol agents connect over); and
- a **command-line interface and terminal UI** (`probectl`) that wraps the same
  API so you can do from a shell whatever the web interface does.

Everything is scoped to one [tenant](../glossary.md) — one isolated customer or
organization — which is the outermost boundary on every record, query, and API
call.

## Why it exists

A network observability platform that you can only click through is a platform
you cannot automate. Real operations live in scripts, pipelines, and
infrastructure-as-code: provision a probe target in the same change that deploys
a service, page a human from a runbook, pull last night's results into a report.
So every capability the web interface offers is reachable through a stable,
documented, versioned API — and the CLI exists so the same actions fit naturally
into a shell or a continuous-integration job.

Two design choices follow from "this must be safe to depend on":

- **Versioning with a contract.** Routes live under `/v1/...` and the OpenAPI 3.1
  spec is the source of truth. The spec is updated in the same change as the
  route it describes, so there are no undocumented routes to discover by
  surprise, and a deprecation policy governs how a version retires.
- **Transport security on every channel.** Every listener serves Transport Layer
  Security ([TLS](../glossary.md), 1.2 or higher). The API and web interface are
  HTTPS; the agent channel is mutual TLS ([mTLS](../glossary.md) — both ends
  present a certificate, not just the server). There is no plaintext or
  no-authentication mode to lean on in production. A missing secure channel or
  credential fails closed rather than falling back to plaintext.

## How it works

The control plane is **stateless and tenant-aware**: it holds no per-request
state of its own, and it resolves the caller's tenant at the edge and carries
that tenant through every downstream read and write. This is what lets you run
more than one copy behind a load balancer, and it is the foundation of tenant
isolation — a request can only ever touch its own tenant's data.

How you authenticate depends on the surface:

- **Human / browser sessions** use single sign-on. The control plane speaks
  OpenID Connect ([OIDC](../glossary.md) — the standard web-login protocol) to
  your identity provider (for example Okta, Microsoft Entra ID, or Keycloak), so
  logins and group memberships come from the system you already run.
- **Programmatic API calls** present a bearer credential, and every call is
  checked against role-based and attribute-based access control
  ([RBAC](../glossary.md)/[ABAC](../glossary.md)) — a permission such as
  `alert.read` or `test.write` gates each route. The tenant boundary is
  enforced first, then the permission.
- **Agents** authenticate over mTLS with a short-lived, tenant-bound identity.
  An agent is bound to a single tenant when it enrolls, and the control plane
  verifies that identity on every connection.

A request flows: caller authenticates at the edge → tenant resolved → permission
checked → the control plane reads or writes the relevant store, always scoped to
that tenant → JSON comes back. Configuration changes and data-access actions are
written to the tamper-evident audit log along the way.

The `probectl` CLI is a thin client over the same `/v1` API — it is not a second
code path with its own logic. Whatever you can do with `curl` against the API,
you can do with the CLI, and it presents results as readable tables (or JSON
when you ask). The terminal UI is the keyboard-first companion for browsing the
same data interactively in a shell.

## Use it

Confirm the control plane is up and serving, then read data through `/v1`. Pass
your certificate authority file so the client trusts the control plane's
certificate, and a bearer credential for anything beyond the health check:

```sh
# Liveness/readiness — no auth required, just TLS trust.
curl --cacert ./ca.crt https://probectl.example.com/readyz

# Observe: {"status":"ready"} once migrations have applied and the plane is up.
```

```sh
# A real, tenant-scoped read: the latest synthetic result per target.
curl --cacert ./ca.crt \
  -H "Authorization: Bearer $TOKEN" \
  https://probectl.example.com/v1/results/latest
```

```json
{
  "collector_running": true,
  "items": [
    {
      "target": "https://shop.example.com/",
      "type": "http",
      "success": true,
      "metrics": { "http.dns.ms": 12, "http.connect.ms": 28, "http.tls.ms": 41, "http.ttfb.ms": 96 },
      "observed_at": "2026-06-22T14:03:21Z"
    }
  ]
}
```

The same call through the CLI — point it at your control plane and hand it the
same credential, and it renders a table instead of raw JSON:

```sh
probectl --url https://probectl.example.com --token "$TOKEN" \
  result latest

# Observe: a TARGET | TYPE | SUCCESS | DNS | CONNECT | TLS | TTFB table — the same
# data as the JSON above, formatted for a human. Add --json for the raw
# object, e.g. to pipe into jq in a CI job.
```

Because the API is described by an OpenAPI 3.1 document, you can also generate a
typed client in your language of choice, or validate requests against the spec
in tests, instead of hand-writing HTTP calls. Routes are versioned under `/v1`,
so a client written against today's contract keeps working under the deprecation
policy.

## Pitfalls & limits

- **A control plane with no producers shows no data — that is expected.** A fresh
  install is a healthy, empty database. `/readyz` is green and the dashboards are
  blank until you attach an agent or collector. The fix is always "attach a
  producer," never "restart the tower." See the getting-started guide.
- **Evaluation-only convenience modes are not production.** There is a local
  development mode where requests are unauthenticated — it exists only for poking
  the API on a laptop, and it is constrained so it cannot run on a network
  interface or in a release build. In production you use OIDC sign-on for humans
  and bearer credentials for scripts. Do not build automation against the
  no-auth mode.
- **Mind which client and which port.** The control plane serves HTTPS, and the
  CLI expects a bearer credential. Against a self-signed certificate, pass the
  certificate authority file (`--cacert` for `curl`, the equivalent CLI flag);
  against a real certificate it just works. A connection error right after start
  usually means migrations are still applying — wait and retry.
- **No undocumented routes, by policy.** If a route is not in the `/v1` OpenAPI
  spec, treat it as not part of the contract. Build against the documented
  surface so upgrades stay predictable.
- **gRPC is the agent channel, not your general-purpose API.** Drive automation
  through the REST `/v1` API or the CLI; gRPC carries the agent telemetry stream
  over mTLS.

## Reference

| Surface | Protocol | Auth | Purpose |
|---|---|---|---|
| REST API (`/v1/...`) | HTTPS, OpenAPI 3.1 | OIDC session or bearer + RBAC/ABAC | Drive every capability programmatically |
| Agent channel | gRPC over mTLS | tenant-bound agent identity | Agents stream observations in |
| `probectl` CLI / terminal UI | HTTPS to `/v1` | bearer credential | Shell- and CI-friendly client over the same API |
| Health | `GET /readyz` | none (TLS only) | Liveness/readiness checks |

Properties you can rely on: every listener serves TLS and there is no production
plaintext or no-auth path (a missing secure channel or credential fails closed);
the REST API is versioned under `/v1` with an OpenAPI 3.1 contract kept in step
with the routes and a deprecation policy, so no route is undocumented; every call
is scoped to the caller's tenant first and then checked against RBAC/ABAC; and
the CLI is a client over the same API, not a separate code path. Full
configuration keys and the agent-enrollment lifecycle are documented in the
configuration and enrollment guides.

## See also

Getting started (zero to first data, including agent enrollment); alerting and
incidents (the `/v1/alerts` and `/v1/incidents` routes in depth); the glossary
for any term above.

**Covers:** F10
