# Feature index

> **Looking for how to *use* probectl?** Start with the **[user journeys](journeys.md)** —
> the end-to-end paths (onboarding, alert→root-cause, threat response, tenant setup,
> cost/SLO governance, production operations). This page is the **reference** behind
> those paths.

The traceability matrix: every probectl feature (F1–F57) and the page that documents
it. Use it to answer "where is feature X explained?" The customer-facing feature pages
live under [`features/`](features/); three standalone pages ([bgp.md](bgp.md),
[audit.md](audit.md), [limitations.md](limitations.md)) sit alongside this index. Each
feature has one **primary** page (where it's taught to a zero-knowledge reader); it may
be referenced from others.

| Feature | Primary page |
|---|---|
| F1 — Canary agent | [features/active-testing.md](features/active-testing.md) |
| F2 — Network tests (active synthetic) | [features/active-testing.md](features/active-testing.md) |
| F3 — Path visualization | [features/topology-and-change.md](features/topology-and-change.md) |
| F4 — HTTP / web tests | [features/active-testing.md](features/active-testing.md) |
| F5 — DNS / DNSSEC tests | [features/active-testing.md](features/active-testing.md) |
| F6 — BGP & routing monitoring | [bgp.md](bgp.md) |
| F7 — Open-data enrichment | [features/open-data-and-outage.md](features/open-data-and-outage.md) |
| F8 — Alerting | [features/alerting-and-incidents.md](features/alerting-and-incidents.md) |
| F9 — Dashboards & incident timeline | [features/alerting-and-incidents.md](features/alerting-and-incidents.md) |
| F10 — Control plane (REST/gRPC + CLI/TUI) | [features/control-plane.md](features/control-plane.md) |
| F11 — eBPF host & L7 agent | [features/telemetry-planes.md](features/telemetry-planes.md) |
| F12 — OTel data model + OTLP | [features/telemetry-planes.md](features/telemetry-planes.md) |
| F13 — AI RCA & NL query | [features/ai-assistant.md](features/ai-assistant.md) |
| F14 — MCP server | [features/ai-assistant.md](features/ai-assistant.md) |
| F15 — Browser synthetic monitoring | [features/digital-experience.md](features/digital-experience.md) |
| F16 — Endpoint agent (DEM) | [features/digital-experience.md](features/digital-experience.md) |
| F17 — Flow analytics | [features/telemetry-planes.md](features/telemetry-planes.md) |
| F18 — Device telemetry (SNMP & gNMI) | [features/telemetry-planes.md](features/telemetry-planes.md) |
| F19 — Internet-outage view | [features/open-data-and-outage.md](features/open-data-and-outage.md) |
| F20 — Real user monitoring | [features/digital-experience.md](features/digital-experience.md) |
| F21 — Voice / RTP quality | [features/digital-experience.md](features/digital-experience.md) |
| F22 — SSO & role model | [features/identity-and-access.md](features/identity-and-access.md) |
| F23 — Audit log foundation | [audit.md](audit.md) |
| F24 — Tenant→Org→Team→Project hierarchy | [features/identity-and-access.md](features/identity-and-access.md) |
| F25 — SCIM / ABAC / delegated admin | [features/identity-and-access.md](features/identity-and-access.md) |
| F26 — SIEM integration | [features/integrations.md](features/integrations.md) |
| F27 — On-call & ITSM | [features/integrations.md](features/integrations.md) |
| F28 — Zero-downtime lifecycle & fleet rollout | [features/operations.md](features/operations.md) |
| F29 — IaC & GitOps | [features/integrations.md](features/integrations.md) |
| F30 — CMDB / Grafana / Prometheus federation | [features/integrations.md](features/integrations.md) |
| F31 — Secrets integration | [features/integrations.md](features/integrations.md) |
| F32 — FIPS-mode crypto | [features/operations.md](features/operations.md) |
| F33 — Multi-region & HA | [features/operations.md](features/operations.md) |
| F34 — Advanced governance | [features/operations.md](features/operations.md) |
| F35 — Supportability | [features/operations.md](features/operations.md) |
| F36 — TLS / certificate observability | [features/security-and-threat.md](features/security-and-threat.md) |
| F37 — NDR-lite detection engine | [features/security-and-threat.md](features/security-and-threat.md) |
| F38 — Threat-intel enrichment | [features/security-and-threat.md](features/security-and-threat.md) |
| F39 — Change intelligence | [features/topology-and-change.md](features/topology-and-change.md) |
| F40 — Live topology graph | [features/topology-and-change.md](features/topology-and-change.md) |
| F41 — FinOps / egress cost | [features/cost-slo-and-chaos.md](features/cost-slo-and-chaos.md) |
| F42 — SLO & business impact | [features/cost-slo-and-chaos.md](features/cost-slo-and-chaos.md) |
| F43 — Segmentation validation | [features/security-and-threat.md](features/security-and-threat.md) |
| F44 — Guarded remediation | [features/security-and-threat.md](features/security-and-threat.md) |
| F45 — AI authoring & discovery | [features/ai-assistant.md](features/ai-assistant.md) |
| F46 — Last-mile / WiFi / ISP diagnostics | [features/digital-experience.md](features/digital-experience.md) |
| F47 — Network chaos | [features/cost-slo-and-chaos.md](features/cost-slo-and-chaos.md) |
| F48 — Carbon & power | [features/cost-slo-and-chaos.md](features/cost-slo-and-chaos.md) |
| F49 — Plugin/detection marketplace (non-goal) | [limitations.md](limitations.md) |
| F50 — Tenancy & hard isolation | [features/tenancy.md](features/tenancy.md) |
| F51 — Provider / MSP plane | [features/commercial-plane.md](features/commercial-plane.md) |
| F52 — Pooled / siloed / hybrid isolation | [features/tenancy.md](features/tenancy.md) |
| F53 — Metering & billing export | [features/commercial-plane.md](features/commercial-plane.md) |
| F54 — White-label branding | [features/commercial-plane.md](features/commercial-plane.md) |
| F55 — Export, residency & verifiable deletion | [features/commercial-plane.md](features/commercial-plane.md) |
| F56 — Per-tenant keys / BYOK | [features/commercial-plane.md](features/commercial-plane.md) |
| F57 — Tenant fairness | [features/tenancy.md](features/tenancy.md) |

New terms used on these pages are defined in the [glossary](glossary.md).
