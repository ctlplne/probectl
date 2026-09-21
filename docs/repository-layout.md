# Repository layout

The canonical package map. It is checked in both directions by
`scripts/check_layout_map.sh`: every top-level package under `internal/` and
`ee/` must appear here, and every name here must exist as a package directory —
so this page cannot quietly come to describe a different codebase than the one
you cloned. Entries are `name (one-line purpose)`, separated by `·`.

```
cmd/        probectl-control · probectl-agent · probectl-ebpf-agent · probectl-endpoint ·
            probectl-flow-agent · probectl-device-agent · probectl-bmp-listener ·
            probectl-cloud-metrics · probectl-license · probectl-sdkgen ·
            probectl-scorecard ·
            probectl-workflow-policy · probectl-chaos-dependency-drill ·
            probectl-delivery-audit (repository-only independent auditor) ·
            probectl-deadseams (zero-call-site gate) ·
            terraform-provider-probectl · probectl (CLI, web-parity)
internal/   a2a (agent-to-agent measurement broker) · agent (canary-plugin agent runtime) ·
            agentlabel (placement-metadata validation) · agenttransport (agent gRPC lane, tenant-verifying) ·
            ai (AI query/RCA/MCP + egress gate) · alert (alerting engine) ·
            anomaly (tenant-scoped anomaly models) · apierror (domain error vocabulary) ·
            audit (immutable audit log + WORM) · auth (OIDC SSO, RBAC/ABAC) ·
            backup (at-rest backup encryption) · bakeoff (buyer comparison scorecards) ·
            bgp (BGP bridge to control plane) ·
            branding (deployment theming) · breaker (storage-client circuit breaker) ·
            browser (browser/transaction synthetics) · browsercanary (browser engine as canary plugin) ·
            bus (Kafka, NATS/JetStream durable-lightweight, and in-process volatile transports) · canary (canary plugin interface) ·
            carbon (carbon/power observability) · change (change ingest + incident correlation) ·
            chaos (local test-only fault injector) · cipolicy (CI/workflow policy tests) ·
            cli (probectl CLI) · cloudmetrics (cloud metric importers) ·
            cluster (multi-region HA) · cmdb (CMDB correlation) ·
            compliance (segmentation validation + evidence) ·
            completeness (capability/surface completeness contract) · config (config load/validate) ·
            configschema (config YAML schema helpers) · control (HTTP API server) ·
            cost (FinOps/egress cost engine) · crypto (the only crypto door) ·
            deliveryaudit (independent signed delivery evidence) ·
            device (SNMP/device telemetry plane) · docslint (doc-accuracy tests) ·
            ebpf (eBPF host agent) · endpoint (endpoint/DEM agent) ·
            evidence (signed offline incident packages) ·
            enroll (agent trust root/enrollment) · fairness (per-tenant admission fairness) ·
            flow (NetFlow/sFlow/IPFIX plane) · gen (generated code: protobuf/gNMI/prometheus) ·
            govern (data-governance core) · httpbody (bounded HTTP body readers) ·
            i18n (server/CLI message catalog) · incident (cross-plane incident correlation) ·
            ingesthealth (payload-free ingest observability) · inventory (operator-list primitives) ·
            license (offline edition gating) · lifecycle (zero-downtime upgrade) ·
            logging (structured slog setup) · metrics (self-observability) ·
            notify (on-call/notification wiring) · objectstore (per-tenant blob store) ·
            opendata (open-data enrichment) · otel (OTel semconv mapping) ·
            outage (collective outage view) · path (ECMP/MPLS path discovery) ·
            perf (load/perf harness) · pipeline (bus-to-store result pipeline, tenant-verifying) ·
            preflight (deployment self-check) · promapi (Prometheus-compatible surfaces) ·
            redactpat (shared secret/PII recognition patterns) ·
            remediation (core guarded-remediation seam) · reporting (tenant report artifacts) ·
            rum (real-user monitoring) · schema (offline schema lints) ·
            scim (SCIM 2.0 provisioning) · secrets (secret-backend integration) ·
            siem (SIEM export) · slo (OpenSLO engine) ·
            store (tenant-scoped datastore adapters) · support (support bundles/health) ·
            tenancy (tenant boundary: fences + posture) · tenantcrypto (per-tenant at-rest crypto seam) ·
            tenantlife (tenant lifecycle: export/erasure) · terraformprovider (Terraform provider core) ·
            testspec (synthetic-test schema) · testsupport (shared test helpers, no silent skips) ·
            testsync (signed pull-based test distribution) · threat (TLS/NDR-lite threat signals) ·
            topology (versioned topology + what-if) · usage (core metering seam) ·
            version (build metadata) · webui (embedded web UI) ·
            wire (bounded reader for untrusted wire input)
ee/         billing (metering/usage export) · cmd (commercial offline CLIs) ·
            governance (ee governance workflows) · pricing (offline TCO model; no license prices) ·
            provider (provider/management plane) · remediation (guarded remediation workflow) ·
            silo (siloed/hybrid isolation) · tenantkeys (BYOK) · web (embedded provider-console assets)
analyzer/   Python BGP · proto/ schemas · migrations/ (sequential, idempotent) · web/ frontend
deploy/     helm · compose · terraform · backup · packaging | docs/ · test/ (real-stack integration)
```

Core lives under `cmd/`, `internal/`, `analyzer/`, `proto/`, `migrations/`,
`web/` and `deploy/`. Commercial capabilities live only under `ee/`, which
imports core; core never imports `ee/` (enforced by `make editions-gate`), and a
core-only build with `-tags probectl_core` stays green with `ee/` inert. See
[LICENSING.md](../LICENSING.md) for what each tree is licensed under.
