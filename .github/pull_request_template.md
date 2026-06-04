## Summary

<!-- What does this PR do, and why? -->

## Sprint & requirements

- **Sprint:** <!-- e.g. S0 -->
- **Requirement IDs:** <!-- e.g. F50, F52 -->

## Changes

<!-- The notable changes in this PR. -->

## Definition of Done (CLAUDE.md §8)

- [ ] Compiles; `gofmt` + `golangci-lint` clean (Python: `ruff` + `black`)
- [ ] Unit + relevant integration tests pass in CI
- [ ] OpenAPI spec + `docs/` updated (no undocumented routes at a GA milestone)
- [ ] Idempotent migration included for any DB change
- [ ] New config keys documented in `docs/configuration.md`
- [ ] Feature self-observability (logs/metrics) present — probectl observes probectl
- [ ] Security guardrails upheld (CLAUDE.md §7)
- [ ] Conventional Commits; this PR references its sprint + requirement IDs

## Tenancy & security

<!-- Note any impact on the tenant boundary, crypto, auth, audit, or external
     data sources. A cross-tenant isolation test MUST accompany any change to a
     data-access path (CLAUDE.md §7 guardrail 1). -->

- [ ] No data-access path can return cross-tenant rows; isolation test added/updated if a data path changed
- [ ] No secrets committed; no plaintext listeners; outbound fetches validate TLS
