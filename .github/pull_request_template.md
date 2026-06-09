## Summary

<!-- What does this PR do, and why? Keep it the smallest coherent change. -->

## Changes

<!-- The notable changes in this PR. -->

## Definition of Done

<!-- See CONTRIBUTING.md → Definition of Done. Check what applies. -->

- [ ] Compiles; `gofmt` + `go vet` + `golangci-lint` clean (Python: `ruff` + `black`)
- [ ] Unit + relevant integration tests pass in CI
- [ ] OpenAPI spec + `docs/` updated (no undocumented API routes)
- [ ] Idempotent migration included for any schema change
- [ ] New config keys documented in `docs/configuration.md`
- [ ] Feature self-observability (logs/metrics) present — probectl observes probectl
- [ ] Commits follow Conventional Commits and carry a DCO sign-off (`git commit -s`)

## Tenancy & security

<!-- Note any impact on the tenant boundary, crypto, auth, audit, or external
     data sources. A cross-tenant isolation test MUST accompany any change to a
     data-access path — it is the highest-severity invariant in this codebase. -->

- [ ] No data-access path can return cross-tenant rows; isolation test added/updated if a data path changed
- [ ] No secrets committed; no plaintext listeners; outbound fetches validate TLS
- [ ] Crypto goes only through `internal/crypto`; proto changes are additive-only
