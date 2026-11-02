# Real NetBox source proof

The `integration` check starts the digest-pinned NetBox 4.4.5 application,
PostgreSQL and Valkey in an internal disposable network before the other test
stacks. It stops this source before starting those stacks. This proves the
actual provider protocol, tenant filtering and fresh role/site lookups. The
complete release-binary FX-3 receipt remains a separate acceptance requirement.

`scripts/ci_netbox.py start` is CI-only. It generates a private CA and runtime
credentials in `/tmp/probectl-qa-beta-netbox`. The source has one native TLS
listener on `127.0.0.1:18443`; database/cache connections validate their server
certificates and names. Wrong source CA/hostname and an API write through the
read-only token must fail. Two source tenants have equal IPs and device names,
separate VRFs and distinct role/site values. ORM administration seeds only this
disposable source; probectl receives an expiring view-only token.

The explicit source-proof step sets `PROBECTL_TEST_NETBOX_REQUIRED=1`; missing
`PROBECTL_TEST_NETBOX_FIXTURE` or any required source setup then fails the test.
Other integration lanes leave the opt-in unset and skip this one source proof.
The test warms both tenant caches, checks role/site against full related-CI
ownership, refuses unmapped callers, then moves an actual source IP to the other
tenant and proves fresh import previews refuse the absent/ambiguous ownership.
Cleanup restores that row, removes the exact compose project and deletes the
runtime directory, including its credentials and keys. No remote source is used.

The artifact contains only `receipt.json` (version, image identities, tested
checkout and source scope) and `provider-proof.json` (passed provider assertions).
Raw source data, keys, token, environment and container logs are not uploaded.

Provenance checked 2026-11-02: [NetBox](https://github.com/netbox-community/netbox/tree/v4.4.5)
is Apache-2.0; its official [container](https://github.com/netbox-community/netbox-docker/tree/3.4.1)
is pinned by digest. [Valkey](https://github.com/valkey-io/valkey/blob/8.1/COPYING)
uses BSD-3-Clause, and [PostgreSQL](https://www.postgresql.org/about/licence/)
uses the PostgreSQL License. These self-hosted test services need no hosted
account or hosted-service AUP. They add no product dependency or telemetry egress.
This first compatibility proof covers the pinned NetBox version only.
