# Real NetBox source proof

The `netbox-live` check starts the digest-pinned NetBox 4.4.5 application,
PostgreSQL and Valkey in an internal disposable network on its own runner.
It runs independently of the stateful `integration` check, and `verify-all`
requires both checks to pass. This proves the
actual provider protocol, tenant filtering and fresh role/site lookups. The
complete release-binary FX-3 receipt remains a separate acceptance requirement.

`scripts/ci_netbox.py start` is CI-only. It generates a private CA and runtime
credentials in `/tmp/probectl-qa-beta-netbox`. The source has one native TLS
listener on its internal bridge at port8443. The Linux fixture clients route
the logical `https://localhost:18443` origin directly to that exact owned
container, retaining localhost SNI/hostname verification. Docker does not
realize published ports for an internal-only container without a default gateway;
the requested loopback binding is recorded as a diagnostic, not assumed usable.
No external bridge, host routing mutation, proxy or additional listener is needed.
Database/cache connections validate their server certificates and names.
Task queues use separate host/password parameters: the pinned django-rq URL
path drops separately configured credentials and client options. A fixture-only
Django settings extension preserves the base settings and explicitly requires
hostname verification, the fixture CA and TLS1.2 before web or ORM startup.
Bootstrap checks the effective task client options and performs an authenticated
ping. No password appears in a URL. The caching URL also contains no credential.
Wrong source CA/hostname and an API write through the
read-only token must fail. Two source tenants have equal IPs and device names,
separate VRFs and distinct role/site values. ORM administration seeds only this
disposable source; probectl receives an expiring view-only token.

The explicit source-proof step sets `PROBECTL_TEST_NETBOX_REQUIRED=1`; missing
`PROBECTL_TEST_NETBOX_FIXTURE` or any required source setup then fails the test.
Other integration lanes leave the opt-in unset and skip this one source proof.
The test warms both tenant caches, checks role/site against full related-CI
ownership, refuses unmapped callers, then moves an actual source IP to the other
tenant and proves fresh import previews refuse the absent/ambiguous ownership
and evict the old lookup cache entry.
Cleanup restores that row, removes the exact compose project and deletes the
runtime directory, including its credentials and keys. No remote source is used.

The artifact contains only `receipt.json` (version, image identities, tested
checkout and source scope) and `provider-proof.json` (passed provider assertions).
Raw source data, keys, token, environment and container logs are not uploaded.
Bootstrap failures report only a fixed stage and exception category, never the
exception message, traceback, SQL or input. The runner rejects extra diagnostic
fields and unknown categories before printing anything from that protocol.

Provenance checked 2026-11-02: [NetBox](https://github.com/netbox-community/netbox/tree/v4.4.5)
is Apache-2.0; its official [container](https://github.com/netbox-community/netbox-docker/tree/3.4.1)
is pinned by digest. [Valkey](https://github.com/valkey-io/valkey/blob/8.1/COPYING)
uses BSD-3-Clause, and [PostgreSQL](https://www.postgresql.org/about/licence/)
uses the PostgreSQL License. These self-hosted test services need no hosted
account or hosted-service AUP. They add no product dependency or telemetry egress.
This first compatibility proof covers the pinned NetBox version only.

NetBox's production API middleware converts unhandled exceptions to JSON before
Django's request logger receives an exception. On HTTP500 the fixture runner
extracts only a fixed allowlist of exception classes and boolean diagnostic
signals from that bounded response, then discards the entire body. The source
error text, request, token, SQL and traceback never enter logs or receipts.
An unknown class becomes `other`; planted error messages are tested for leakage.
The strict HTTP status and exact application-version assertions remain enabled.

Database TLS uses an explicit absent client-certificate path in the readable
fixture application directory. SCRAM authenticates this database client;
server trust remains verify-full with the fixture CA. Libpq must not inspect an
administrator's implicit client profile from a nonroot web process. A real
connection proof runs as the same unit:root identity: the original implicit
profile and a planted inaccessible profile must fail with the certificate-file
permission refusal, then the explicit configuration must connect with
pg_stat_ssl=true. An existing file at the intended absent path is refused.
This does not change HOME, run the web worker as root or weaken TLS verification.
