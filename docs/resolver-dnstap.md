# Resolver dnstap coverage and pressure

An operator-owned resolver can submit reduced dnstap client-response
observations. The file can contain DNS names and addresses. Keep it on the
resolver host in a restricted directory. probectl retains timestamps,
client-response counts, NXDOMAIN counts, SERVFAIL counts and truncation
counts. The client reduces the file before it opens the existing evidence
mTLS connection.

1. In the correct tenant and routing context, create a canonical device for
   the resolver and enroll an agent with a dedicated evidence certificate.
   Use `probectl entities sources-assign` to assign that agent's
   `dns_resolver` source reference to the resolver device UUID under
   `anchor_entity_id`. Put the same exact reference in the submit command.
2. Configure your resolver to produce client-response dnstap frames in a
   local file. BIND supports `dnstap { client response; };` and
   `dnstap-output file "<local path>";`. Use the resolver's graceful close
   or rotation to produce a stopped Frame Streams file. Start the capture
   after the certificate and source assignment are active.
3. Run `probectl dnstap submit --help` for its local file, the UTC minute
   bounds, and the mTLS address and identity options. Supply up to two hours
   of consecutive, completed minutes, ending within the last 24 hours.
   Choose the complete minutes inside the rotated file. The client counts
   and excludes responses in adjacent partial minutes. Exact uploads can be
   retried. A changed upload for an admitted minute returns a conflict.
4. Run `probectl entities resolver-dns-coverage <device UUID>` with the
   `context_id`, `agent_id` and `source_ref` query parameters. The
   default is ten completed minutes. Select up to 120 with `minutes`.
   Each row contains only captured counts. A missing minute stays absent.
   The coverage view requires both entity and metrics access in the current
   routing context.
5. View resolver pressure signals and their observed clocks in Incidents.
   Two adjacent minutes need the same error class above the response,
   error-count and share floors. These are operator-tunable signals about
   captured response pressure. Examine the linked resolver, coverage and
   ordinary service behavior in the same incident.

The file STOP verifies closure. It carries no producer drop counter. A
zero count describes that closed-file interval. It cannot establish that
the resolver handled zero DNS traffic. Retained counts are available for the
last 24 hours. Retention and import are scoped to the current source
assignment and the certificate's tenant.

[ISC BIND dnstap documentation](https://kb.isc.org/docs/aa-01342) ·
[BIND file rotation](https://bind9.readthedocs.io/en/stable/manpages.html#dnstap-reopen-roll-number) ·
[Configuration](configuration.md)
