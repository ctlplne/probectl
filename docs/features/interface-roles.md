# Interface role configuration

In **Admin → Interface roles**, choose an owned routing context, declare provider
and customer ASN sets, and arrange description rules in first-match order.
Provider/customer sets must not overlap. ASNs cover the complete positive
32-bit ASN domain. Patterns use Go's regular-expression syntax; the server
creates stable IDs for new rules. Editing a rule retains its ID. Rule pages are
presentation only: saving submits the complete ordered policy, including rules
on other pages.

Choose an owned canonical **interface** to read, set or reset its manual role:
transit, IX peering, private peering, customer, backbone or other. A manual
choice remains until an explicit reset, even when automatic source observations
change or expire. A reset requires confirmation. It never makes missing source
evidence trustworthy or asserts that a BGP session is up.

The current-role explanation preview joins owned SNMP and BMP evidence with
this configuration through Admin, REST, CLI and native MCP. PeeringDB IX-prefix
lookup, Explorer role dimensions and real-router acceptance remain unfinished.

The flow-engine component accepts a request-local current role projection for
`in_if_role` and `out_if_role`. It joins the uniquely owned exporter, protocol,
complete observation-domain ID and interface index; a row's claimed agent ID
cannot select a routing context. Unknown metadata remains `other`, with all
traffic retained. Complete raw and retained inputs use the same classification,
and result metadata retains source/configuration provenance. Public activation
still requires the current-authority loader and frozen-reader integration.
Selecting either field requires `entities.read`, `metrics.read` and
`events.read`; a missing projection refuses execution rather than inventing
authority. This component does not qualify the real-router feature.

Explanations require a current tenant user with `entities.read`, `metrics.read`
and `events.read` for the selected routing context. The actual credential is a
separate permission ceiling. Responses include `role`, `reason`, complete
`sources`, `as_of`, `snmp_current` and `prefix_current`. A fresh application-role
snapshot checks current user grants, context policy and all facts again after
computation. Rebinding, withdrawal, policy changes or expiry refuse publication;
refresh to compute from the new state. Missing or ambiguous source association
remains `other`. An owned override still wins.

The evaluation component validates a complete policy before choosing the first
matching description rule. Explanations retain the policy ID, exact revision
and rule ID, or the manual override ID and revision. Regex execution accounts
for repeat expansion, capture state and matching work before compilation and
matching; resource refusal or cancellation returns no partial classification.
Withdrawn or stale source observations cannot produce a description match.
The tenant store supplies current source facts; same-router real sender and
router acceptance remains required before qualification.

When sender-bound device evidence is configured, each successful base SNMP
poll reads the complete supported IP-MIB interface-prefix table over that same
connection. The table travels only on the configured-target observation, in
its own bounded request. An unsupported, malformed, incomplete or over-budget
walk publishes no prefix table in the new poll epoch; readers must withhold
older tables. Prefix contents and availability participate in the identity
fingerprint, so changes send immediately while unchanged complete observations
retain the existing twelve-hour refresh and explicit 24-hour receiver expiry.
Fault recovery forces a new successful observation even if the fingerprint is
unchanged. Collector counters `interface_prefix_snapshots` and
`interface_prefix_unavailable` expose the outcomes. Raw device metrics continue
when prefix evidence is unavailable. Current-source freshness enforcement and
same-router FRR/SNMP proof remain required before automatic role activation.

The read-time component follows the latest poll even when its prefix table is
unavailable or expired; it never falls back to an older non-null table. A later
authenticated poll fault withholds automatic facts until a successful new
observation. Resolving the incident does not invent recovery. The latest peer
observation replaces its previous ASN. These inputs share the owned interface,
router and context, and retain the source's current certificate and assignment
expiry. The served explanation uses this loader and evaluator; Explorer role
dimensions remain unfinished.

Bind the BMP router source to its owned canonical router. A peer device
inferred from an address is a different identity and cannot supply this
origin-router binding for automatic roles.

Reads require `entities.read`; writes require `agent.write`, deployment MFA
when enabled, and the current context's resource policy. The authenticated
principal chooses the tenant. Context and interface ownership are enforced in
the tenant's application-role Postgres transaction, including FORCE RLS,
context/interface-kind foreign keys and silo routing. A provider operator has
no implicit configuration access. Mutations and their tenant audit append
commit together. Audit records retain IDs, revisions and cardinalities, not a
second copy of the patterns or ASN sets.

Every edit uses the returned configuration `id` and exact decimal-text
`revision`. Initial absent configuration has `id:""`, `revision:"0"`. The
combination prevents a stale editor from changing a reset and recreated
configuration whose revision has returned to 1. A 409 response requires reloading
and reviewing the current configuration. An unchanged semantic policy retains
its revision. Clearing a policy means replacing its definition with three empty
arrays; it does not reset interface overrides.

| Operation | REST | CLI |
| --- | --- | --- |
| Explain current role (preview) | `GET /v1/entity-contexts/{context_id}/interfaces/{id}/role` | `probectl interface-roles explain CONTEXT INTERFACE --json` |
| Read policy | `GET /v1/entity-contexts/{context_id}/interface-role-policy` | `probectl interface-roles policy CONTEXT --json` |
| Replace complete policy | `PUT` on the policy path | `probectl interface-roles set-policy CONTEXT --body-file - --json` |
| Read manual override | `GET /v1/entity-contexts/{context_id}/interfaces/{id}/role-override` | `probectl interface-roles override CONTEXT INTERFACE --json` |
| Set manual override | `PUT` on the override path | `probectl interface-roles set-override CONTEXT INTERFACE --body-file - --json` |
| Confirm reset | `DELETE` on the override path, with a JSON body | `probectl interface-roles reset-override CONTEXT INTERFACE --body-file -` |

The policy input contains `expected_id`, `expected_revision`, and `definition`
with complete `provider_asns`, `customer_asns` and `description_rules` arrays.
Each description rule has `pattern`, `role` and its existing `id` when editing.
The override input contains `expected_id`, `expected_revision` and `role`.
Reset contains `expected_id`, `expected_revision` and `confirmed:true`.

There is no policy rule/ASN count quota. A captured positive Explorer operation
profile admits memory, response bytes and execution time; existing tenant query
fairness also applies. Input reserves one sixteenth of the memory profile,
bounded by response admission; decoding reserves a quarter, and retained state,
normalization and output use the rest. A complete response is encoded before a
write commits. A resource refusal publishes no partial policy and rolls back a
mutation. Raise the existing `PROBECTL_FLOW_QUERY_MAX_MEMORY_BYTES`, response and
execution settings coherently for larger intended workloads. The named CLI command and raw `api PUT` path accept
complete policy body files through 64 MiB; the server retains its own independent
operator admission. No request can disable a resource bound with zero.

MCP tools `interface_role_policy`, `interface_role_policy_set`,
`interface_role_override`, `interface_role_override_set` and
`interface_role_override_reset` use the same configuration operations. They take
`context_id`, plus `interface_id` for overrides, and the same mutation fields as
REST. Writes require an authenticated tenant user. Existing consent, redaction,
current policy, call audit and final publication checks apply; configuration
access grants no telemetry/source permission. Complete native requests share the
operator's existing native source-byte profile across HTTP and stdio. Legacy
non-native request admission is unchanged. Go and TypeScript SDKs are generated
from the same OpenAPI schemas.

The default shared operation memory admission is 2 GiB. This is a resource
allowance, not an allocation: it admits the complete saved 4,097-rule workload
through two source reads and ordered evaluation. The positive configured
`PROBECTL_FLOW_QUERY_MAX_MEMORY_BYTES` still controls each operation; reduced
profiles refuse the complete result rather than dropping rules or sources.
