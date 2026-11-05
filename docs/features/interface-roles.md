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

This configuration surface is available while automatic classification and its
real-router acceptance are being completed. Saving a policy does not yet enable
automatic labels or add role dimensions to Explorer.

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
