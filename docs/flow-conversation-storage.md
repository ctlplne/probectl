# Private conversation storage foundations

`internal/store/flowconversation` provides storage primitives for retained flow
questions. It does not register a listener, API, CLI command or MCP tool. This
checkpoint adds no production migration for its tables and does not enable
conversation persistence. The flow explorer and its runtime integration remain
separate work.

The application must authorize the tenant and current owner before using these
primitives. Tenant RLS is the outer boundary. Conversation messages and jobs
also require the restrictive owner policy in pooled and siloed storage;
provider operators receive no implicit access. Startup posture checks and silo
repair use the same policy definition. A separately authorized maintenance path
must remain distinct from ordinary owner reads.

The codec uses the existing tenant encryption dispatcher and refuses keyless
storage. An authenticated minimal header contains the original credential
reference, complete required permissions and the encrypted payload digest. The
separate payload contains private application data. Both envelopes bind the
tenant, owner, conversation, immutable message revision and lifecycle epoch.
Opening a header grants no later payload access. Paired rewrap preserves the
binding; its caller must still perform an audited storage compare-and-swap.

Worker references identify the exact credential accepted at authentication;
they contain neither a raw bearer token nor permission grants. Session
references also bind the authenticating Manager policy. Background revalidation
checks current storage state without extending session activity. A replacement
credential cannot adopt an old attempt. Explicit owner history reads have a
separate current-credential authorization callback.

Input admission atomically appends an encrypted input, a source-free queued job
and mandatory audit. Writer, audit-stream and epoch fences serialize admission
against lifecycle changes. Parent references are explicit immutable revisions.
Finite retention deadlines never round upward; a missing deadline is accepted
only when the authoritative application policy permits it.

Workers use database-time leases bound to the process instance, input revision,
tenant epoch, lease generation and cancellation revision. Renewal and takeover
replace the lease fence. Cancellation cannot revive work. Proposal publication
atomically appends the encrypted proposal, its job reference, a new lease fence
and audit. It preserves the processing state: a proposal is not a completed
answer or permission to execute a query. Takeover returns the same proposal
reference for recovery.

Crypto, current-authorization callbacks, model calls and native queries must run
outside SQL mutation locks. Applications must validate typed documents, complete
ancestry, current source permissions and privacy policy before planning or
publication, then revalidate the exact attempt at sensitive boundaries. These
storage primitives cannot substitute for those checks.

Before runtime persistence is enabled, integration must include counted tenant
and subject portability, verifiable erasure, retention, worker drain and late
writer fencing, paired key rotation and key inventory. The disposable schema in
`internal/testsupport/historyfixture` is for owned integration databases only;
it is not a product migration or a completed lifecycle service.

See [guardrails](guardrails.md) for G7-1, G7-3, G7-5, G7-6 and G7-7, and
[contributor conventions](../CONTRIBUTING.md) for testing and licensing.
