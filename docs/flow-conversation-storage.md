# Private conversation storage foundations

`internal/store/flowconversation` provides storage primitives for retained flow
questions. It does not register a listener, API, CLI command or MCP tool. This
checkpoint adds no production migration for its tables and does not enable
conversation persistence. The flow explorer and its runtime integration remain
separate work.

Ordinary operations require current tenant and owner authorization. Source-free
restart discovery and maintenance use separate internal operational authority;
they cannot borrow an owner's credential or grant source access. Tenant RLS is
the outer boundary. Conversation messages and jobs
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

Claims and renewals return two separate lease deadlines. `Until()` is the
absolute PostgreSQL timestamp required for exact storage compare-and-swap.
`Deadline()` is a conservative process deadline for context-bound IO. It uses
the authoritative remaining duration from the same database clock read that
updates the lease, anchored to the earlier local monotonic query-send time.
Application/database clock skew cannot lengthen the permitted work. Lock and
network delay can shorten it. Invalid or unexpectedly unbounded database
durations refuse the lease. Callers must still enforce operation/privacy
bounds, replace only a confirmed current lease, and drain actual work.

Restart discovery binds one tenant and owner at the storage layer and returns
only bounded job metadata and an opaque encrypted minimal header. It never
selects the payload column. Per-page rows, header bytes and time bound cost;
there is no total backlog cap. A cursor supports a best-effort keyset sweep,
not an immutable snapshot. New or newly eligible work may require another
sweep. Internal operational authorization is checked around discovery and
header bootstrap; request and provider Principals cannot select this path.
Bootstrap authenticates original provenance only. Actual execution must still
reload the exact current credential and validate the complete input, ancestry,
source permissions, privacy policy and lease before opening source or planning.

Independent terminal cleanup can fail queued or expired processing work after
the creator loses authority, without reading source or requiring its encryption
key. It compares the exact input, epoch, observed status, lease generation and
cancellation revision. A newer claim, renewal, publication or cancellation
refuses the transition. Failure state, advanced fences and a bounded system
audit reason commit atomically; audit failure rolls back. Unknown or corrupt
minimal headers cannot authorize work, but remain eligible for source-free
maintenance. Transient infrastructure errors are not proof of a permanent
authorization refusal. The automatic scheduler and its error classification
remain separate integration work.

Crypto, current-authorization callbacks, model calls and native queries must run
outside SQL mutation locks. Applications must validate typed documents, complete
ancestry, current source permissions and privacy policy before planning or
publication, then revalidate the exact attempt at sensitive boundaries. These
storage primitives cannot substitute for those checks.

Tenant-family read and exclusive maintenance leases coordinate bounded private
callbacks without holding writer/audit/epoch/job mutation locks across IO. The
read lease captures the current operation generation and rechecks it around
nested work and callback return. Nested exact-identity contexts expire when
their owning callback drains and cannot revive a released SQL lease. Pool-wide
admission reserves connections for short working transactions.

A separate durable invalidating flag binds tenant, internal operation UUID,
fixed purpose and the exact immutable lifecycle-plan digest. Begin atomically
advances the operation generation and appends audit. Exact retries resume the
same intent; conflicting plans and audit failures refuse. All ordinary history
and worker paths reject pending state. Independently authorized resume needs
no creator credential, source SELECT or decryption key. Lost advisory leases
cannot clear the durable intent.

Cancellation sweeps use positive operator row/time resources, span owners only
within the same tenant, refuse counter overflow and atomically audit changed
metadata. They report canceled/still-active job counts without selecting source
or imposing a total-backlog cap. Begin and ordinary-writer cancellation precede
full-tenant audit/offboarding fences. Later destructive phases require the
independently audited lifecycle path. Zero active jobs is not complete erasure.
There is no finish/clear operation yet: complete source/result/key counts and
positive distributed drain/crash/orphan recovery proofs precede activation.

Before runtime persistence is enabled, integration must include counted tenant
and subject portability, verifiable erasure, retention, worker drain and late
writer fencing, paired key rotation and key inventory. The disposable schema in
`internal/testsupport/historyfixture` is for owned integration databases only;
it is not a product migration or a completed lifecycle service.

See [guardrails](guardrails.md) for G7-1, G7-3, G7-5, G7-6 and G7-7, and
[contributor conventions](../CONTRIBUTING.md) for testing and licensing.
