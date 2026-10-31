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

Pending-state database failures remain retryable storage errors. They are
checked separately from current operational authority and never enter the
authorization-denial normalizer. An unavailable state read cannot enter the
maintenance callback or become proof of a permanent authority loss.

Source callbacks now register a separate audited tenant/owner activity row
before opening private data. The record contains operation/instance IDs and an
operation epoch, not source, credentials or grants. Current journal operations
under that context require its exact active registration. A restrictive DELETE
policy prevents active records from disappearing under lifecycle owner binding;
startup and silo guard plans enforce it and deny table-wide truncation. Records
have no job/message/user cascade. Final registry tombstoning also needs explicit
activity zero-count integration.

Only the process's private reference can acknowledge its own actual callback,
nested work and buffer drain. Retirement and audit are atomic; offboarded/fenced
tenants use the separate provider lifecycle stream instead of appending tenant
audit after its fence. Failed acknowledgements retain source-free local retry
references with bounded same-tenant backpressure. Independently authorized
retries cannot adopt another instance's source or creator credential. The exact
pending-intent barrier checks durable unacknowledged activity before destructive
callbacks, even if the original SQL family lease was lost.

An unknown crashed instance remains pending after its session ends, after job
cancellation and regardless of age. The owned subprocess crash test proves this
refusal, not a completed product crash-recovery procedure. Positive orphan
instance fencing, complete artifact/key counts and full lifecycle/public service
integration remain mandatory before persistence is enabled.

Full-tenant `Engine.Erase` now detects the routed history family and refuses
partial or unknown schemas. Independent lifecycle authority commits or resumes
the exact internal full-tenant intent, cancels job metadata in bounded batches,
and verifies durable actual drain before the canonical global offboarding fence.
Only then can it purge terminal jobs followed by leaf messages across all owners
in this tenant. The app role retains FORCE tenant/owner RLS; only global registry
metadata and the separate lifecycle audit use the provider role. Private source
SELECT, creator credentials and decryption keys are unnecessary for this purge.

Every batch reconciles before/deleted/remaining counts and commits mandatory
provider audit with its deletes. Leaf selection prevents an unbounded ancestry
cascade from bypassing the row resource. Audit failure, no progress with rows
remaining, active work or a mismatched plan keeps erasure incomplete before
other stores or keys are deleted. Exact retries resume behind the global fence.
The attestation reports message/job counts and verified operation drain; final
canonical PostgreSQL teardown removes the epoch behind that fence. An absent
history family preserves ordinary erasure. This does not complete subject
matching, portability, retention, key inventory/rotation, orphan recovery or
future retained-result lifecycle requirements.

Before runtime persistence is enabled, integration must include counted tenant
and subject portability, verifiable erasure, retention, worker drain and late
writer fencing, paired key rotation and key inventory. The disposable schema in
`testsupport.InstallFlowHistoryFixture` is for owned integration databases only;
it is not a product migration or a completed lifecycle service.

See [guardrails](guardrails.md) for G7-1, G7-3, G7-5, G7-6 and G7-7, and
[contributor conventions](../CONTRIBUTING.md) for testing and licensing.

## Controlled tenant portability reader (private foundation)

`Journal.WithTenantExport` requires an independent current privacy-operation
checker and a current record/privacy checker. It admits a Principal-free
maintenance context only; historical creator credentials and grants establish
ciphertext integrity and never authorize the export. Ordinary owner reads keep
their exact owner and conversation checks. Partial/unknown schema refuses.

The reader registers audited durable activity before private source and keeps
it live through the complete archive/output callback, nested readers and
current-authority watcher. Cancellation or loss of the SQL family lease does
not acknowledge a writer that has not actually returned. Failed retirement
retains a private source-free retry reference; unknown crashed instances stay
pending. No time-based or missing-lock success is inferred.

Messages stream in positive row/byte-bounded tenant keyset pages across owners,
with complete immutable ancestor metadata checked before source. Decoded JSONL
preserves message metadata and exact JSON numbers; encryption envelopes,
creator credential references, permission snapshots and control keys are not
portable. There is no total history/turn cap. The callback must consume the
single-use stream successfully; ignoring its error cannot report success.

This is a private storage primitive, not enabled public conversation storage.
The real initiating-credential/Engine composition, honest HTTP failures,
subject portability/erasure, retention, paired key lifecycle, positive orphan
fencing and retained native results remain required before activation.


## Immutable subject-erasure plans (private foundation)

`Codec.PrepareSubjectErasurePlan` freezes a trimmed subject and normalized,
sorted aliases already validated by an independently authorized lifecycle
operation. The private selector includes random salt; its digest binds an
operation without exposing low-entropy subject guesses through bookkeeping.
The plan refuses public JSON and formatting and grants no message access.

`Journal.BeginSubjectInvalidation` atomically stores its encrypted selector,
exact operation ID, purpose, binding, generation advance and mandatory audit.
Tenant encryption authenticates the tenant, operation, purpose and binding;
keyless plaintext is refused. The disposable fixture keeps this ciphertext in
`flow_conversation_epochs.operation_plan`. It is not a product migration.

`Journal.ResumeSubjectInvalidation` requires the exact internal operation UUID
and fresh independent authority before decrypting and again after verifying the
canonical selector and digest. A restart uses those frozen aliases rather than
re-resolving a changed directory. Different plans and corrupt, oversized,
missing or unavailable-key envelopes refuse. An exact retry preserves one
intent and audit event; audit failure rolls back the complete transition.

These methods neither admit matching message source nor prove actual drain,
delete records or clear the refusal marker. Complete subject matching and
erasure, retention, key inventory/rewrap including the plan envelope, and
positive orphan recovery remain required before private persistence is enabled.


## Pending subject matching source (private foundation)

Subject matching uses a separate internal source context for the exact pending
subject-erasure operation. It requires independently current lifecycle
authority and strong durable drain, then atomically rechecks zero activity,
registers the actual operation and appends mandatory audit under the canonical
writer, audit and epoch lock order. Losing the family SQL lease cannot admit
another source or destructive mutation while this registration is live.

The approved encrypted alias plan opens after registration. Current authority
and the exact intent are checked during source use; ordinary owner history,
active-generation export and general maintenance cannot borrow this context.
The matching callback and nested readers release their actual buffers before
acknowledgement. Returning early or canceling a context does not imply drain.
The first nested-reader failure refuses success even if its caller ignores it.
Panic unwinding also joins actual readers and the watcher before source-free
retirement; failed acknowledgement retains the existing private retry.

This is admission for destructive matching of all stored data, including
expired ciphertext, and grants no source-return API or completion authority.
The bounded semantic matcher, native document validation, complete descendant
selection, counted job/leaf deletion, all-plane receipts and self-erasure,
retention, key lifecycle and positive orphan recovery remain required before
private persistence is enabled. No product migration is introduced here.
