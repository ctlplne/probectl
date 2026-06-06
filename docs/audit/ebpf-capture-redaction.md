# eBPF TLS-capture path: redaction adjudication (D-001)

**Task:** A1 (unified diligence register). **Finding adjudicated:** D-001 — "masking off-by-one"
(independent run, T:R8) vs "no masking exists at all" (internal run, O:EBPF-001).
**Scope:** investigation only; no behavior changes. Informs U-003 / task C13.

## Verdict

**Both audits looked at the same line and described different properties of it. On the
substantive question — does any payload redaction exist — O:EBPF-001 is correct: none exists.**

- **O:EBPF-001 ("no payload redaction exists") — CORRECT.** There is no content masking,
  redaction, filtering, or sanitization anywhere on the eBPF TLS-capture path, from the kernel
  probe to the userspace parsers. The only privacy property is structural: the bus schema
  (`proto/probectl/ebpf/v1/ebpf.proto:69–89`, `message L7Call`) has no payload/body field, so raw
  plaintext cannot leave the agent process via the emit path.
- **T:R8 ("masking off-by-one") — real code artifact, mischaracterized.** The "masking routine"
  is `internal/ebpf/bpf/sslsniff.bpf.c:73`:
  `bpf_probe_read_user(&e->data, n & (MAX_DATA - 1), buf); // mask aids the verifier`.
  This is a **copy-length mask for the BPF verifier**, not payload masking. It does contain a
  genuine boundary bug (below), so the off-by-one observation is accurate — but it is a
  capture-fidelity/data-integrity bug, not evidence that redaction exists.
- **The two claims are not mutually exclusive once "masking" is disambiguated.** D-001 resolves:
  do not strike T:R8's bug — fold it into U-003/C13 scope. **U-003 stands as written (Critical:
  TLS plaintext captured with no payload redaction or consent framework), unchanged in substance.**

Version skew is ruled out: `git log --follow internal/ebpf/bpf/sslsniff.bpf.c` shows exactly two
commits (`0806e65` introduction, `8f3e173` rename-only rebrand). Both audit runs saw this code.

## The length-mask bug (what T:R8 actually found)

```c
// internal/ebpf/bpf/sslsniff.bpf.c:69–73
__u32 n = (__u32)num;
if (n > MAX_DATA)            // :70–71 clamp allows n == 4096 (MAX_DATA, :23)
    n = MAX_DATA;
e->len = n;                  // :72 declared length: up to 4096
bpf_probe_read_user(&e->data, n & (MAX_DATA - 1), buf);  // :73 mask allows at most 4095
```

The clamp permits `n == 4096` but the mask `n & 4095` evaluates to **0** at exactly that value.
For every SSL_write/SSL_read chunk **≥ 4096 bytes**:

1. **Zero payload bytes are copied**, while `e->len` still claims 4096.
2. Userspace (`source_live_l7_linux.go:127–141`) trusts `c.Len` and copies
   `c.Data[:4096]` — **stale ring-buffer memory** (`bpf_ringbuf_reserve` does not zero reused
   pages), i.e. typically bytes of an *earlier* TLS chunk, possibly from a different process,
   delivered as if it were this connection's payload.
3. Effects are confined to the agent process: misattributed plaintext feeds the L7 parsers
   (wrong-connection contamination in memory) and large-chunk traffic parses as garbage, so L7
   calls are silently undercounted. Nothing payload-shaped reaches the bus either way.

The common case (chunks < 4096 — e.g. typical request headers) copies correctly and in full, so
this bug does **not** reduce the privacy exposure of U-003. Related unchecked edge: the
`bpf_probe_read_user` return value is ignored (failure → same stale-data delivery).

## Full capture path (plaintext lifetime, every transformation)

| # | Stage | Location | What happens to payload |
|---|-------|----------|-------------------------|
| 1 | Capture (kernel) | `internal/ebpf/bpf/sslsniff.bpf.c:78–105` | Uprobes on `SSL_write` (entry) + `SSL_read` (uretprobe; args stashed at entry :87–93). Raw application plaintext read from user memory before encryption / after decryption. |
| 2 | Truncate + ship | `sslsniff.bpf.c:54–75` (`emit`) | Only transformation in kernel: length clamp to 4096 (:70–71) + verifier length mask (:73, buggy at the boundary). Chunk (pid, tid, SSL* as conn key, direction, len, up to 4096 raw bytes) submitted to `tls_chunks` ring buffer (16 MiB, :36–39). **No content inspection or masking.** |
| 3 | Userspace handoff | `internal/ebpf/source_live_l7_linux.go:105–152` | Ring read → `binary.Read` into `sslChunk` (:118–122) → `n = min(c.Len, 4096)` (:127–130) → payload copied **verbatim** into `L7Event.Data.Payload` (:131–143). **No filtering** (no grep hit for redact/sanitize/filter/strip on this path). |
| 4 | Routing | `internal/ebpf/runtime.go:166–195` (`observeL7`) | Connection metadata cached per ConnID; raw `DataEvent` forwarded to `l7.Manager.OnData` (`internal/ebpf/l7/tracker.go:65–72`). |
| 5 | Detection | `internal/ebpf/l7/detect.go:18–36` | First request bytes prefix-matched (HTTP/1 methods, HTTP/2 preface) + port hints. Reads payload; transforms nothing. |
| 6 | Parse + retain | `internal/ebpf/l7/http1.go:31,46` · `http2.go:58,68` · `dns.go` · `kafka.go` | Raw payload **appended to unbounded per-connection `reqBuf`/`respBuf` in agent heap** until complete messages are scanned. Parsers *extract* metadata into `l7.Call` (`l7/l7.go:34–44`): protocol, method, resource, status, timings, byte counts. **Plaintext lifetime ends here** (consumed buffers trimmed; GC). |
| 7 | Aggregate | `internal/ebpf/aggregate.go:51–66` | `L7Record` (metadata only) queued; no payload field exists past this point. |
| 8 | Emit (bus) | `internal/ebpf/emit.go:115–133` (`toProto`) → `:35–58` | Marshals `L7Call` proto — **metadata only; the schema has no payload/body field** (`proto/probectl/ebpf/v1/ebpf.proto:69–89`). Published to `probectl.ebpf.flows`, tenant-keyed. |
| 9 | Consume + store | `internal/control/ndr.go:160` · `topologyapi.go:161` · `complianceapi.go:122` | Control-plane consumers unmarshal `FlowBatch` and persist/observe flow + edge + L7-call **metadata** (threat engine, topology store, compliance). Raw payload structurally cannot arrive here. |

`l4flow.bpf.c` (the other BPF program) captures L3/L4 flow tuples only — no payload.

## Complete masking/redaction inventory

Repo-wide search for masking on the eBPF path finds exactly two matches, neither payload redaction:

- `internal/ebpf/bpf/sslsniff.bpf.c:73` — the verifier **length** mask above.
- `internal/ebpf/capability_linux.go:101–105` — `CapEff` **capability bitmask** parsing
  (the "capability bitmasks" the coordinator grep found; unrelated to payload).

`ee/governance/governance.go` implements classification/redaction **policy for a different data
path** (per-tenant governance: `redact_from`/`redact_export` on exports, provider plane). It is
never consulted by `internal/ebpf` — consistent with O:RED-007's note.

## Supporting observations (for U-003 / C13 scope)

- **Capture is on by default, no consent gate:** `internal/ebpf/runtime.go:68` attaches the live
  TLS-uprobe source unconditionally whenever the agent is built with `-tags ebpf` and the host
  has a BTF kernel, CAP_BPF, and libssl at `/usr/lib/x86_64-linux-gnu/libssl.so.3` (or
  `PROBECTL_EBPF_LIBSSL`, `source_live_l7_linux.go:168–173`). `internal/ebpf/config.go` has **no
  key to disable L7/TLS capture** (`L7FixturePath` only substitutes a replay source).
- Emitted *metadata* is not risk-free: `resource` carries the verbatim HTTP request-target
  (`l7/http1.go:114–124`) — query strings can embed credentials — and DNS qnames. C13's redaction
  layer should consider this.
- `Config.RingBufferBytes` is documented but unwired: `loadSslsniffObjects(&s.objs, nil)`
  (`source_live_l7_linux.go:58`) ignores it; ring size is hardcoded `1 << 24` in the C (:38).
  (Corroborates the internal run's side-finding.)
- The observe-only guardrail is enforced by `internal/ebpf/observeonly_test.go`
  (`TestBPFProgramsAreObserveOnly`) — preserved, untouched by this investigation.

## Remediation status (C13)

Closed by C13 (U-003): live capture is now **default-OFF** behind
`l7_capture_enabled` + `l7_capture_consent_tenant` (exact-match per-tenant
consent; `internal/ebpf/l7policy.go`), payload bodies are **zeroed in place**
at the `source_live_l7_linux.go` handoff before any parser/buffer retention
(`RedactPayload`, default `headers` mode), and the D-001 length-mask bug is
fixed (`sslsniff.bpf.c` clamps to `MAX_DATA-1`, so the verifier mask is the
identity and the stale-ring-memory ship is gone). Tests prove capture stays
off without consent and no raw body byte survives the boundary.

## Recommended register updates

- **D-001 → resolved.** Adjudication: "their" off-by-one is a real length-clamp bug at
  `sslsniff.bpf.c:73` (capture fidelity + stale-memory misattribution), not payload masking;
  "our" no-redaction claim is correct. Fold the length-clamp fix into C13 (it sits exactly at the
  boundary where C13 adds the redaction layer).
- **U-003 → unchanged** (Critical stands). Acceptance criteria already cover the fix direction:
  default-off, per-tenant consent, redaction before user-space retention, test that no raw
  payload persists.
