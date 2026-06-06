# eBPF TLS-capture path — plaintext exposure & redaction adjudication (D-001)

**Scope:** investigation only — no behavior change. Adjudicates the disputed
diligence finding **D-001**: one audit run claimed the eBPF payload masking
routine has an *off-by-one* (T:R8); the other claimed *no payload masking/redaction
exists at all* (O:EBPF-001). This document traces the full capture path from the
BPF ring buffer to user-space handoff and emission, cites every transformation by
`file:line`, and states which claim is correct.

Commit audited: `ee28fcd` (`main`). Capture path is built only under `-tags ebpf`
(`bpf2go`); it is **observe-only** (CLAUDE.md §7 guardrail 8) and opt-in.

---

## Verdict (TL;DR)

| Claim | Source | Adjudication |
|---|---|---|
| "**No payload redaction/masking exists**" | O:EBPF-001 | ✅ **CORRECT.** There is no content redaction anywhere on the path. The only construct containing the word "mask" is a **verifier length-bound bitmask**, not a privacy mask. |
| "**Masking routine has an off-by-one**" | T:R8 | ⚠️ **Mislabeled, but points at a real bug.** There is no masking *routine* (in the redaction sense). The cited `& (MAX_DATA-1)` is a verifier bounds-mask on the *copy length*, and it does have a **boundary defect at exactly `MAX_DATA`** (a capture-correctness + stale-memory bug — not a redaction off-by-one). |

**Net:** both audits are describing the same line — `sslsniff.bpf.c:73`. On the
privacy substance, **O:EBPF-001 is right: nothing is redacted.** T:R8 correctly
sensed a defect at that line but mischaracterized a length-bounding bitmask as a
redaction mask. Recommended `U-003` update is in the last section.

---

## Capture path (BPF ring buffer → user space → bus)

### 1. Where plaintext is captured

`internal/ebpf/bpf/sslsniff.bpf.c` — uprobes on the SSL library's plaintext API
(read *after* decrypt, write *before* encrypt; Pixie/eCapture model, no MITM):

- `SEC("uprobe/SSL_write")` → `probe_ssl_write` — **sslsniff.bpf.c:78-83** (egress plaintext, `is_read=0`).
- `SEC("uprobe/SSL_read")` + `SEC("uretprobe/SSL_read")` → `probe_ssl_read_enter` / `probe_ssl_read_exit` — **sslsniff.bpf.c:86-105** (ingress plaintext captured at *return*, when the buffer is filled, `is_read=1`).

Both funnel into `emit()` — **sslsniff.bpf.c:54-75** — which reserves a
`struct tls_chunk` (carries `data[MAX_DATA]`, `MAX_DATA = 4096`,
**sslsniff.bpf.c:23,26-34**) on the ring buffer
`tls_chunks` (`BPF_MAP_TYPE_RINGBUF`, `1<<24` = **16 MiB**, **sslsniff.bpf.c:36-39**).

### 2. Every transformation applied in the BPF program (`emit`)

```c
__u32 n = (__u32)num;
if (n > MAX_DATA)            // sslsniff.bpf.c:70-71  — clamp length to 4096
    n = MAX_DATA;
e->len = n;                  // sslsniff.bpf.c:72     — reported length
bpf_probe_read_user(&e->data, n & (MAX_DATA - 1), buf); // :73 "mask aids the verifier"
```

- The **only** transformation is a length clamp + the `n & (MAX_DATA-1)` bitmask
  on the *copy length*. This bitmask exists to let the eBPF verifier prove the
  copy stays within `data[4096]`. **It does not alter, mask, truncate, or redact
  payload content** — the bytes copied are verbatim application plaintext.
- No per-byte masking, no field redaction, no pattern scrubbing. (Repo-wide grep
  for `redact|sanitiz|scrub|mask` across `internal/ebpf/` returns only this line
  and unrelated capability-bit masks in `capability_linux.go:101,105`.)

### 3. User-space handoff

`internal/ebpf/source_live_l7_linux.go` (`//go:build linux && ebpf`, **:1**):

- `sslChunk` mirrors the C struct, incl. `Data [4096]byte` — **:42-51**.
- `L7Events` reads the ring buffer and copies the plaintext **verbatim** into the
  event: `Payload: append([]byte(nil), c.Data[:n]...)` — **:131-142** (no
  redaction). A length guard clamps `n` to `len(c.Data)` — **:127-130**.
- The raw plaintext now lives transiently in `L7Event.Payload` /
  `l7.DataEvent.Payload` (`internal/ebpf/l7/l7.go:26-30`).

### 4. Parse → metadata, payload discarded (not emitted)

- Parsers consume `DataEvent` and emit `l7.Call` — `internal/ebpf/l7/l7.go:34-44`.
  `Call` carries **only derived metadata**: `Protocol, Method, Resource, Status,
  Error, Start, Latency, ReqBytes, RespBytes`. **There is no payload/body field.**
- The raw `Payload` slice is used only for parsing and is then dropped (GC'd); it
  is **never persisted or emitted**.
- Emission: `BusEmitter.Emit` → `L7Record.toProto()` → `ebpfv1.L7Call` →
  `bus.EBPFFlowsTopic` — `internal/ebpf/emit.go:35-57,115-133`. The proto carries
  metadata only (no payload).

### 5. Residual metadata-PII exposure (separate from raw payload)

Although raw bodies are never emitted, **`Resource` is the full HTTP request-target
including the query string, stored verbatim** — `internal/ebpf/l7/http1.go:114-124`
(`parseRequestLine` returns `parts[1]` unmodified) → `call.Resource = req.path`
(`http1.go:67`). So a request to `/login?token=SECRET` emits `Resource =
"/login?token=SECRET"` to the bus, unredacted. The same applies to DNS qname and
Kafka topic. This is a *metadata-level* exposure and is **also not redacted**,
reinforcing O:EBPF-001.

---

## The boundary bug behind T:R8's "off-by-one"

`MAX_DATA = 4096`, so `MAX_DATA - 1 = 4095 = 0x0FFF`. Walking `emit()`:

| `num` (bytes to copy) | `e->len` (sslsniff.bpf.c:72) | bytes copied = `n & 4095` (:73) | Result |
|---|---|---|---|
| 1 … 4095 | n | n | ✅ correct |
| **= 4096** (or `>4096`, clamped) | **4096** | **0** | ❌ **bug** |

At exactly `MAX_DATA`, the copy length masks to **0** while `e->len` is reported as
**4096**. `bpf_ringbuf_reserve` does **not** zero the slot, and the user-space
reader trusts `c.Len` (`source_live_l7_linux.go:127-130` only clamps the *upper*
bound, it does not detect "len says 4096 but 0 copied"). Consequences:

1. **Capture loss:** a single SSL read/write of ≥4096 plaintext bytes captures **0
   bytes** of that chunk (common for large bodies).
2. **Stale-memory read / minor info-leak:** user space then reads `c.Data[:4096]`
   of **uninitialized ring-buffer memory** (whatever a previous chunk left there —
   same host/agent/tenant), and feeds it to the L7 parser.

This is a real defect at the line T:R8 flagged — but it is a **length-bitmask
boundary bug**, *not* a redaction off-by-one. No content is being masked; the
opposite — at the boundary, garbage is read in.

---

## Recommended `U-003` update (for the unified register)

- **Confirm:** no payload masking/redaction exists on the eBPF TLS-capture path
  (O:EBPF-001 upheld). The remediation is the planned **metadata-only default +
  opt-in redacted payload capture** (sprints S-G11 / S-G12), plus stripping/redacting
  the query string from `Resource` (`http1.go`).
- **Add (small, separate):** fix the `sslsniff.bpf.c:69-73` boundary so a
  full-`MAX_DATA` chunk copies `min(n, MAX_DATA)` bytes and `e->len` equals the
  bytes actually copied (e.g. clamp to `MAX_DATA-1`, or copy `n` with a verifier-safe
  bound that includes the top value), and have the user-space reader treat
  `len > copied` defensively. This closes T:R8's genuine (mislabeled) defect and
  removes the stale-memory read.
- **Reclassify D-001:** *adjudicated* — the two claims are not contradictory; they
  describe the same line from different angles. Privacy gap = "no redaction"
  (confirmed); plus a capture-correctness/stale-memory bug at the `MAX_DATA`
  boundary (confirmed).

## Mitigating context (unchanged by this finding)

- Path is **opt-in** (`-tags ebpf` build + explicit attach) and **observe-only**
  (no enforcement hook; CLAUDE.md §7 guardrail 8) — `sslsniff.bpf.c:11-15`.
- Raw bodies are **never emitted to the bus** — only derived metadata
  (`emit.go:115-133`). The exposure window for raw plaintext is the in-memory ring
  buffer + the transient parse buffer on the agent host.
- Go `crypto/tls` is **not** captured by these uprobes (it does not use libssl);
  documented in `docs/ebpf-feasibility.md §7`.

*Evidence gathered by source review at `ee28fcd`. The BPF program could not be
loaded/executed in the audit sandbox (no `CAP_BPF`); the boundary analysis is from
the C source and is deterministic.*
