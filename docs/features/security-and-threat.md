# Security and threat

## What it is

A security camera is not a security guard who tackles intruders. It *watches*,
it *records*, and it *flags* what looks wrong so a human can decide what to do.
That is exactly what probectl's security layer is. It produces
**confidence-scored signals** from the network data the platform already
collects, attaches the evidence, and hands those signals to your security team
and your Security Information and Event Management ([SIEM](../glossary.md))
system. It is emphatically **not** an inline Intrusion Prevention System
([IPS](../glossary.md)) — it never sits in the traffic path and it **never
blocks, drops, or rewrites a packet**. It flags; a human decides.

The layer has five parts, all built on observations probectl made anyway:

- **Transport Layer Security ([TLS](../glossary.md)) and certificate
  observability** — posture problems in the certificates your synthetic tests
  already saw, including correlation against Certificate Transparency
  ([CT](../glossary.md)) logs.
- **Network Detection and Response, lite ([NDR](../glossary.md)-lite)** —
  behavioral detectors that flag suspicious *patterns* even when nothing is on a
  blocklist yet.
- **Threat-intelligence enrichment** — matching what probectl saw against public
  lists of known-bad addresses, hostnames, and certificate fingerprints.
- **Segmentation validation** — checking what your network *actually does*
  against the zones your policy says must not talk, with audit-grade evidence.
- **Guarded remediation** — the assistant may *propose* a fix; a human approves
  it; probectl itself never executes a network change.

Everything is scoped to one [tenant](../glossary.md) — one isolated customer or
organization — the outermost boundary on every signal.

## Why it exists

Network observability and network security look at the same wire. The same flow
records, the same kernel-level connection data from the extended Berkeley Packet
Filter ([eBPF](../glossary.md)), and the same TLS handshakes that tell you a
service is slow also tell you a certificate is expiring, a host is beaconing to a
command-and-control server, or traffic is crossing a wall it should not. Standing
up a *separate* product to notice that would mean re-capturing data probectl
already has — wasteful, and it doubles the load on the very services you watch.

So probectl reuses what it already observed and turns it into security
**signals**. The deliberate limit — and the reason this is safe to run inside a
production network — is that it never acts on those signals automatically. An
inline blocker that fires on a noisy public feed or a behavioral hunch will
eventually drop legitimate traffic. probectl's job is to tell a human *why* to
look; the human decides what to do, in their own change process.

## How it works

Every part of this layer follows the same shape: **reuse an observation probectl
already made, score it, attach evidence and provenance, and emit a tenant-scoped
signal** onto the incident timeline and the SIEM export. None of it re-probes a
target, and none of it sits inline.

**TLS / certificate observability.** Every time probectl's HTTPS synthetic test
makes a request, a TLS handshake happens and the server presents its
certificate. That handshake already revealed the certificate, the protocol
version, the cipher, and whether the chain verified. probectl harvests those
facts it *already captured* and analyzes them — it opens no second connection and
re-handshakes nothing (like a doctor reading the X-ray already taken, not
ordering a second scan). It flags expired certificates, certificates expiring
inside a configurable window (default 21 days), not-yet-valid and self-signed
certificates, weak keys (RSA below 2048 bits), deprecated TLS (1.0 or 1.1), weak
ciphers, and chains that failed to verify. When a finding is a renewable
certificate problem, it builds an actionable hand-off — subject, issuer, the
hostnames the certificate is valid for, serial, expiry, and the reason — so an
operator can jump straight to a renewal flow.

**Certificate Transparency correlation (opt-in).** When you enable it, probectl
correlates a certificate's serial number against CT logs — the public,
append-only registries where every legitimately issued certificate is supposed
to be recorded. A serial CT has never seen is flagged as a low-severity
*issuance anomaly* — like a person with no entry in the birth registry: not
proof of forgery, but worth a look. It is off by default because it is an
outbound fetch to a third party; when on, it fetches over validated TLS, respects
the source's rate limits, and degrades to a silent no-op if the source is down,
so it never breaks posture analysis.

**NDR-lite behavioral detection.** Threat-intel catches *known-bad by name*; this
catches *suspicious-looking behavior* — the guard who can't name the intruder but
knows nobody walks the halls at 3 a.m. trying every door handle. It runs
detectors over telemetry probectl already gathered locally — DNS lookups, flow
records, TLS posture, and the service map — for patterns like algorithmically
generated domain names, data smuggled inside DNS queries, metronome-regular
callbacks (a command-and-control heartbeat), egress volume far above a host's own
learned baseline, traffic to hostile infrastructure, and unexpected east-west
fan-out. It ships **on** because it makes **no outbound calls** — it only
processes data probectl already has.

**Threat-intel enrichment (opt-in).** This hands probectl a "wanted list" — public
feeds of known-bad addresses, hostnames, malicious server certificates, and
malicious TLS client fingerprints. probectl matches what it already saw against
that list and raises a scored, source-attributed signal per hit. Feeds are
fetched **once and shared** across tenants (the list is the same for everyone),
but each match lands on a **tenant-scoped** incident. It is **off** by default
because it makes outbound fetches; when on, every feed is fetched over TLS with
certificate validation that is never disabled, treated as untrusted input, and
cached so a down feed leaves the last-good list in place rather than emptying it.

**Segmentation validation.** Segmentation is splitting a network into zones that
must not talk — the walls auditors ask about. probectl proves them the only
honest way an observability tool can: you *declare* the forbidden zone-pairs, and
probectl validates that declaration against *observed* traffic. Crucially, it
distinguishes "we watched that path and saw only allowed traffic" from "we never
saw any traffic there" — a quiet zone is **not** proven blocked, and probectl
**never emits the word 'compliant'**; the strongest claim it makes is "no
violations observed, with the stated coverage." It exports audit-grade,
hash-chained evidence so tampering with the export is detectable.

**Guarded remediation.** The assistant can do cross-plane root-cause analysis and
simulate a topology change. This lets it take *one* more step — **propose** a fix
grounded in that analysis — and then **stop**. The lifecycle is
`proposed → approved | rejected`. There is no executor anywhere: approving a
proposal records a signed, audited human authorization that an operator then
carries out in their *own* change process; it changes a database row and writes
an audit entry, and never touches the network. It is the shape of a
building-permit office — the assistant drafts the application with an impact
study, an inspector may stamp it, and the construction crew works entirely
outside the building.

## Use it

The security signals share one tenant-scoped surface. Read TLS posture and the
threat detections through the versioned API (the `threat.read` permission), pull
audit-grade segmentation evidence (the `audit.read` permission), and — where the
guarded-remediation capability is present — review proposals through the
remediation routes.

```sh
# Certificate posture probectl already captured from your synthetic tests.
curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
  https://probectl.example.com/v1/tls/posture

# Observe: the latest posture per target, clean certs included, each flagged
# expired/expiring/weak/self-signed/etc. A "collector_running": false flag
# distinguishes "nothing wired to observe TLS" from a genuinely clean fleet, so
# an empty page never lies about why it is empty.
```

```sh
# Threat detections — NDR-lite behavior plus any threat-intel matches, newest first.
curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
  https://probectl.example.com/v1/threat/detections
```

```json
{
  "detections_running": true,
  "items": [
    {
      "kind": "ndr.beaconing",
      "entity": "10.0.4.12",
      "confidence": 78,
      "severity": "warning",
      "evidence": { "dst": "203.0.113.9:443", "jitter": 0.04, "samples": 22 },
      "incident_id": "inc_91a2"
    }
  ]
}
```

Tune the behavioral detectors as code — declarative rule files let you change any
threshold, lower a noisy rule's severity, or switch one off entirely, without a
code change. A malformed rule file fails startup on purpose, so tuning you
believe is live actually is:

```yaml
# A tuning overlay: same id replaces a default; a new id adds a detector.
rules:
  - id: ndr-beaconing-default      # same id -> REPLACES the shipped default
    version: 2                     # bump on every change
    kind: beaconing
    name: Periodic beaconing (tuned)
    severity: warning
    base_confidence: 45
    suppress: 4h                   # once an entity trips this, stay quiet 4h (a snooze)
    thresholds: { min_samples: 12, max_jitter: 0.08, min_interval_s: 10, max_interval_s: 3600 }

# Observe: after restart the tuned rule is in force; suppression means a
# persisting behavior re-raises occasionally, not on every observation. No
# rule, tuned or default, ever blocks traffic — they only raise signals.
```

For segmentation, you declare forbidden zone-pairs in a policy file and read the
verdicts and hash-chained evidence:

```sh
curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
  https://probectl.example.com/v1/compliance/evidence

# Observe: a self-verifying, hash-chained JSON document. Each rule's verdict is
# one of "violation", "observed_clean", or "not_observed" — the last meaning "we
# had no visibility," NOT "the path is blocked." Coverage caveats are baked
# inside the signed document so they cannot be quietly dropped.
```

In the web interface, all of this lives on the **Security** page: the threat
detections (with rule, confidence, and the provenance of why each fired) above
the certificate inventory (filterable, with an expiring-soon worklist), with the
segmentation results and evidence export alongside. Each detection links to its
correlated incident on the timeline.

## Pitfalls & limits

- **It is a signal, never an IPS.** This is the load-bearing limit. probectl does
  not block traffic, terminate connections, or sit inline — there is no
  enforcement path. Detections are confidence-scored, tunable, suppressible, and
  exported to your SIEM. Acting on them is your decision, made in your tooling.
- **Remediation is observe-only and human-gated.** The assistant may propose; a
  human with the approval permission may approve; probectl never executes. Every
  proposal carries a read-only **dry-run** that sizes the *blast radius* (how many
  services, prefixes, and hosts the change would touch). A proposal whose blast
  radius exceeds the configured ceiling — *or* whose blast radius is unknown —
  **cannot be approved** (fail closed), and blocked attempts are themselves
  audited. Approvals are off until an operator turns them on; until then the
  assistant still proposes and humans still review, but Approve is unavailable.
- **Behavioral detection on a public network will sometimes be wrong.** That is
  precisely why probectl flags rather than blocks. Treat detections as leads to
  triage; weigh the confidence score and the evidence; tune or suppress noisy
  rules. Suppression is a snooze, not a dismissal — the behavior is still watched.
- **"Observed" is not "intended."** A quiet zone-pair is **not** proven isolated,
  and probectl will not call your network "compliant." It generates *evidence* for
  an auditor — verdicts, coverage, and a hash-chained export — and cannot itself
  certify you against any framework; only your assessor can.
- **Threat-intel and CT correlation are opt-in outbound fetches.** They are off by
  default to honor the no-outbound-by-default stance. When enabled they fetch over
  validated TLS, treat the data as untrusted, and degrade gracefully — a down or
  rate-limited feed never breaks core function; it just leaves the last-good data
  in place. A match is a lead, not a verdict, and feeds carry stale or
  shared-infrastructure entries (a content-delivery address once used by malware,
  for instance).
- **TLS coverage is what your synthetic tests reach.** The certificate inventory
  is built from the handshakes probectl's own HTTPS client negotiated, so anything
  you point an HTTPS test at lands in the inventory; the layer does not discover
  certificates you never test.

## Reference

| Capability | Surface | Permission | Default |
|---|---|---|---|
| TLS / certificate posture | `GET /v1/tls/posture` | `threat.read` | on (synthetic-fed) |
| CT-log correlation | within posture | `threat.read` | off (opt-in) |
| Threat detections (NDR-lite + intel) | `GET /v1/threat/detections` | `threat.read` | NDR on; intel off |
| Segmentation verdicts | `GET /v1/compliance` | `threat.read` | validator on |
| Audit-grade segmentation evidence | `GET /v1/compliance/evidence` | `audit.read` | — |
| Remediation proposals (review) | `GET /v1/remediation/proposals` | `remediation.propose` | proposal-only |
| Approve a proposal (human only) | `POST /v1/remediation/proposals/{id}/approve` | `remediation.approve` | approvals off by default |

Properties you can rely on: probectl produces confidence-scored signals and
exports them to your SIEM, and it is not an inline IPS — it never blocks,
terminates, or rewrites traffic; remediation is observe-only and human-gated by
default, with a mandatory dry-run, a blast-radius ceiling that fails closed, and
full audit of propose/approve/reject/blocked actions; behavioral detection runs
locally with no outbound calls, while threat-intel and CT correlation are opt-in
outbound fetches that degrade gracefully and treat external data as untrusted;
segmentation evidence is hash-chained so tampering is detectable, and probectl
never claims "compliant"; and every signal is scoped to the caller's tenant.

## See also

Alerting and incidents (how these signals become one correlated, tenant-scoped
incident); the control plane (auth, versioning, and the `/v1` API these routes
live under); the glossary for any term above.

**Covers:** F36, F37, F38, F43, F44
