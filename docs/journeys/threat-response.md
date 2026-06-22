# Catch a routing or security threat

You are a security or network engineer. Something on the network looks wrong — a
route to your address space shifted, or a host is behaving oddly — and you need to
turn that hunch into one piece of evidence your team can act on. This journey
walks you from the first signal to a single correlated incident, exported to your
Security Information and Event Management ([glossary](../glossary.md)) — your
**SIEM** — with a human decision still pending.

The one thing to hold onto the whole way: probectl **watches and flags; it never
acts**. Detections are confidence-scored signals exported to your SIEM, not an
inline blocker — probectl is not an Intrusion Prevention System (**IPS**) and
never drops, terminates, or rewrites a packet. Any fix is *proposed*, then a human
approves it and carries it out in their own change process. probectl never
executes the change.

## Who this is for

- A security or network engineer triaging a possible hijack, leak, or intrusion.
- Anyone who holds the `threat.read` permission (and `audit.read` for evidence)
  and wants the cross-plane picture in one place.
- You already have data flowing — synthetic tests, flows, or BGP feeds wired up.

## Before you start

- A control plane you can reach over HTTPS, and a bearer token for a principal
  with `threat.read`. Pulling audit-grade segmentation evidence also needs
  `audit.read`.
- At least one producer feeding the planes you care about: HTTPS synthetic tests
  feed the certificate inventory; the prefix allow-list feeds BGP monitoring.
- The control plane's certificate authority file (`./ca.crt`) so `curl` trusts
  the endpoint. Border Gateway Protocol (**BGP**) and Network Detection and
  Response, lite (**NDR**-lite) are defined in the [glossary](../glossary.md).

## The path

1. **Spot the first signal.** A behavioral detection (NDR-lite) surfaces, or a
   routing event (BGP) rolls up into a correlated incident. List the threat
   detections newest-first, and pull the internet-outage context so you can tell
   "the world is broken" from "only my route moved":

   ```sh
   curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
     https://probectl.example.com/v1/threat/detections

   curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
     https://probectl.example.com/v1/outages
   ```

   You observe each detection with its kind (for example `ndr.beaconing`,
   `ioc.blocklist`, or `tls.malicious_cert`), a confidence score, the evidence, and
   the incident it is tied to. A BGP routing anomaly is not a threat detection
   itself — it surfaces as the correlated incident the detection rolls into. Powered
   by [BGP and routing monitoring](../bgp.md) and
   [security and threat](../features/security-and-threat.md).

2. **Correlate certificate and TLS posture onto the incident.** Read the Transport
   Layer Security (**TLS**) posture probectl already captured from your synthetic
   handshakes, plus any threat-intelligence matches, so the same incident carries
   certificate and intel evidence:

   ```sh
   curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
     https://probectl.example.com/v1/tls/posture
   ```

   You observe the latest posture per target, clean certificates included, each
   flagged expired, expiring, weak, or self-signed. A `"collector_running": false`
   flag tells you nothing is wired to observe TLS, so an empty page never lies.
   Powered by [security and threat](../features/security-and-threat.md).

3. **Validate segmentation with audit-grade evidence.** Check what the network
   *actually did* against the zone-pairs your policy says must not talk, and pull
   the hash-chained evidence document:

   ```sh
   curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
     https://probectl.example.com/v1/compliance/evidence
   ```

   You observe a self-verifying document where each rule reads `violation`,
   `observed_clean`, or `not_observed` — the last meaning "no visibility," not
   "blocked." Coverage caveats are baked into the signed document so they cannot
   be quietly dropped. Powered by
   [security and threat](../features/security-and-threat.md).

4. **Export the detection to your SIEM.** probectl forwards its threat signals and
   audit log into the tool your security team already runs, each event stamped
   with the tenant it was drained from and scrubbed of secrets first:

   ```sh
   export PROBECTL_SIEM_ENABLED=true
   export PROBECTL_SIEM_PRESET=splunk
   export PROBECTL_SIEM_ENDPOINT=https://splunk.example:8088/services/collector/raw
   export PROBECTL_SIEM_TOKEN=<hec-token>   # inject from your secret manager
   ```

   You observe the threat and audit events arriving in your SIEM in its native
   wire format, never dropped silently. Powered by
   [ecosystem integrations](../features/integrations.md).

5. **Review a guarded remediation proposal — human-gated.** The assistant may
   *propose* a fix grounded in the analysis; probectl never auto-acts. List the
   proposals and read the dry-run blast radius:

   ```sh
   curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
     https://probectl.example.com/v1/remediation/proposals
   ```

   You observe proposals in state `proposed`, each with a read-only dry-run sizing
   how many services, prefixes, and hosts a change would touch. A proposal whose
   blast radius exceeds the ceiling — or is unknown — cannot be approved (fail
   closed). Approving only records a signed, audited human authorization; an
   operator then carries the change out in their own process. Powered by
   [security and threat](../features/security-and-threat.md).

## You're done when

- One correlated, tenant-scoped incident pulls evidence from BGP, TLS posture,
  segmentation, and threat detections together — not five separate alerts.
- That incident is exported to your SIEM in its native format.
- A guarded remediation proposal sits in `proposed`, with a human decision still
  pending. probectl has flagged; nothing on the network has changed.

## Next

Standing up isolated tenants for many customers? See
[Stand up and isolate a tenant](./tenant-setup.md).

**Journey:** J3 · **Visits:** F6, F36, F37, F38, F43, F44, F26
