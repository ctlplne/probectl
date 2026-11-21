# DDoS response runbook

## Configure short-window detection

Select a pinned saved flow view and choose a five- or ten-second observation
window in the DDoS query alert. Set volume and observed-record floors for
that window length. Each episode requires two adjacent completed windows. The
fast scheduler checks for due short-window rules every two seconds on the
existing alert leader, independently of the ordinary alert pass. Configure
export and collection frequently enough to populate both windows. After an
evaluation has established a clock, a missed short-window pair stays eligible
through the following completed window. If its observations arrive in time,
the episode cites their original clocks. Longer export delays and incomplete
evidence can still delay or prevent an alert.

Select **Representative week from the last four** when one unusual week could
distort the comparison. The view must retain raw flow coverage across the
four UTC weeks, with populated windows in at least three. The assessment
selects one original week closest to the median byte and packet counts.
Scheduled episodes use two adjacent windows from that same original week.
The receipt retains the chosen clocks for incident reports and routing review.
The default is **Same time last week**.

For generic ingress pressure on one host, enter its HTTP telemetry service
name and port. The application comparison requires current `metrics.read`
access and HTTP server spans with `network.local.address` set to the canonical
protected IP, `network.local.port` set to the selected port, and
`network.transport` set to `tcp`. Enable these attributes at the ingress
listener where the flow's destination matches the observation. Applications
behind a proxy or NAT need telemetry from the listener at the same network
boundary as the selected flow view. `server.address` and `server.port` can
describe the HTTP authority supplied in request headers. A bounded observation
needs at least 20 completed requests per window. The current successful-request
growth must explain both byte and packet growth within 25% on the selected TCP port
and across the protected host. Suppression also requires at most 1%
unsuccessful requests and a p95 duration no more than 1.5 times the
reference. Degraded HTTP responses corroborate pressure only when traffic
on the selected listener independently meets the configured volume and
growth thresholds. Traffic outside the listener can qualify on its own
volume and growth. When neither component reaches those thresholds,
degraded responses leave the host-wide increase ambiguous. Missing,
full-page or ambiguous application observations leave the bound generic
pressure unevaluated for episode admission. Explicit network pressure
continues through its own flow
evidence. HTTP requests are assigned by their start time and can count after
completion even when they cross a window boundary. [OpenTelemetry HTTP span conventions](https://opentelemetry.io/docs/specs/semconv/http/http-spans/#http-server-span) · [Synthetic benchmark](ddos-detection-benchmark.md)

## Confirm the incident

1. Open the incident for the customer you are assisting. Check the tenant
   indicator and the protected prefix before reviewing any traffic or
   decision. Open **Show original traffic evidence**.
2. Record the vector, its confidence, and the two completed observation
   windows. Use **Open DDoS incident report** for the highest window-average
   bit and packet rates, the observed duration, and the leading observed
   source addresses. Export the typed report through the incident CLI if
   you need to retain it with the customer's case.
3. Check source coverage and sampling before comparing rates with device
   counters. The report's source addresses describe observations from
   the selected view. A reflector association alone cannot establish
   who originated the activity.

## Review a response

1. In the traffic receipt, select **Prepare routing proposal**. Choose the
   configured routing context and protected prefix, an unfiltered
   whole-prefix flow view, and a known benign source prefix. Use the
   context's agreed RTBH community or an exact FlowSpec match.
2. Preview the collateral. For FlowSpec, compare **Whole protected
   prefix** with **Traffic matching the proposal**. Confirm the known
   benign packet count, the unclassified portion, and the proposed
   address scope. Set the maximum that this response is allowed to affect.
3. File the exact preview. A different active tenant account opens the
   review under **Admin → AI remediation proposals**. For a FlowSpec
   review, check the device's documented profile and its reported free
   entries before accepting the proposed rule. Record the approval from
   that interactive session.
4. Carry the approved plan into the customer's established network
   change process. Record the device or provider acknowledgement and
   the time it was observed. Use those observations to distinguish an
   approved plan, a route accepted in the control plane and an active
   forwarding action.

## Use a published transit RTBH template

Under **Published transit template**, choose the exact transit product
and BGP session ASN. Confirm the customer has blackholing enabled
on that session, verify the allowed prefix, and check the provider's
published propagation scope. The review pins the template version,
community, destination prefix and exact observed collateral. A different
interactive tenant user still approves the same measured proposal.

The catalog includes [Arelion](https://www.arelion.com/our-network/bgp-routing/bgp-communities),
[GTT](https://www.gtt.net/services/managed-networking/internet/ip-transit/bgp-communities/),
[Hurricane Electric](https://www.he.net/adm/blackhole.html),
[Inter.link](https://inter.link/knowledgebase/bgp-communities/),
[Lumen Internet On-Demand](https://docs.lumen.com/intelligent-internet/adding-intelligent-internet-with-bgp-routing/),
[NTT DATA Global IP Network](https://www.gin.ntt.net/support-center/policies-procedures/routing/)
and [RETN](https://retn.net/products/ddos-protection).
Some providers enable the feature per session or service. Inter.link's
global template can propagate to peers and other upstreams.

Run `probectl remediation rtbh-templates` to read the current catalog from
the authorized control plane. Use the exact community and
`upstream_template_id` from its response on the existing preview call.
When a published template does not match your agreement, use the community
from your verified routing policy.

## Close and retain evidence

1. Confirm removal through the same authorized route or provider scope.
   Record the observed removal time and check that related traffic and
   service signals recovered.
2. Retain the exact report and recorded approvals in the customer's
   incident record. If the collector or source view was unavailable,
   record the coverage gap and the last complete observation time.
3. Review the benign packet limit and detection policy with the customer
   after the incident, using the recorded observations and phase changes.

## Queue tenant report packs

Open the exact DDoS incident report and select **Save incident report**. This
creates a private report definition tied to the tenant’s incident and receipt.
Open that definition in Dashboards. Use **Generate CSV** or **Generate PDF**
for an immediate pack. Current access to the underlying data is checked again
at generation and download. Authorized reviewers can include the recorded
mitigation decisions in an immediate pack.

To let an MSP operator queue a run, create a report schedule and enable
**Allow provider-triggered DDoS incident reports for this schedule**. In the
provider console, select **DDoS incident reports**, select the tenant or tenants,
and choose **Queue DDoS reports**. The provider sees operation counts. The
normal tenant worker generates the pack with the schedule owner's current
read-only authority and delivers to the configured tenant destination. A
current tenant audit-read grant lets the worker include the recorded decisions. The tenant can revoke
the consent on its schedule. Runs need the retained receipt and its original
observations to remain readable.

The provider CLI uses `probectl provider ddos-reports <tenant-id>` with one
body `request_id` per operation and `probectl provider ddos-report-progress
<tenant-id> <request-id>` to read the counts. Reuse the request ID to retry.

The [synthetic detection benchmark](ddos-detection-benchmark.md) records the
replay corpus, alert outcomes and measurement limits.
