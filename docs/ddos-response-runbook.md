# DDoS response runbook

## Configure short-window detection

Select a pinned saved flow view in the DDoS query alert. The console defaults
new rules to five-second observation windows with a five-second minimum
between reads. You can select ten seconds or the saved view's supported longer
window. Set volume and observed-record floors for the window you choose. Each
episode requires two adjacent completed windows. The fast scheduler checks for
due short-window rules every two seconds on the existing alert leader,
independently of the ordinary alert pass. In the pooled control database,
the tenant-scoped due index covers enabled five- and ten-second DDoS rules.
Configure export and collection frequently enough to populate both windows.
After an evaluation has established a clock, a missed short-window pair stays eligible
through the following completed window. If its observations arrive in time,
the episode cites their original clocks. Longer export delays and incomplete
evidence can still delay or prevent an alert.

Short-window admission checks whether the finding still qualifies after
setting aside reports with a known exporter start before the current window.
If those reports supplied necessary traffic or application evidence, the
assessment reports timing coverage as unknown. Quiet totals also leave
coverage unknown when the contained reports are absent, lack a required
exporter or its reference sampling rates, or fall below the configured
record minimum for a sampled group. The rule keeps its previous episode
state until observations can establish recovery. Reports with only fallback
timestamps and older records still contribute to their end-time windows.
The receipt retains the end-time totals from the pinned view.

Short-window comparisons need the same observed exporters and their reported
sampling rates in the current and reference windows. This includes exporters
with a sampling rate of one. A change leaves coverage unknown and keeps the
prior episode and evaluation clock. Check for late exports or a change in
collection before interpreting the totals. An empty contribution can also
mean an edge carried no traffic for this view. List required exporters when
the rule should also refuse comparisons that omit the same edge in both
windows.

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
growth must explain both byte and packet growth within 25% on the selected TCP
port. If traffic elsewhere on the host increased, the same comparison applies
to that host-wide counter. Suppression also requires at most 1%
unsuccessful requests and a p95 duration no more than 1.5 times the
reference. During degraded service, compare the increase in all completed
requests, including errors, with the increases in listener bytes and
packets. Apply the 25% tolerance to the increases relative to the
reference window. When demand grew in proportion to both counters, an
overloaded flash crowd and HTTP attack pressure remain possible. The
application assessment reports
inconclusive overload. The generic rule defers evaluation and keeps its
previous state.
Degradation can corroborate pressure when the listener independently
meets the volume and growth thresholds and completed demand fails to
explain the increase. Traffic outside the listener can qualify on its own
volume and growth. When neither component reaches those thresholds,
degraded responses leave the host-wide increase ambiguous. Missing,
full-page or ambiguous application observations leave the bound generic
pressure unevaluated for episode admission. The preview calls out unavailable
application evidence while showing the measured flow pressure. Ordinary OTLP
ingest masks IP addresses before storing spans. A masked local address cannot
establish this exact socket comparison. Confirm the preview has comparable
application counts before relying on application corroboration.

A SYN or UDP service vector must
meet the configured share of current packets and the growth threshold against
its own historical packet count. If aggregate traffic fails the volume
comparison, the measured vector must also reach the packet floor by itself.
A sampled SYN or UDP service vector in a short window must still qualify
after excluding its current packet estimates from exporter and rate groups
with fewer original vector records than the configured minimum. The share
uses the complete packet total. If the remaining observations cannot support
the vector, the window is unavailable and the saved rule retains its state.
For short windows, mixed network evidence can qualify when two or more
independent vectors each clear the packet floor and grow from their own
historical counts. Together they must clear the share threshold and account
for more of the packet population than the historical upper bound. A
single qualifying vector takes precedence. Mixed pressure is tentative
because flow data identifies observed packet characteristics.
A historical TCP record with zero flags or a UDP record without a source port
may belong to the vector. A record with missing transport may belong to either
vector. The current observed vector must exceed that historical upper bound
by the configured growth threshold. Current classification gaps can also
leave a short window inconclusive. This happens when unclassified packets
could account for network pressure at the configured growth, packet and
share thresholds. The existing episode retains its clock until the
detector can evaluate comparable coverage again. HTTP requests
are assigned by their start time and can count after completion even when
they cross a window boundary.
[OpenTelemetry HTTP span conventions](https://opentelemetry.io/docs/specs/semconv/http/http-spans/#http-server-span)

For sampled tracing, use locally rooted HTTP server spans with consistent
OpenTelemetry probability metadata. Different known thresholds, or a mix of
known and unknown thresholds, leave generic application pressure unevaluated.
Two windows with no metadata still compare their recorded requests. The
detector cannot infer a sampling change in those windows from the trace
counts alone. Separately qualifying network evidence continues to use its
original admission rules. [OpenTelemetry probability metadata](https://opentelemetry.io/docs/specs/otel/trace/tracestate-handling/) · [Synthetic benchmark](ddos-detection-benchmark.md)

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
   counters. Window-average rates divide the counters of reports ending in
   each window by that window's duration. The source addresses describe
   observations from the selected view. Treat a reflector association as
   evidence about the observed UDP service. Use independent evidence to
   establish traffic origin.

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
