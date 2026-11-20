# Regional ISP subscriber usage

Assign an existing tenant prefix tag to each subscriber’s canonical prefixes
in the correct routing context. A manual assignment or a reviewed IPAM tag
import can supply the subscriber value. Bind the flow exporter to that same
context. Choose a single-window saved Flow Explorer view whose collectors
represent the subscriber’s accounting points.

Open **Subscriber usage** on that view. Choose the subscriber prefix tag and
enter its exact value. The report records the current tag revision and the
observed interval. Use an interval wholly covered by the current explicit
assignments and exporter bindings. A changed assignment requires an interval
after the change. The report needs complete raw source groups and preserves
integer counter precision.

Download means the destination matched the subscriber. Upload means the source
matched. A record with both ends in the subscriber is counted once under
**Within subscriber**. The remote service columns come from the retained FX-8
IP-range attribution of the opposite endpoint. Unknown and ambiguous service
attribution remain visible. Classification groups outside the top 20 are
included in the other-services total.

To include latency, assign the same tag and subscriber value to each enabled
ICMP test in its existing routing context. The test, its measuring agent and
its registered path must have current bindings in one of the saved view's
flow contexts. Choose **Include original ICMP latency**. Reading the result
requires `metrics.read`, `test.read` and `entities.read` for those sources.
Each row reports the number, exact sum, minimum, maximum and arithmetic mean
of complete original round-trip measurements in that window. A fractional
mean is an exact fraction of a nanosecond. Rows show partial or unavailable
coverage when the original measurements cannot support a full summary.

Choose **Include a DDoS incident** to link one retained observation to a
subscriber. Select the routing context, incident and DDoS observation.
Choose a usage interval that contains both qualifying observation windows.
The protected prefix must fit inside an explicit subscriber assignment in
that context. A conflicting overlapping assignment or incomplete original
exporter evidence prevents the link. Incident and alert read permissions
apply to the context. Audit readers and authorized remediation reviewers can
also see the recorded decisions for that context.

The equivalent CLI command is `probectl explorer subscriber-usage <view-id>
--body-file request.json`. Provide the exact saved view `version`, `tag_id`,
`tag_key` and `subscriber`. For a relative saved view, an optional UTC `end`
pins its observation clock. Set `include_latency` to `true` for the optional
latency evidence. For a DDoS link, include an `incident` object with
`context_id`, `incident_id`, `rule_id` and `receipt_fingerprint` from the
selected observation. Equivalent requests are served at
`POST /v1/explorer/flow-views/{id}/subscriber-usage`.

## POP and tower capacity

Apply the same effective interface tag and value to every link in a POP or
tower. In **Capacity planning**, open **Measured capacity forecast** and
choose **Tagged circuit**. Select **Point of presence** or **Tower** under
**Capacity group**. Enter the tag ID, its exact value, the training interval,
forecast horizon and a group operating threshold.

For each current member, supply its canonical context and interface IDs, the
physical counter bound and its own operating threshold. The physical bound
validates the counter measurements. The operating threshold sets the point at
which the forecast flags that link. The report records the tag revision and
shows the earliest projected constraint among members with complete forecasts.
A link with gaps remains visible with its sample coverage. The group rate and
utilization fraction appear when every member contributes to the final aligned
measurement interval.

Run the same report through `probectl capacity forecast --body-file request.json`
or `POST /v1/flows/capacity/forecast`. Use the regular circuit target and add
`group.kind` of `pop` or `tower`. Set `group.thresholds` to one
`context_id`, `interface_id` and exact decimal `capacity_bps` per member.
The normal `physical_bounds` remain required separately.

## Upstream SLA evidence

In **Capacity planning**, use **Recorded terms** to select the upstream
agreement that names the tagged circuit or its actual transit interface.
Select the exact recorded revision and the carrier's completed billing period.
Open **Carrier claim draft** for the original scoped measures, coverage and
the resulting draft. The claim uses the agreement's billing calendar. The
capacity forecast retains its separately selected training window.

Use the same agreement ID, revision and billing period in a dashboard's
`carrier_claim.selections` to produce a signed evidence pack. The existing
carrier report path rechecks current source and financial access and carries
the original measures with the recorded agreement. A reviewer can verify the
pack offline. [Signed carrier SLA claim reports](dashboard-reporting.md#signed-carrier-sla-claim-reports-preview)

## Billing and operations exchange previews

Choose Splynx, Sonar or UISP under **ISP exchange preview**. Enter the stable
external service, account or subscriber identifier from your vendor export.
Run the subscriber report and download the CSV. Each file contains one usage
row with exact upload, download, within-subscriber and total counters, the
observation bounds, saved view revision and tag revision. The first column is
`service_id` for Splynx, `account_id` for Sonar and `subscriber_id` for UISP.

Use the CSV to check your column and identifier mapping in the vendor sandbox
before billing. These previews are generated locally from the scoped report.
The source documents describe the identifiers and exports available for
reconciliation. [Splynx reports](https://splynx.com/blog/system-administration/reports-in-splynx-overview-and-how-to-guide/) · [Sonar account data](https://docs.sonar.expert/accounts/account-view-overview) · [UISP data management](https://help.uisp.com/hc/en-us/articles/22590983111447-UISP-Security-Data-Management)

For the API or CLI, add `exchange` to the existing subscriber report request
with `target` and `external_id`. The response's `exchange.csv` is the same
file content available in the console.
