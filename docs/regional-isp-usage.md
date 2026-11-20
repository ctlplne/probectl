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

The equivalent CLI command is `probectl explorer subscriber-usage <view-id>
--body-file request.json`. Provide the exact saved view `version`, `tag_id`,
`tag_key` and `subscriber`. For a relative saved view, an optional UTC `end`
pins its observation clock. Set `include_latency` to `true` for the optional
latency evidence. Equivalent requests are served at
`POST /v1/explorer/flow-views/{id}/subscriber-usage`.
