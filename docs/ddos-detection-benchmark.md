# Synthetic DDoS detection benchmark

Run from a clean probectl checkout with the Go toolchain in `go.mod`.

```sh
git rev-parse HEAD
go version
go env GOOS GOARCH
go test -count=1 -v -run '^TestSyntheticDDoS(DetectionBenchmark|ProtectedServiceSensitivity|ReplayExport)$' ./internal/control
GOMAXPROCS=2 go test -run '^$' -bench '^BenchmarkSyntheticDDoSDetection$' -benchmem -count=5 ./internal/control
```

The version-two corpus contains 416 trials from 26 labeled scenario families.
A deterministic grid varies the starting offset, volumes, observed counts,
sampling ratio, number of destinations and HTTP response evidence. The fixture
uses documentation IPv4 space. Tests materialize in-memory flow rows and
reduced application observations. Replay runs entirely in process against
that synthetic telemetry. [Fixture and independent label oracle](../internal/control/flow_ddos_benchmark_test.go)

Each trial evaluates two adjacent five-second windows against the same UTC
clocks from the previous week. The detector uses the same projection, traffic
classification, application comparison and episode decision as saved rule
evaluation. Modeled onset covers time from the synthetic event's start to
the second qualifying close, including up to four seconds before the first
full window. The benchmark command measures in-process allocation and runtime
for a complete corpus. Exporter flush, ingestion, storage reads, scheduler
queueing and delivery add their own time in deployment.

## Export the synthetic inputs

Run the benchmark with a new output directory to compare detectors against
the same observations.

```sh
replay_parent="$(mktemp -d)"
PROBECTL_TEST_DDOS_CORPUS_DIR="$replay_parent/replay" \
  go test -count=1 -v -run '^TestSyntheticDDoSDetectionBenchmark$' ./internal/control
shasum -a 256 "$replay_parent/replay/inputs.json"
```

`inputs.json` contains all 416 cases under numeric IDs. Each case includes
its protected scope, modeled start, and two ordered pairs of reference and
current windows. Windows have UTC bounds, a flow completeness flag, grouped
flow metrics and any bound application's HTTP observations. Bytes and packets
are corrected flow totals and `flows:total` counts original records. HTTP span
durations are in nanoseconds. Both data types are synthetic.

Give the same input file to each evaluator. Keep `ground-truth.json` with the
scorer. It maps the IDs to scenario names and positive or negative labels and
binds them to the SHA-256 of the input file. Record each product's configuration,
unsupported input, abstentions and decision clock before scoring. The export
contains flow aggregates and spans for offline comparison. Measuring an
exporter or product end to end requires its separate lab replay.

The `fixture_rows_sha256` field uses the existing benchmark digest. Flatten
each pair's reference and current flow arrays in order into `Flows`. For cases
with a bound application, flatten their HTTP arrays in the same order into
`Application`. The Go test computes the digest from that JSON object.

## How the detector uses the inputs

The corpus exercises sustained volume, sampled observations, TCP flag
pressure, five UDP service associations, changing network signals, destination
spread, stable load, isolated spikes and incomplete observations. The flash
crowd and volume-pressure fixture share identical flow rows. For an explicitly
bound ingress host, the application plane determines whether independently
observed successful requests explain both byte and packet growth on the
configured TCP port and across the protected host. Pressure on other ports
can open an episode even during healthy growth on the bound service. If the
traffic outside that TCP listener stays flat or falls, the listener comparison
can explain growth across the host. Healthy response outcomes and comparable
latency are required for suppression. Missing or ambiguous bound evidence
leaves generic pressure unevaluated for alarm admission. A SYN or UDP
service association can qualify on its own flow evidence when its packet count
grows against the same historical vector and meets the configured share of
current packets.

Scheduled and preview assessments use a bounded projection of stored HTTP
server observations. The read applies the tenant, service, local TCP socket
and half-open start clock before its limit. A request can count once its span
has completed, including when its duration exceeds the start window's width.
Each window needs 20 to 16,383 matching original observations. The projection
keeps exact request counts, successful responses, p95 duration and an
observation digest. Overflow and a known partial window in the in-memory store
leave application evidence unavailable.

| Output field | Meaning |
| --- | --- |
| `fixture_manifest_sha256` | Exact corpus settings, trial parameters, clocks and independent labels |
| `fixture_rows_sha256` | Materialized flow and application observations at the original replay clocks |
| `case`, `label_positive` | Stable trial ID and independent synthetic event label |
| `class`, `service` | Opened episode class and observed UDP service when available |
| `abstained`, `demand_explained` | Coverage refusal or independently corroborated benign demand |
| `unrelated_pressure` | Traffic outside the selected TCP service exceeded the flow thresholds |
| `episode_delay_seconds` | Modeled seconds to an opened episode |
| `true_positive`, `false_positive`, `true_negative`, `false_negative` | Classified totals |
| `abstained_positive`, `abstained_negative` | Coverage refusals, reported independently by label |
| `onset_min`, `onset_p50`, `onset_p95`, `onset_max` | Modeled onset distribution across opened episodes |

## Published results

Two replays on Go 1.26.11 and an Apple M1 Max reproduced the original v2
manifest and all 416 trial outcomes. The local socket attributes changed the
materialized observation digest, which matched across both replays.
[Baseline revision](https://github.com/ctlplne/probectl/blob/a7b1997/docs/ddos-detection-benchmark.md)

| Measure | Result |
| --- | --- |
| Fixture manifest SHA-256 | `5aa5d0055e73fd3f76d8a65c849bd625ad314f06d8cbe20897a32cf97914c9f7` |
| Materialized observations SHA-256 | `1c9f7ffcd1484bd0ca02df73462edcd26b453ed55a993bfc61c3919d94abf1d2` |
| True positives / false positives | 208 / 0 |
| True negatives / false negatives | 80 / 16 |
| Abstained positives / abstained negatives | 48 / 64 |
| Modeled onset min / median / p95 / max | 10 s / 12 s / 14 s / 14 s |
| In-process runtime per 416-trial corpus | 52.19–94.43 ms across five runs |

The detector classified 304 of 416 trials. The 48 abstained positives bring
the number of positive trials without an opened episode to 64. All 16 matched
flash-crowd replays were corroborated as healthy demand. The low-intensity
controls account for the 16 classified misses. The positive abstentions
cover incomplete flow, unavailable application context and a mixed packet
profile outside the observed application demand. The two
separate-port pressure families still produced episodes.

The current replay uses the same scoped assessment as scheduled rules.
Its oracle expects an abstention for the 16 negative trials whose pressure
has fewer original records than the rule requires, and for the 16 positive
trials whose two flow windows report different sampling rates. The expected
totals are 192 true positives, 0 false positives, 64 true negatives, 16 false
negatives, 64 positive abstentions and 80 negative abstentions. The replay
prints the current manifest digest and measured totals.

For sampled windows, each reported rate needs the configured minimum number
of original records. A rule with required exporters checks the minimum for
each selected exporter and rate. Well-observed traffic at one rate cannot
supply missing records for a different estimate.

Version one used 13 trials and two completed 60-second windows. A benign
flash crowd opened a tentative volume episode on identical aggregates. Its
source and results remain reproducible at the original commit. [Version-one benchmark and results](https://github.com/ctlplne/probectl/blob/d79fc7993d09b3ce1d4e8242b7b5c869100d2537/docs/ddos-detection-benchmark.md)

## Protected service sensitivity holdout

Sixteen variants model the same 70% ingress growth with different original
volumes and HTTP request counts. The reference stays below 102,000 bytes
and 1,100 packets per five seconds. The surge carries 153,000–172,405 bytes
and 1,530–1,861 packets. The fixture compares the corpus thresholds with
service thresholds of 140,000 bytes and 1,400 packets per five seconds.

| Scenario | Result across 16 variants |
| --- | --- |
| Degraded service with the original benchmark thresholds | 16 below both floors |
| Degraded service with the tested service thresholds | 16 episodes in 10–14 modeled seconds |
| Same traffic with proportionate successful demand and healthy responses | 16 suppressed as explained demand |
| Same traffic with missing application observations | 16 abstentions |

These 64 comparisons are separate from the 416-trial corpus. [Sensitivity fixture](../internal/control/flow_ddos_sensitivity_test.go)

## Stable network background holdout

Two paired replays compare healthy HTTP growth on a shared host with equal
host-wide traffic in both tenants. Total packets rise from 2,500 to 3,100.
In one lane the dominant network vector stays at 1,900 packets and the
bound listener accounts for the increase. In the other lane that vector
grows to 2,300 packets and opens one episode with its original counters.
Both SYN flags and a UDP service association are exercised. The previous
detector opened an episode in both benign lanes. These trials run through
the saved-rule and receipt paths and are separate from the 416. [Paired datastore fixture](../internal/control/alert_ddos_application_pressure_integration_test.go)

The field-coverage replay uses the same totals and hides the previous week's
TCP flags or UDP source port on the 1,900 background packets. The earlier
detector counted the newly reported field as vector growth and fired in both
healthy controls. The corrected detector lets all 1,900 unclassified
historical packets count toward the possible previous vector. Both healthy
lanes stay quiet and both growing vectors still qualify. [Field-coverage fixture](../internal/control/alert_ddos_application_pressure_integration_test.go)

## Shared host and unrelated application outage holdout

The paired fixture stores identical host-wide totals of 290,000 bytes and
3,500 packets and identical HTTP failures for two tenants. In the first
tenant, the failed listener itself carries 210,000 bytes and 2,700 packets,
which meets the configured floors and growth threshold. It receives one
episode with the original listener counters. In the second, traffic on
the failed listener stays flat. Traffic on a different port increases while
remaining below both floors. That combination leaves aggregate pressure
ambiguous. [Paired scheduler fixture](../internal/control/alert_ddos_application_pressure_integration_test.go)

## Trace sampling holdout

The holdout starts with 24 recorded successful requests that represent 24
healthy requests. Flow and actual demand rise fourfold, while the trace
export retains 24 of the 96 current requests. The baseline opened a generic
pressure episode. The detector now reports incomparable application evidence
when the authorized span windows carry different known sampling thresholds.
Mixed coverage also leaves generic pressure unqualified. The paired datastore
fixture keeps both tenants' flow totals identical. Its tenant with comparable
sampling and actual HTTP degradation opens one scoped episode. The tenant
with changed sampling stays quiet and cannot access that receipt. These
holdouts are separate from the 416-trial corpus. [Synthetic holdout](../internal/control/flow_ddos_application_test.go) · [Paired datastore fixture](../internal/control/alert_ddos_application_pressure_integration_test.go)

## Representative reference holdout

The scheduled detector's separate holdout compares the same synthetic input
against both reference modes. Pressure in the previous week matches the
current traffic, so that single-week comparison has no growth. The
representative mode uses two adjacent windows from a quieter original week
and opens one episode. Its sibling stays quiet even with one historical week
missing. The receipt and incident report preserve the selected clocks. The
holdout is separate from the 416 benchmark trials.
[Selector holdout](../internal/anomaly/ddos_weekly_reference_test.go) · [Paired runtime fixture](../internal/control/flow_ddos_reference_integration_test.go)

## Concurrent rules holdout

An older fast rule holds one of two tenant query slots and waits on its
telemetry source. A second rule for a different protected host reads its own
stored flow windows and publishes an authorized episode while the first rule
is still waiting. A quiet sibling tenant completes its evaluation and cannot
read the other tenant's receipt. The serial baseline exceeded the fixture's
eight-second wait. The bounded two-worker pass produced a visible receipt in
0.22–0.25 seconds across two local runs. This measures progress within an already
started scheduler pass. A tenant configured for one concurrent query keeps
serial evaluation. [Paired scheduler fixture](../internal/control/alert_ddos_fast_integration_test.go)

A separate fixture holds one tenant's fast read open while a second tenant
completes an empty evaluation. After synthetic flow observations are stored
for the second tenant, its next poll publishes one scoped receipt. The
earlier scheduler stalled beyond eight seconds. The independent scheduler
published the receipt 2.27 seconds after storage while the first tenant still
held its query slot. The two-second polling cadence is subject to an eight-tenant
concurrency bound. A ten-tenant scheduling test verifies that waiting tenants
take free slots without waiting for another polling interval.
[Stalled tenant and slot-limit fixtures](../internal/control/alert_ddos_fast_integration_test.go) · [Ten-tenant check](../internal/control/alerteval_test.go)

## Exporter redistribution holdout

Two synthetic exporters observe the same protected host through a saved view.
The first tenant's aggregate grows from 3,600 to 7,200 packets in each
five-second comparison and opens one episode for DNS-associated UDP traffic.
The second tenant's two exporters swap their 400 and 3,200 packet counts.
Their combined total stays at 3,600 and no episode opens. Selecting only the
growing edge in the second tenant produces a local signal. An excluded third
exporter does not affect the result, and the sibling tenant cannot read the
first tenant's receipt. The fixture models complete flow observations at
both edges. [Synthetic redistribution fixture](../internal/control/alert_ddos_multi_edge_integration_test.go)

Run the holdout on the disposable PostgreSQL and ClickHouse integration stack.
[Integration stack setup](development.md#testing-layers)

```sh
PROBECTL_TEST_REQUIRE_SERVICES=1 go test -tags=integration -count=1 -v \
  -run '^TestFastDDoSSeparatesSyntheticEdgeRedistributionFromAggregateGrowth$' ./internal/control
```

## Shipped collector timing

Two two-tenant runs on macOS arm64 seeded synthetic prior-week references in
ClickHouse and sent synthetic IPFIX records through two enrolled `probectl-flow-agent`
processes at the default two-second flush interval. The protected host had
two qualifying five-second windows. The sibling tenant had one and opened no
episode. The issued receipt identified the original windows and was visible
only in the owning tenant.

| Measurement | Wall time across two runs |
| --- | --- |
| Second IPFIX record write to first raw query that returned it | 1.77–2.21 s |
| First IPFIX record write to first visible episode receipt | 10.40–10.64 s |
| Second window close to first visible episode receipt | 1.40–1.64 s |

The measurement includes collection, the broker, storage, the scheduler and
the authorized API. Its start clock is the synthetic export record sent to the
local collector. Exporter cache and flush delays are a separate measurement.
The current fixture runs the same checks at five- and ten-second cadences,
with a fresh tenant pair for each. The table records the five-second runs.
Use the disposable development stack with Dex for this test.
[Integration stack setup](development.md#testing-layers) · [Timing fixture](../internal/flow/ddos_wire_timing_integration_test.go)

```sh
PROBECTL_TEST_REQUIRE_SERVICES=1 go test -tags=integration -count=1 -v \
  -run '^TestFastDDoSMeasuresIPFIXRecordDeliveryThroughTheShippedIncident$' ./internal/flow
```

## Comparison scope

NETSCOUT documents Arbor Sightline monitoring by managed object using flow,
routing and device telemetry, with configured protection scopes. Radware documents DefensePro using learned traffic baselines and
multiple request characteristics to distinguish anomalous HTTPS load from
flash crowds. These are public capability descriptions. The probectl corpus
measures specific local detection behaviors. Vendor-equivalent accuracy and
latency require side-by-side measurement. [Arbor Sightline datasheet](https://www.netscout.com/sites/default/files/2022-05/NETSCOUT%20-%20Arbor%20Sightline.pdf) · [NETSCOUT on flow, routing and device context](https://ir.netscout.com/news/news-details/2018/NETSCOUT-Converts-Visibility-into-Operational-Insights/default.aspx) · [Radware HTTPS flood detection](https://support.radware.com/app/answers/answer_view/a_id/1030072/~/the-defensepro-https-flood-protection-module)

See the response runbook for configuring a short window, selecting authorized
application evidence and reviewing the resulting signals. [DDoS response runbook](ddos-response-runbook.md)

### Required exporter coverage

A protected rule or assessment can list up to eight required exporter IPs.
These addresses narrow the existing saved view. Each required exporter
needs an original flow observation for the protected population in each
compared window. An empty contribution leaves the comparison unavailable.
It can mean an exporter was quiet, late or absent. An unavailable window
cannot establish a healthy baseline, start an episode or end an existing
one. A representative reference requires three usable weekly candidates.

This option compares the stored population for addresses the operator already
authorized. Per-exporter presence is limited to these original records. Export completeness
and physical identity depend on the measurement point. A truncated or unauthoritative
capture remains unavailable. A successful assessment reports the count of
required exporters present in each cited window.

The paired holdout removes one exporter's 3,200 packets from the reference
and restores that exporter's ordinary contribution in the current window.
Without the explicit requirement, the saved rule sees apparent growth
from 400 to 3,600 and opens an episode. With the requirement, the comparison
is unavailable. The fully observed sibling still opens one episode for
3,600 to 7,200 packets and retains both exporter counts in its receipt.
The incomplete tenant cannot read the sibling's receipt.

```sh
PROBECTL_TEST_REQUIRE_SERVICES=1 go test -tags=integration -count=1 -v \
  -run '^TestFastDDoSRequiresOriginalExporterCoverage$' ./internal/control
```

[Paired synthetic fixture](../internal/control/alert_ddos_multi_edge_integration_test.go)


### Exporter sampling comparability holdout

For a rule or assessment with required exporters, each paired current and
reference window must contain the same set of reported sampling rates at
each exporter. A comparison with changed rates is unavailable. It leaves
the evaluation clock and any active episode in place. Representative
selection excludes a historical pair if either of its windows has
incomparable rates and still requires three comparable weeks. The check
uses the rates in the stored records. Changes to the underlying sampling
method or to a population sharing an exporter address may be invisible
when those records report the same rates. Five- and ten-second rules
without a required exporter list compare the reported rates and keep the
stored exporter identity for sampled groups. Their rate-one rows share an
exporter group after the original view filters are applied. Records with
no stored exporter identity share a sampled group for their reported rate.
A longer rule can require exporters to enable a per-exporter comparison.

The synthetic holdout keeps raw counts at 400 and 100 for two exporters.
Swapping the 1 and 8 multipliers raises the corrected aggregate from 1,200
to 3,300 packets with the same two rates present. The evaluation must
abstain with or without explicit exporter requirements. A paired tenant
keeps both exporters and their original rates,
while the corrected packet counts grow from 3,600 to 7,200. The positive
case must open one original receipt, which the sibling cannot read.
In the unpinned fixture, both exporters report one in eight in the current
window. The apparent total rises from 1,200 to 4,000 packets with the same
original counts. The rule abstains because the unsampled group disappeared.

```sh
PROBECTL_TEST_REQUIRE_SERVICES=1 go test -tags=integration -count=1 -v \
  -run '^TestFastDDoSRequiresComparable(RequiredExporter|DefaultExporter|Aggregate)Sampling$' ./internal/control
```

[Paired synthetic fixture](../internal/control/alert_ddos_multi_edge_integration_test.go)


### Sparse sampled window holdout

With reported flow sampling, both compared windows need the configured
minimum number of original records. The corrected byte and packet totals
still measure estimated volume. They cannot substitute for the original
sample count. A sparse current window leaves the evaluation clock and any
active episode in place. Representative selection considers the other
historical weeks when a sampled reference falls below that record minimum.

The synthetic holdout keeps 6,400 corrected packets in each window of an
ongoing episode. The exporter reports the same rate of one in eight
throughout. One window contains a single original record, below the
configured floor of four. The next two windows have four records each.
The evaluator must keep the original episode through the sparse window
and publish no duplicate when complete comparisons resume. A sibling with
steady, adequately sampled traffic stays quiet and cannot read the receipt.

```sh
PROBECTL_TEST_REQUIRE_SERVICES=1 go test -tags=integration -count=1 -v \
  -run '^TestFastDDoSKeepsEpisodeThroughAnUndersampledWindow$' ./internal/control
```

[Paired synthetic fixture](../internal/control/alert_ddos_sample_floor_integration_test.go)

### Incomplete timing during episode recovery

If any original exporter report crosses the start of a five- or ten-second
window, reports wholly inside that window must meet the rule's existing
minimum original record count before the detector accepts a quiet result.
The detector also checks that those reports cover the comparable sampling
groups. An incomplete window leaves the previous decision and its clock in
place.

The paired recovery fixture lowers traffic to its historical total for one
window of an active episode. Three of four reports cross the start, leaving
one contained report against a minimum of four. The sampled and unsampled
variants both require the episode to stay active. Qualifying traffic resumes
with four contained reports and the original receipt. The quiet sibling
cannot read that receipt. These cases use synthetic records and are separate
from the 416-trial corpus.

```sh
PROBECTL_TEST_REQUIRE_SERVICES=1 go test -tags=integration -count=1 -v \
  -run '^TestFastDDoSKeepsEpisodeThroughQuietTotalsFromCrossingIntervals$' ./internal/control
```

[Unit fixture](../internal/control/flow_ddos_timing_test.go) · [Paired fixture](../internal/control/alert_ddos_sample_floor_integration_test.go)

### Sustained pressure across a classification change

A five- or ten-second episode stays active when both adjacent windows
qualify on its protected scope and the classification changes between a
specific vector and general volume pressure. The original receipt keeps
its evidence. A new episode still requires two compatible findings.
Configured application context must qualify a volume finding before
either decision. A complete quiet comparison clears the active episode.

The paired synthetic holdout keeps corrected traffic steady at 6,400
packets per window after the episode opens. The second comparison shifts
from observed SYN pressure to general volume pressure. Later windows
return to SYN pressure. The original episode must keep one receipt, with
continued evaluation, and its quiet sibling must be denied that receipt.


### Continuing weekly growth holdout

A short-window rule with the representative weekly reference can see a
large difference from its chosen reference even when both bytes and
packets keep growing at the rates measured across four complete original
weeks. For flow-only general volume in that measured growth band, the
assessment requests independent corroboration, even when traffic reaches
more destinations within the protected prefix. It leaves the active
episode and clock in place. A sudden acceleration above the observed
band and independently qualifying network vectors still use their
original evidence. A rule with a bound application keeps its existing
cross-plane comparison.

A trend needs the original same-clock windows and sufficient raw
observations at both ends of every compared increase. Sampled traffic
requires named exporters with comparable reported sampling rates in
all five windows before this trend check can apply.

A separate holdout uses 240 independently labeled synthetic scenarios
and evaluates each in both reference modes. It includes matching flow
volumes and destination spread for benign traffic and concurrent pressure,
a new acceleration, and independently qualifying SYN pressure while
aggregate volume follows the trend. Missing or indistinguishable evidence remains an
explicit abstention. The original 416-trial corpus is independently
reproducible.

```sh
go test -count=1 -v -run '^TestSyntheticDDoSChangingWeeklyBaselineHoldout$' ./internal/control
PROBECTL_TEST_REQUIRE_SERVICES=1 go test -tags=integration -count=1 -v \
  -run '^TestWeeklyDDoSRequiresIndependentContextForAContinuingVolumeTrend$' ./internal/control
```

[Offline holdout](../internal/control/flow_ddos_weekly_holdout_test.go) · [Paired synthetic fixture](../internal/control/flow_ddos_reference_integration_test.go)
