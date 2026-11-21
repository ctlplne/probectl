# Synthetic DDoS detection benchmark

Run from a clean probectl checkout with the Go toolchain in `go.mod`.

```sh
git rev-parse HEAD
go version
go env GOOS GOARCH
go test -count=1 -v -run '^TestSyntheticDDoS(DetectionBenchmark|ProtectedServiceSensitivity)$' ./internal/control
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
Use the disposable development stack with Dex for this test.
[Integration stack setup](development.md#testing-layers) · [Timing fixture](../internal/flow/ddos_wire_timing_integration_test.go)

```sh
PROBECTL_TEST_REQUIRE_SERVICES=1 go test -tags=integration -count=1 -v \
  -run '^TestFastDDoSMeasuresIPFIXRecordDeliveryThroughTheShippedIncident$' ./internal/flow
```

## Comparison scope

NETSCOUT documents Arbor Sightline monitoring by managed object using flow,
routing and device telemetry, along with configured filters and threat-feed
context. Radware documents DefensePro using learned traffic baselines and
multiple request characteristics to distinguish anomalous HTTPS load from
flash crowds. These are public capability descriptions. The probectl corpus
measures specific local detection behaviors. Vendor-equivalent accuracy and
latency require side-by-side measurement. [Arbor Sightline architecture](https://www.netscout.com/sites/default/files/2020-09/SECJTF_003_EN-2001%20-%20Arbor%20Sightline%20-%20How%20It%20Works.pdf) · [Radware HTTPS flood detection](https://support.radware.com/app/answers/answer_view/a_id/1030072/~/the-defensepro-https-flood-protection-module)

See the response runbook for configuring a short window, selecting authorized
application evidence and reviewing the resulting signals. [DDoS response runbook](ddos-response-runbook.md)
