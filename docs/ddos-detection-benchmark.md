# Synthetic DDoS detection benchmark

Run from a clean probectl source checkout with the Go toolchain declared in
`go.mod`.

```sh
git rev-parse HEAD
go version
go env GOOS GOARCH
go test -count=1 -v -run '^TestSyntheticDDoSDetectionBenchmark$' ./internal/control
GOMAXPROCS=2 go test -run '^$' -bench '^BenchmarkSyntheticDDoSDetection$' -benchmem -count=5 ./internal/control
```

The version-one fixture is declared in
[`flow_ddos_benchmark_test.go`](../internal/control/flow_ddos_benchmark_test.go).
It consists of 13 independent trials with two adjacent completed 60-second
observations and each window's same-UTC reference from the previous week. The
fixture declares traffic aggregates and deterministic row materialization for
the documentation prefix `192.0.2.0/24`. The separately declared label oracle
supplies evaluation labels. All replay stays in memory and opens no sockets.

The build exercises the same row projection, detector and two-window
episode evaluation used by saved-view alerting. The elapsed observation time
starts at the first modeled current window. The timing command measures
in-process generation, projection, classification and episode evaluation
over the 13 trials. It reports nanoseconds and allocations per full corpus
iteration. Storage queries, ingestion, scheduler delay, and notification
delivery are outside this measure.

The accuracy command emits three types of records in its Go test log.

| Field | Meaning |
| --- | --- |
| `fixture_manifest_sha256` | Digest of the deterministic corpus parameters, clocks, detector settings, and labels |
| `fixture_rows_sha256` | Digest of the materialized flow rows in replay order |
| `case` | Stable version-one trial name |
| `label_positive` | Synthetic event oracle label |
| `class` | Episode class or empty for no episode |
| `service` | Observed UDP service association, when available |
| `abstained` | An incomplete observation prevented assessment |
| `episode_delay_seconds` | Modeled time from the first current window to an episode, or zero when no episode opens |
| `true_positive`, `false_positive`, `true_negative`, `false_negative` | Classified case totals |
| `abstained_positive`, `abstained_negative` | Unavailable cases by oracle label |

## Version-one results

The Go 1.26.11 run on macOS arm64 reproduced both corpus digests on two
independent executions.

- Manifest SHA-256 `253cce51b168824e4f82c5b9e0b6b0f2295283158823159b3c4a0f88ffa39500`.
- Materialized rows SHA-256 `7922db20097553c399aad58de9eef26fff3c901f0a5f2baecfaad250fc4ce315`.

| Result | Trials |
| --- | --- |
| True positives | 2 volume, including sampled input, 1 TCP SYN, 1 suspected UDP reflection, 1 distributed destination |
| False positive | 1 benign flash crowd classified as volume pressure |
| True negatives | 4, covering stable traffic, one elevated window, the observation floor and differing consecutive vectors |
| False negative | 1 low-intensity case below the configured floors |
| Abstentions | 1 positive and 1 benign case with incomplete coverage |

Precision was 5/6. Recall was 5/6 among classified positive trials and 5/7
when counting the abstained positive in the denominator. The detector
abstained on 2/13 trials. Every episode opened at 120 seconds of modeled
observation. The Apple M1 Max run with two Go workers measured 0.232–0.235
ms per iteration of all 13 trials across five runs. Each iteration
allocated roughly 194 kB in 4,966 allocations.

The flash crowd deliberately has the same observed aggregates as the
volume-pressure case. Both produce the same episode class. The fixture
reports accuracy only for these 13 cases and the checked-in thresholds.
Deployment false-alarm rates and attack attribution require separate data.

The observed UDP service association carries the same evidence limit as
the shipped response workflow. See the
[DDoS response runbook](ddos-response-runbook.md).
