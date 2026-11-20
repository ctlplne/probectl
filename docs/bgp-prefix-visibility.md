# BGP prefix visibility preview

Open **Planes → BGP → Public prefix visibility** to see how many eligible
collector peers observed an exact IPv4 or IPv6 prefix. The collector counts
each session once, including sessions that announce several ADD-PATH paths.
Origins show every observed AS and its peer count. A peer can contribute to
several origin counts when the source data is ambiguous.

The preview supports RouteViews archives. Its eligibility policy counts
distinct routes in each complete baseline and admits peers with at least
800,000 IPv4 or 150,000 IPv6 routes for that family. The measured proportion
describes the collector's eligible sample. Each point retains its denominator,
policy version, source clocks and both original compressed digests.

## Supply whole collector archives

Use one explicitly enabled fetch process on a host with access to the
published archive. The command issues an HTTPS request using only the
collector and the public archive clock. An accepted file is reusable on
subsequent runs. The control plane reads the same original archive once for
the selected local watch set and publishes each result through its own tenant
transaction.

```sh
probectl-control public-mrt-fetch -cache-dir /var/lib/probectl/public-mrt \
  -collector route-views.eqix -kind baseline -at 2026-10-01T00:00:00Z
probectl-control public-mrt-fetch -cache-dir /var/lib/probectl/public-mrt \
  -collector route-views.eqix -kind updates -at 2026-10-01T00:00:00Z
```

Fetch the collector's RIB at each two-hour UTC boundary and the associated
updates every 15 minutes after the publisher closes the file. Keep the
original and its `receipt.json` together when copying the cache to an
air-gapped deployment. The production reader verifies every file's original
digest. Configure an absolute cache directory and up to three collectors.
The supervisor reads the directory locally and waits five minutes past the
nominal end for each update file. Manage archive disk retention on the fetch
host and keep each in-use baseline and all of its updates together.

| Setting | Meaning |
| --- | --- |
| `PROBECTL_BGP_VISIBILITY_CACHE_DIR` | Absolute path to the sealed archive directory. |
| `PROBECTL_BGP_VISIBILITY_COLLECTORS` | Comma-separated RouteViews collectors, such as `route-views.eqix`. |

Both settings default to empty. The analyzer, tenant BMP receiver and separate
MRT evidence uploader have their existing configuration. RouteViews is run by
the University of Oregon RouteViews Project. For help with probectl, use its
operator support channel. [RouteViews collector archive reference](https://api.routeviews.org/docs/)

## Monitor a prefix

Viewing history requires `events.read`. Saving or removing a monitor requires
`alert.write`. Set an exact CIDR, a threshold from 0.01 to 100 percent and
the desired alert types. The collector's temporary gap, missing eligible
cohort and changed peer session explain points where counts are unavailable.
Zero visible peers appears only for an accepted observation with a known
eligible cohort.

A new threshold crossing or loss creates a tenant-scoped BGP incident signal
with the original collector, counts and digest. Replaying an accepted clock
preserves the original result. Historical replays beyond the recent alert
window populate history. Signals remain observational.

```sh
probectl --json bgp visibility-list
probectl --json bgp visibility MONITOR_ID
```

The OpenAPI spec and SDK describe `/v1/bgp/visibility`. The native MCP tool
`bgp_visibility_history` reads one monitor with current `events.read` and
`ai.query` authority. Leaving prior observations intact lets a reader compare
their original policy and source evidence.
