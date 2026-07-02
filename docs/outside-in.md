# Owned outside-in monitoring

Outside-in monitoring means testing a service from places that act like users,
partners, branch offices, cloud regions, or customer networks. A vendor-owned
global probe fleet sells those places as a managed service. probectl takes the
replacement path: **owned vantages**. You run the probes, you choose the sites,
and the results stay inside your tenant.

The useful mental model is a fire alarm panel with labeled rooms. A probe is a
smoke detector, a **vantage** is the room where it is mounted, and the coverage
map tells you which rooms actually have detectors. If you have no detector in
Tokyo, probectl does not imply Tokyo is covered.

## The replacement motion

| Managed-SaaS pattern | probectl owned-vantage pattern |
|---|---|
| Vendor-owned probe fleet | Customer/MSP-owned `probectl-agent` fleet, enrolled into the buyer's tenant over mTLS |
| Vendor data custody | Tenant telemetry stays in the buyer-owned or MSP-owned control plane |
| Vendor-defined locations | Operator-defined site and region labels, tied to business geography |
| Consumption pricing by test volume | Fixed license / Provider/MSP tenant band; usage counters support fairness, capacity planning, showback, and MSP tenant reporting |
| Black-box internet weather | `/v1/outages` joins your vantages with opt-in public outage data and says what is not covered |

This is the ThousandEyes-style job, but with a different trust boundary. probectl
does not operate a global probe fleet, and that is intentional. It beats the
managed-service model when the buyer values custody, fixed economics, and MSP
resale more than renting someone else's worldwide vantage estate.

## Label model

Every owned vantage should carry a small, consistent label set. The agent's
tenant and agent id come from its certificate and registry row; the labels below
are the operator naming convention used in configs, test names, A2A mesh inputs,
and coverage reports.

| Label | Example | Why it matters |
|---|---|---|
| `site` | `iad-branch-07`, `lon-dc-1` | The human-place name: where this agent sits. |
| `region` | `us-east`, `eu-west`, `ap-south` | Roll-up for maps, SLOs, and incident scope. |
| `network_role` | `branch`, `dc`, `cloud`, `partner`, `customer-edge` | Separates user-path probes from backbone or partner probes. |
| `provider` | `aws`, `azure`, `gcp`, `onprem`, `isp-comcast` | Explains which underlay owns the path. |
| `residency` | `us`, `eu`, `in` | Helps regulated tenants prove where vantage telemetry originates. |

For A2A, the served API already accepts site-labeled agents:

```json
POST /v1/a2a/mesh
{
  "mode": "tcp",
  "count": 5,
  "agents": [
    {"agent_id": "iad-branch-07", "site": "iad-branch-07"},
    {"agent_id": "lon-dc-1", "site": "lon-dc-1"},
    {"agent_id": "aws-use1-edge", "site": "aws-use1"}
  ]
}
```

The tenant is still the authenticated caller's tenant, never a body field. Site
labels shape the matrix; they do not create a security boundary.

## Coverage map

The coverage map is the part that keeps the story honest. It answers three
questions:

1. Which regions and sites have at least one enrolled canary agent?
2. Which probe packs run from each site?
3. Which important targets have at least two independent vantages?

Use this minimum table in runbooks and buyer reviews:

| Region | Site | Agent id | Probe packs | Targets covered | Gap |
|---|---|---|---|---|---|
| `us-east` | `iad-branch-07` | `iad-branch-07` | `edge-http`, `dns-public`, `voice-rtp` | checkout, login, dns, voip | none |
| `eu-west` | `lon-dc-1` | `lon-dc-1` | `edge-http`, `dns-public`, `a2a-mesh` | checkout, login, dns, site mesh | no voice reflector |
| `ap-south` | `_none_` | `_none_` | `_none_` | `_none_` | uncovered; do not claim APAC outside-in coverage |

The rule is blunt: a row with `_none_` is a known blind spot, not a green cell.
The `/v1/outages` response follows the same honesty rule with coverage notes:
coverage is your vantage points plus public open data, not a vendor-owned global
fleet.

## Probe-pack templates

A **probe pack** is a repeatable bundle of canaries that every owned vantage in a
class should run. It is not a new runtime primitive; it is an operating pattern
over the served `probectl-agent` config and `probectl test create` surface.

### `edge-http`

Purpose: prove user-facing service availability and phase timing from every
site.

```yaml
canaries:
  - type: http
    target: "https://checkout.example.com/health"
    interval: 30s
    timeout: 10s
    params:
      method: "GET"
      expect_status: "2xx,3xx"
      follow_redirects: "true"
  - type: browser
    target: "https://checkout.example.com/login"
    interval: 60s
    timeout: 10s
    params:
      script: '{"name":"login","start_url":"https://checkout.example.com/login","steps":[{"action":"goto"},{"action":"assert_status","status":200}]}'
```

### `dns-public`

Purpose: separate resolver trouble from service trouble.

```yaml
canaries:
  - type: dns
    target: "checkout.example.com"
    interval: 30s
    timeout: 5s
    params:
      type: "A"
      transport: "udp"
      dnssec: "true"
  - type: dns
    target: "checkout.example.com"
    interval: 60s
    timeout: 5s
    params:
      mode: "trace"
```

### `a2a-mesh`

Purpose: measure site-to-site path quality between owned locations.

```json
POST /v1/a2a/mesh
{"mode":"udp","count":10,"agents":[
  {"agent_id":"iad-branch-07","site":"iad-branch-07"},
  {"agent_id":"lon-dc-1","site":"lon-dc-1"},
  {"agent_id":"aws-use1-edge","site":"aws-use1"}
]}
```

### `voice-rtp`

Purpose: catch quality issues that plain ping hides.

```yaml
canaries:
  - type: voice
    target: "voice-echo.example.com:5004"
    interval: 60s
    timeout: 3s
    params:
      codec: "g711"
      duration_seconds: "3"
      dscp: "46"
```

## Outside-in plus internet weather

Owned probes tell you what your users see. Public outage feeds tell you what
public observatories see. probectl joins those at `GET /v1/outages`:

- `vantage_events` come from the tenant's own synthetic-result stream.
- `events` come from opt-in public feeds, ingested once and shared as public
  reference data.
- `affected_tests` are tenant-scoped joins between those two worlds.
- `coverage_notes` state when feeds or ASN/geo scope resolution are off.

Outbound public feeds remain off by default:

```sh
export PROBECTL_OUTAGE_FEEDS_ENABLED=true
export PROBECTL_FLOW_ENRICH_ASN=true
```

That keeps the default no-phone-home posture intact. Turning feeds on is an
operator decision, and a failed feed degrades to stale/labeled context instead of
breaking core monitoring.

## MSP resale pattern

For an MSP, the product shape is:

1. The MSP self-hosts probectl Provider/MSP edition.
2. Each customer is a tenant with its own enrolled vantages and tenant-scoped
   tests.
3. The MSP can export usage for showback or its own invoice, but probectl's
   product unit remains the fixed annual tenant-band license.
4. Usage counters are not probectl billing units.
5. White-label branding can make the tenant portal feel native to the MSP
   without changing where telemetry lives.

The rule is **no vendor-managed shared probe pool** that silently mixes
customers' data. If an MSP wants pooled infrastructure, the pool is still MSP-owned,
tenant-isolated, audited, and priced by tenant band rather than test volume.

## Proof checklist

Use these checks before claiming outside-in coverage:

- At least two owned vantages exist for each critical target or the coverage map
  names the gap.
- `GET /v1/results/latest` shows fresh results for every probe pack.
- `POST /v1/a2a/mesh` succeeds for the sites that should be mesh-tested.
- `GET /v1/outages` returns coverage notes, and those notes are copied into the
  operations review.
- `docs/pricing.md` still says Provider/MSP is a fixed annual tenant-band
  license and usage counters are not probectl billing units.
- Public outage feeds are either off by default or explicitly enabled by the
  operator with source/AUP review.

## Source map

- Active and synthetic testing: [`features/active-testing.md`](features/active-testing.md)
- Internet outage view: [`features/open-data-and-outage.md`](features/open-data-and-outage.md)
- Agent deployment: [`deploying-agents.md`](deploying-agents.md)
- Provider/MSP plane: [`provider-plane.md`](provider-plane.md)
- Fixed-license pricing: [`pricing.md`](pricing.md)
- Buyer memo: [`buyer-memo.md`](buyer-memo.md)
