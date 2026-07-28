<!-- probectl-ai-handoff/v1; lang=en; dir=ltr -->
# probectl Ask investigation handoff

> **Point\-in\-time, non\-authoritative investigation note\. This file is a local copy of one tenant\- and RBAC\-scoped answer\. Evidence can age, permissions can change, and source records may be retained or deleted\. Re\-open probectl and re\-authorize every cited source before making a decision\.**

## Receipt

- **Contract:** ` probectl-ai-handoff/v1 `
- **Answer ID:** ` ans/incident #42 `
- **Tenant:** ` tenant-acme `
- **Question:** Why did checkout \*slow\* after \[change\]?
- **Confidence:** ` high `
- **Insufficient evidence:** no
- **Degraded fallback:** yes
- **Model:** ` builtin `
- **Reasoning adapter:** ` builtin `
- **Reasoning execution:** ` builtin_fallback `
- **Egress consent:** ` granted `
- **Attempted adapter:** ` openai:operator-model `
- **Suppressed causal claims:** 1

## Grounded root cause

> A BGP route change diverted checkout traffic through a congested transit\.

- **Citations:** [E1](#evidence-1)

## Grounded findings

1. The route changed before latency rose\.
   - **Citations:** [E1](#evidence-1), [E2](#evidence-3)
2. Checkout latency crossed the warning threshold\.
   - **Citations:** [E2](#evidence-3)

## Read-only investigation plan

1. Check the exact incident and its correlated signals\.
   - **Domain:** ` entities `
   - **Status:** ` queried `
   - **Read-only:** yes
   - **Limit:** 50
   - **Evidence count:** 2
   - **Truncated:** no
   - **Selector:** ` {"incident_id":"inc-42","target":"checkout.example"} `
   - **Node:** ` service:checkout `
   - **Window:** ` 2026-07-28T08:00:00Z — 2026-07-28T09:00:00Z `
2. Check change and routing events near the selected window\.
   - **Domain:** ` events `
   - **Status:** ` blocked `
   - **Read-only:** yes
   - **Limit:** 50
   - **Evidence count:** 0
   - **Truncated:** no
   - **Reason:** RBAC denied this read\.
3. Check bounded service metrics\.
   - **Domain:** ` metrics `
   - **Status:** ` skipped `
   - **Read-only:** yes
   - **Limit:** 25
   - **Evidence count:** 0
   - **Truncated:** yes
   - **Reason:** The source is not configured\.

## Evidence by plane

### bgp

<a id="evidence-1"></a>
#### E1 — Route changed for 192\.0\.2\.0/24

- **Domain:** ` entities `
- **Status:** ` critical `
- **Occurred at:** ` 2026-07-28T08:15:00Z `
- **Source:** ` bgp://event/route-42 `
- **Summary:** AS64501 announced a more\-specific route\.
- **Cited by:** root cause, finding 1
- **Fields:** ` {"as_path":[64500,64501],"origin_asn":64501,"prefix":"192.0.2.0/24"} `

### change

<a id="evidence-2"></a>
#### E3 — Deployment completed

- **Domain:** ` events `
- **Occurred at:** ` 2026-07-28T08:10:00Z `
- **Source:** not recorded
- **Summary:** The application deployment completed without an error\.
- **Cited by:** not recorded
- **Fields:** ` {"deployment":"checkout-2026-07-28.1","status":"succeeded"} `

### metrics

<a id="evidence-3"></a>
#### E2 — Checkout p95 latency

- **Domain:** ` metrics `
- **Status:** ` warning `
- **Occurred at:** ` 2026-07-28T08:17:30.123Z `
- **Source:** ` metric://checkout/p95 `
- **Summary:** p95 reached 940 ms &amp; remained elevated\.
- **Cited by:** finding 1, finding 2
- **Fields:** ` {"labels":{"service":"checkout","site":"blr-1"},"unit":"ms","value":940} `

## Limitations

> **This handoff is evidence, not live authoritative state, remediation approval, or permission to act\. Validate current telemetry, authorization, and operating context in probectl\.**
