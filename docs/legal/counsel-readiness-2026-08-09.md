# probectl counsel-readiness packet — 2026-08-09

## Status and purpose

**Status: founder-prepared, non-authoritative, counsel approval required.**

ELI5: probectl is one product with two rooms. The core room is source-available
under BUSL-1.1 and becomes MPL-2.0 four years after each release; the SDK, wire
contracts and examples are MPL-2.0 today. The commercial room is visible in the
same building under `ee/`, but a
customer needs paid permission to operate it. This packet tells counsel exactly
where the walls are, how customers and MSPs are expected to use the product,
and which legal switches still need a lawyer.

Nothing in this file is an offer, a binding price, a warranty, or legal advice.
The current `ee/LICENSE` is a drafting skeleton. Until counsel publishes final
paper, commercial production and resale rights must come from separately
executed agreements.

## 1. Fixed product facts

Counsel should preserve these facts in every document:

| Topic | Locked product fact | Contract consequence |
|---|---|---|
| Brand | The product is **probectl**. No white-label or OEM identity replacement is offered. | MSPs may identify themselves as the managed-service operator, but the probectl name, tenant indicator, and provider-console separation remain visible. |
| Core license | All core source outside `ee/`, `pkg/`, `proto/` and `examples/` is BUSL-1.1 under the final root `LICENSE` (Licensor certctl LLC; production use permitted under the Additional Use Grant; Change Date four years after each version is published; Change License MPL-2.0). `pkg/`, `proto/` and `examples/` are MPL-2.0. | Customer terms must not restrict rights the customer already has under the BSL's Additional Use Grant or, for the client tree, under MPL-2.0. Counsel should validate the tree boundary, the service-provider carve-out and the distribution notices against the [BSL text](https://mariadb.com/bsl11/) and the [MPL](https://www.mozilla.org/en-US/MPL/2.0/). |
| Commercial boundary | Commercial implementation lives only under `ee/`. Core never imports `ee/`; CI checks the one-way boundary. | The commercial grant must cover only `ee/` and associated commercial artifacts. Source visibility is not a production or resale grant. |
| Deployment | The customer or MSP self-hosts. probectl does not offer a first-party public SaaS. | An uptime SLA cannot promise infrastructure the licensor does not operate. Support and software-warranty commitments should be separate from customer-operated availability. |
| Provider model | An MSP self-hosts one provider deployment for hard-isolated customer tenants under the probectl brand. | Resale requires an MSP entitlement plus a reseller agreement. Provider operators have no silent telemetry-read right. |
| Data posture | Product telemetry remains in the operator-controlled deployment unless the operator explicitly configures an export, remote AI provider, public feed, or support transfer. | The licensor is not automatically a processor merely because software is licensed; processing roles arise when the licensor actually receives or can access personal data. |
| Licensing mechanism | Entitlements are offline Ed25519-signed files; verification performs local math and does not contact the licensor. | Contract metering and audit language must not promise remote license reporting. Customer reporting or audit must be a contractual process. |
| Expiry | A 30-day grace banner is followed by read-only degradation of commercial configuration. Telemetry pipelines continue. | Order forms and the commercial license must match the implemented grace/read-only behavior and must not promise remote disablement. |
| Pricing | No price list or pricing model is published; rates are set per agreement. | The order form controls fees, currency, taxes and FX. |
| Remediation | Observe-only by default; any commercial remediation remains dry-run, human-approved, tenant/RBAC-scoped, blast-radius-limited, and audited. | Do not warrant autonomous prevention or describe probectl as an inline IPS. |
| External data | External feeds are optional, read-only, cached, and source-attributed. Rights differ by source. | Provider use must follow the source schedule; “public” is not equivalent to “commercially redistributable.” |

## 2. Recommended contract stack

One document should not do every job. Recommended stack:

1. **Root `LICENSE`** (BUSL-1.1 with its parameters for the core; MPL-2.0 for `pkg/`, `proto/` and `examples/`) governs first-party source outside `ee/`. Do not edit the license texts.
2. **Commercial source license** governs only `ee/`: review rights, licensed
   production use, modifications, copying, restrictions, term, termination, and
   survival.
3. **Master Software and Support Agreement (MSA)** governs commercial promises:
   payment, warranty, support, confidentiality, security, indemnity, liability,
   and dispute terms.
4. **Order form** records edition, deployment count, tenant band, support tier,
   term, fees, discounts, and any source-specific data rights.
5. **MSP/reseller addendum** grants the narrow third-party managed-service right,
   defines the end-customer chain, preserves probectl branding, and allocates
   first-line support.
6. **DPA plus security exhibit**, only where the probectl legal entity actually
   processes personal data. Self-hosting alone does not prove that role; support
   uploads or tenant-consented break-glass may create it.
7. **Trademark/brand guidelines** define permitted nominative and partner use,
   quality control, prohibited identity replacement, and termination cleanup.
8. **External-data schedule** attaches source-specific permissions and required
   attribution. The engineering draft is
   [`open-data-source-review-2026-08-09.md`](open-data-source-review-2026-08-09.md).

## 3. Recommended commercial-source terms

These are drafting instructions, not final clauses:

- **Grant:** non-exclusive, non-transferable, non-sublicensable except for the
  narrow MSP end-customer service right in an executed addendum; limited to the
  licensed deployment, feature set, tenant band, and term.
- **Source review:** permit viewing `ee/` for evaluation, security review, and
  interoperability review. Execution in an evaluation environment needs a
  written evaluation order.
- **Production modifications:** permit internal modifications during an active
  entitlement, retain notices, and make the customer responsible for its fork.
  No support obligation applies to a defect caused by its modification.
- **Distribution:** prohibit standalone distribution of `ee/`. An MSP may expose
  functionality only as part of its managed service and only under its addendum.
- **No implied rights:** repository access and bypassing a technical gate do not
  grant legal rights. Trademark, support, data, and reseller rights are separate.
- **Expiry:** codify the implemented 30-day grace and subsequent read-only state.
  Do not authorize telemetry destruction or remote kill behavior.
- **Verification:** allow reasonable records-based verification of deployment,
  tenant band, and billable peak agents. Because verification is offline, begin
  with annual certification and a narrowly scoped audit right, no more than once
  per year absent credible underpayment evidence.
- **Reverse engineering:** because the commercial source is visible, focus the
  restriction on circumvention, unauthorized production/resale, removal of
  notices, and competitive redistribution. Counsel should avoid language that
  is pointless, overbroad, or unenforceable in mandatory-law jurisdictions.

### Critical contributor-rights issue

The existing DCO proves that a contributor says they have the right to submit
under the target license; it does **not** assign copyright to the probectl legal
entity. Recommended near-term rule: accept external contributions to MPL core
under DCO, but accept `ee/` contributions only from founders, employees, or
contractors with written invention/IP assignment until counsel installs an
appropriate commercial CLA or other inbound-rights mechanism. Counsel must
decide whether modified `ee/` files remain customer-owned, are licensed back, or
are assigned; do not leave this ambiguous.

## 4. Recommended MSA and order-form positions

| Issue | Recommended starting position | Why |
|---|---|---|
| Contracting entity | Use the actual formed entity and registered address everywhere. If a US venture-financed path is intended but no entity exists, ask corporate/tax counsel whether a Delaware C-corporation is appropriate before publication. | A placeholder licensor cannot cleanly own IP, invoice, indemnify, or receive notice. |
| Term/payment | One-year initial term, annual prepay, net 30, renew only by signed renewal or explicit order-form auto-renewal. Fees exclude taxes. | Simple cash flow and no hidden evergreen term. |
| Price exhibit | None published. The order form states the fees for the edition, deployment count and tenant band it covers. | No price list or pricing model is published; the order form controls. |
| Acceptance | Software is accepted on delivery of credentials/artifacts unless an order form defines a short objective acceptance test. | Avoid subjective indefinite acceptance. |
| Software warranty | 30-day substantial-conformance warranty against published documentation; repair, workaround, or refund of affected prepaid fees as the exclusive remedy. | Bounded promise appropriate for self-hosted software. |
| Availability/SLA | No platform-uptime SLA for customer-hosted infrastructure. Offer support response objectives in a separate support schedule. | The licensor cannot control the customer's cluster, network, or cloud. |
| Support | Business-hours baseline; severity definitions, customer cooperation, supported versions, exclusions, and optional premium response times. | Separates support effort from product uptime. |
| Security | Commit to the documented architecture and a security exhibit, vulnerability handling, and reasonable safeguards; do not claim certifications not yet held. | Evidence-backed commitments survive diligence better than marketing absolutes. |
| Confidentiality | Mutual; standard exclusions; compelled-disclosure process; trade-secret protection while legally protected. | Covers customer diagrams/config and commercial source. |
| IP indemnity | Licensor defends third-party US IP claims for unmodified paid software, with replace/modify/refund remedies; exclude customer changes, combinations, instructions, continued use after notice, and MPL/core supplied by others. | Common allocation without insuring customer forks. |
| Customer indemnity | Customer covers its data, illegal use, unauthorized scans/probes, and customer/MSP promises beyond authorized materials. | The operator controls targets, data, and end-customer relationship. |
| Liability | Starting point: direct-damages cap equal to fees paid/payable in the prior 12 months; consider a 2× super-cap for confidentiality, security/DPA, and vendor IP indemnity; exclude indirect/consequential damages. Mandatory-law and intentional-misconduct carveouts remain counsel decisions. | Gives counsel a concrete negotiation posture without claiming universal enforceability. |
| Suspension | Only for security risk, material breach, or nonpayment after notice; prefer license/read-only contract remedies over interference with telemetry. | Matches the product's safety contract. |
| Governing law | If the licensor becomes a Delaware entity, start with Delaware law and Delaware state/federal venue; otherwise use the entity's home forum. | The forum must match a real entity and counsel strategy. |
| Publicity | No customer logo or case study without written opt-in. | No invented adoption evidence. |
| Export/sanctions | Customer represents lawful destinations/users; counsel determines encryption classification, screening, and required notices. | Cryptography and global MSP resale need jurisdiction-specific review. |

## 5. Recommended MSP/reseller addendum

ELI5: the MSP is the shopkeeper, but the product on the shelf still says
probectl.

- **Appointment:** non-exclusive, non-transferable right to provide a managed
  service within the licensed territory and tenant/agent bands.
- **Brand:** require “probectl” product identity. Permit a bounded formulation
  such as “Managed by MSP Name — powered by probectl,” subject to the brand
  guide. Prohibit product renaming, logo replacement, confusing domains, and
  implying that the MSP owns probectl.
- **Quality control:** require current supported releases, security patches,
  accurate product descriptions, trained administrators, and licensor review of
  materially changed brand uses. Trademark licensing needs real quality control,
  not a paper-only sentence.
- **End-customer terms:** MSP must contract with each tenant, obtain authority to
  process/observe its network data, pass through use restrictions and security
  prerequisites, and avoid restricting the tenant's MPL rights in core.
- **Data roles:** MSP is responsible for its controller/processor/service-provider
  relationship with end customers. The probectl licensor becomes involved only
  for data it actually receives or accesses.
- **Support split:** MSP owns L1/L2; licensor supplies L3 for supported versions.
  Define escalation package, redaction, authorization, severity, and hours.
- **No ambient access:** provider operators do not get silent access to tenant
  telemetry. Any break-glass workflow is explicit, time-bounded,
  tenant-consented, and separately audited.
- **Metering:** monthly peak active agents, tenant band, reporting date, dispute
  window, and records retention. No ingest-byte fee.
- **Commercial promises:** MSP cannot give warranties, indemnities, SLAs, or
  performance claims on the licensor's behalf unless attached to the order.
- **External data:** restricted/unknown sources remain disabled for commercial
  tenants until the MSP has written rights and records the applicable
  attribution/flow-down terms.
- **Termination:** stop new sales immediately, preserve a short orderly customer
  transition if paid and secure, remove marks, return/delete confidential
  material, and honor existing privacy/deletion duties.

## 6. Recommended privacy/DPA posture

### Role map

| Processing path | Likely role starting point | Required paper/control |
|---|---|---|
| Customer runs probectl with no licensor access | Customer or MSP determines its own controller/processor roles; licensor ordinarily receives no tenant telemetry | Product terms, privacy notice for the licensor's own account/billing data, and clear no-access statement |
| Customer sends a support bundle | Customer is controller; licensor may be processor/service provider for the submitted data | DPA, documented authorization, minimization/redaction, access limits, retention/deletion receipt |
| Tenant-consented break-glass | Role depends on purpose and customer/MSP chain; assume processing until counsel says otherwise | DPA/security exhibit, explicit tenant approval, time bound, separate audit record |
| Customer selects remote AI/export vendor | Customer contracts with and configures that vendor; probectl is the adapter | UI/config disclosure, vendor-specific DPA handled by customer unless probectl resells the service |
| Public website, sales, license issuance | Licensor is controller/business for contact, order, and licensing records | Public privacy notice, retention schedule, request workflow, cookie inventory |

When probectl is a processor, the DPA should include documented instructions,
confidentiality, security controls, subprocessors and notice, assistance with
rights requests and incidents, return/deletion, audit evidence, and the exact
processing annex. GDPR controller-processor requirements are anchored in
Article 28, security obligations in Article 32, and cross-border rules begin in
Chapter V of the [official regulation](https://eur-lex.europa.eu/eli/reg/2016/679/oj).
The European Commission publishes pre-approved [Standard Contractual
Clauses](https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/standard-contractual-clauses-scc_en)
for relevant transfers. California contracts should be checked against the
current service-provider/contractor requirements; the CPPA's final rules require
specific purposes and use/disclosure restrictions, not a generic “services”
label ([official regulations](https://cppa.ca.gov/regulations/consumer_privacy_act.html)).

Recommended operational defaults for counsel to encode where applicable:

- describe network identifiers, user identity, audit events, diagnostics, and
  uploaded artifacts as possible personal/customer data;
- process only the support purpose the customer authorized;
- no sale or behavioral-advertising use of customer data;
- 30-day advance subprocessor notice where practical;
- notify the customer without undue delay after confirming a covered incident,
  with a proposed outside target of 48 hours subject to counsel/insurance review;
- delete or return support data within 30 days after purpose/termination unless
  law requires retention, and provide a deletion receipt on request;
- use SCC modules selected by the actual exporter/importer roles rather than
  attaching every module blindly;
- offer documentary evidence first and a bounded customer audit only when that
  evidence is insufficient.

## 7. Recommended trademark/brand posture

The USPTO explains that a trademark identifies the source of goods or services;
registration scope depends on the actual goods/services, not ownership of a word
in every context ([Trademark basics](https://www.uspto.gov/trademarks/basics)).
Recommended counsel work:

1. clear the word mark and logo across federal, state, domain, company-name, and
   common-law sources before broad launch;
2. decide the owning legal entity and file in the appropriate software/service
   classes and filing basis;
3. use `TM` while appropriate and reserve `®` for a registered mark in the
   jurisdiction where used;
4. publish a brand guide covering spelling, logo assets, clear space, colors,
   screenshots, nominative references, partner lockups, domains, social handles,
   and termination cleanup;
5. require real quality control in every reseller trademark license;
6. state plainly that neither the BSL nor the MPL grants a trademark license and that probectl does
   not offer white-label identity replacement.

## 8. Counsel questions and recommended remediation

| ID | Question for counsel | Recommended remediation now |
|---|---|---|
| LEG-01 | What legal entity owns core copyright, `ee/`, and the probectl marks? | Complete founder/contractor IP assignments and use one exact entity name/address across notices and agreements. Do not publish a placeholder as licensor. |
| LEG-02 | Does DCO-only intake give the entity enough commercial rights in external `ee/` contributions? | Freeze external `ee/` contributions until counsel approves a CLA or other inbound-rights mechanism; continue DCO for MPL core. |
| LEG-03 | Does the `ee/` file boundary and build combination preserve the intended MPL obligations? | Counsel review the boundary, headers, build/linking, binary source-offer notice, and third-party inventory against MPL Sections 3.1–3.5. |
| LEG-04 | What source-review, evaluation, modification, and production grants are enforceable in target markets? | Finalize `ee/LICENSE`; keep source review narrow, make executed orders control production, and address mandatory reverse-engineering exceptions. |
| LEG-05 | Which warranty, indemnity, liability cap, and governing forum match entity/insurance/deal size? | Start from §4 positions; align with insurance and never promise customer-hosted uptime. |
| LEG-06 | What is the exact MSP contracting chain? | Draft MSA + MSP addendum + end-customer minimum terms; allocate L1/L2/L3, data roles, metering, taxes, and termination transition. |
| LEG-07 | When does support or break-glass make the licensor a processor/service provider? | Build a processing inventory from real support workflows; attach the DPA only to covered paths, never use “self-hosted” as a blanket exemption. |
| LEG-08 | Which SCC module, UK addendum, or other transfer mechanism applies? | Decide from actual entity locations, support access, subprocessors, and customer flow; complete transfer-impact review where required. |
| LEG-09 | Is the product name/logo clear and protectable? | Run professional clearance, file if advised, and publish the no-white-label brand guide with quality-control terms. |
| LEG-10 | Which encryption export classification and sanctions controls apply? | Counsel/export specialist classify binaries and license delivery; create denied-party/country screening and recordkeeping before global sales. |
| LEG-11 | Which public/open-data sources can be used in commercial MSP service? | Treat every `restricted`/`unknown` source as unavailable for resale until the rights holder or counsel supplies written coverage; attach the source schedule to each affected order. |
| LEG-12 | What privacy notice/cookie posture applies to the public site and sales/support tools? | Inventory actual tools before launch, keep optional analytics opt-in, publish a data-minimal notice, and do not claim zero collection where billing/support records exist. |

## 9. Red lines before the first paid MSP deployment

Do not proceed on the strength of this packet alone. Before a paid MSP serves an
end customer, counsel should deliver or approve:

- exact entity/IP ownership chain;
- final `ee/LICENSE` and commercial notices;
- MSA, order form, MSP/reseller addendum, and support schedule;
- applicable DPA/security exhibit and privacy notice;
- trademark clearance and partner brand guide;
- export/sanctions posture;
- source-by-source written rights for every enabled `restricted` or `unknown`
  feed;
- a negotiation playbook identifying fallback positions and who may approve
  deviations.

## 10. Packet to hand counsel

Send these repository files together:

- `LICENSE`, `NOTICE`, `LICENSING.md`, `CONTRIBUTING.md`, and `ee/LICENSE`;
- `docs/editions.md`, `docs/pricing.md`, and `docs/pricing/tco-calculator.md`;
- `docs/security/tenant-isolation.md`, `docs/hardening.md`,
  `docs/data-retention.md`, `docs/runbooks/tenant-offboarding.md`, and
  `docs/security/incident-response.md`;
- `docs/provider-plane.md`, `docs/remediation.md`, and
  `docs/incident-evidence.md`;
- this file, `counsel-checklist.json`, and the open-data source review;
- the current third-party software inventory in `NOTICE` and
  `docs/third-party-licenses.md`.

The intended output from counsel is not “looks fine.” Ask for redlines, final
templates, a one-page deviation matrix, and a signed decision on each `LEG-*`
row.
