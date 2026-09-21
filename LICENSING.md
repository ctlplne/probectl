# Licensing probectl

probectl is **source-available**. There are three source-license zones in one
repository, and the file path tells you which zone applies. Being able to read
a file grants no right to use it beyond what its zone's license says.

## Core: BUSL-1.1

All first-party source outside `ee/`, `pkg/`, `proto/` and `examples/` is
licensed under the **Business Source License 1.1** (`BUSL-1.1`) with the
parameters stated at the top of [`LICENSE`](LICENSE): the Licensor is certctl
LLC; the Additional Use Grant permits production use, with three limits (no
offering the core to third parties as a hosted or managed service, no embedding
it in a competing product, no circumventing the license-key functionality) and
one express carve-out (operating the core on a customer's own deployment as that
customer's service provider is permitted); the Change Date is four years after
each version is published; and the Change License is the Mozilla Public License
2.0. The complete, unmodified license is in [`LICENSE`](LICENSE).

The BSL is a source-available license, not an open-source license. ELI5: you
can read, build, change and run the core, including in production, at no charge
and without a signed license file; you cannot resell it as a hosted service or
build a competing product on it; and every published version becomes MPL-2.0
open source on its Change Date, automatically and without anyone's action.

## Client tree: MPL-2.0

`pkg/` (the public Go SDK), `proto/` (the wire contracts) and `examples/` are
licensed under the **Mozilla Public License 2.0** (`MPL-2.0`), reproduced in
full in [`LICENSE`](LICENSE) after the BSL. MPL-2.0 is a file-level copyleft.
ELI5: if you distribute a modified MPL-covered file, that file and its source
stay available under MPL-2.0; you may combine those files with separate open or
proprietary files in a larger work without relicensing those separate files.
That is the point of the split: client code can be embedded in your own
software, and other implementations can speak probectl's protocols, without
the core's use grant attaching to that software.

probectl does **not** attach the MPL Exhibit B notice. Client files are not
marked "Incompatible With Secondary Licenses" and keep the compatibility path
described by MPL section 3.3. This is a deliberate owner decision recorded for
counsel review; do not add Exhibit B to source headers.

## Commercial source: `ee/`

Files under [`ee/`](ee/) are **not** offered under the BSL or the MPL. They
carry `SPDX-License-Identifier: LicenseRef-Probectl-Commercial` and point to
the separate [`ee/LICENSE`](ee/LICENSE). That file is currently a
**DRAFT-FOR-COUNSEL skeleton**, not final commercial paper: separately executed
customer/reseller agreements control until counsel publishes the final text.
The source may be visible in this repository, but visibility alone does not
grant production, resale, or trademark rights. Production requires a valid
Enterprise/MSP agreement; resale additionally requires an MSP entitlement and
signed reseller agreement.

Commercial capabilities are also runtime-gated by an offline-verifiable signed
license. Runtime gating and source licensing are different layers: removing a
feature check does not change the commercial license, and license verification
never phones home. The one-way code boundary remains: `ee/` may import core;
core never imports `ee/`.

The runtime tiers are:

| Tier | Commercial capabilities |
|---|---|
| `core` | No `ee/` grants. |
| `enterprise` | FIPS artifact, BYOK, governance, guarded remediation, HA support/SLA, and siloed isolation. |
| `msp` | The complete Enterprise set plus provider-plane operations and local usage metering/export. The MSP resells under the probectl banner. |

`pricing_model` in a signed license is a reserved, informational field; only
the single feature table in `internal/license` grants code. No price list or
pricing model is published: commercial terms are set per agreement. MSP usage
reporting is an operator-run export from the self-hosted provider plane. It
never phones home.

## Contributions

Contributions use the [Developer Certificate of Origin 1.1](https://developercertificate.org/)
and must include a `Signed-off-by` trailer. By contributing to an existing file,
you submit the change under that file's license:

- core files and new first-party files outside `ee/`, `pkg/`, `proto/` and
  `examples/`: `BUSL-1.1`;
- files under `pkg/`, `proto/` and `examples/`: `MPL-2.0`;
- files under `ee/`: the commercial terms referenced by `ee/LICENSE`.

New core source should carry `SPDX-License-Identifier: BUSL-1.1` plus the
three-line BSL notice. New client-tree source should carry
`SPDX-License-Identifier: MPL-2.0` plus the MPL Exhibit A notice. New
commercial source should carry
`SPDX-License-Identifier: LicenseRef-Probectl-Commercial` and point to
`ee/LICENSE`. Generated and third-party files follow their generator or upstream
license; third-party notices are inventoried in [`NOTICE`](NOTICE) and
[`docs/third-party-licenses.md`](docs/third-party-licenses.md).

The reproducible header tool is `scripts/apply_license_headers.sh`; run it
with no argument to update the tree or with `--check` for the read-only CI
gate. It covers tracked `.go`, `.ts`, `.tsx`, and `.py` files outside `ee/`
and stamps the identifier of the zone each file sits in. The documented
exclusions are:

- third-party/build trees: any vendored, `dist` or `node_modules` directory;
- Protobuf output: `*.pb.go` / `*.pb.gw.go`;
- OpenAPI SDK output: `sdk.gen.go` / `sdk.gen.ts`;
- `bpf2go` output: `*_bpfel.go` / `*_bpfeb.go`.

Those generated files must be changed through their generator, not by stamping
the generated copy. `make license-header-gate` runs in both Go and Python lint
jobs, so a new hand-maintained source file without the notice of its zone
fails CI. `make editions-gate` separately checks every `ee/` file for its
commercial identifier + `ee/LICENSE` pointer and rejects that identifier from
core source. Its self-test plants a violation on each side of the boundary.

## Trademarks and legal review

Neither the BSL nor the MPL grants rights to the probectl name, logos, or other
trademarks. Finalizing the `ee/` commercial license skeleton, reseller terms,
DPA/MSA, and commercial open-data AUP review remain counsel-owned work. Those
pending documents do not make the core license provisional: core is BUSL-1.1
now, and each version's Change Date is fixed by its publication date.

This file explains the repository split; it is not a substitute for the license
texts or legal advice.
