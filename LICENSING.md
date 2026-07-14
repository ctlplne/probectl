# Licensing probectl

probectl is an **open-core** project. There are two source-license zones in one
repository, and the file path tells you which zone applies.

## Core: MPL-2.0

All first-party source outside `ee/` is licensed under the **Mozilla Public
License 2.0** (`MPL-2.0`), unless a file explicitly identifies different terms.
The complete, unmodified license is in [`LICENSE`](LICENSE).

MPL-2.0 is file-level copyleft. ELI5: if you distribute a modified MPL-covered
file, that file and its source stay available under MPL-2.0. You may combine
those files with separate open or proprietary files in a larger work without
automatically relicensing those separate files.

probectl does **not** attach the MPL Exhibit B notice. The core therefore is not
marked “Incompatible With Secondary Licenses” and retains the compatibility
path described by MPL section 3.3. This is a deliberate owner decision recorded
for counsel review; do not add Exhibit B to source headers.

## Commercial source: `ee/`

Files under [`ee/`](ee/) are **not** offered under MPL-2.0. They are governed by
the separate commercial terms in [`ee/LICENSE`](ee/LICENSE). The source may be
visible in this repository, but visibility alone does not grant production,
resale, or trademark rights.

Commercial capabilities are also runtime-gated by an offline-verifiable signed
license. Runtime gating and source licensing are different layers: removing a
feature check does not change the commercial license, and license verification
never phones home. The one-way code boundary remains: `ee/` may import core;
core never imports `ee/`.

The runtime tiers are:

| Tier | Pricing model | Commercial capabilities |
|---|---|---|
| `core` | Free | No `ee/` grants. |
| `enterprise` | Flat-rate, self-hosted | FIPS artifact, BYOK, governance, guarded remediation, HA support/SLA, and siloed isolation. |
| `msp` | Consumption, self-hosted resale | The complete Enterprise set plus provider-plane operations and local usage metering/export. The MSP resells under the probectl banner. |

`pricing_model` in a signed license is informational (`flat` or
`consumption`); only the single feature table in `internal/license` grants code.
MSP usage reporting is an operator-run export from the self-hosted provider
plane. It never phones home.

## Contributions

Contributions use the [Developer Certificate of Origin 1.1](https://developercertificate.org/)
and must include a `Signed-off-by` trailer. By contributing to an existing file,
you submit the change under that file's license:

- core files and new first-party files outside `ee/`: `MPL-2.0`;
- files under `ee/`: the commercial terms referenced by `ee/LICENSE`.

New core source should carry `SPDX-License-Identifier: MPL-2.0` plus the MPL
Exhibit A notice. New commercial source should carry
`SPDX-License-Identifier: LicenseRef-Probectl-Commercial` and point to
`ee/LICENSE`. Generated and third-party files follow their generator or upstream
license; third-party notices are inventoried in [`NOTICE`](NOTICE) and
[`docs/third-party-licenses.md`](docs/third-party-licenses.md).

The reproducible core header tool is
`scripts/apply_license_headers.sh`; run it with no argument to update the tree
or with `--check` for the read-only CI gate. It covers tracked `.go`, `.ts`,
`.tsx`, and `.py` files outside `ee/`. The documented exclusions are:

- third-party/build trees: any `vendor/`, `dist/`, or `node_modules/` path;
- Protobuf output: `*.pb.go` / `*.pb.gw.go`;
- OpenAPI SDK output: `sdk.gen.go` / `sdk.gen.ts`;
- `bpf2go` output: `*_bpfel.go` / `*_bpfeb.go`.

Those generated files must be changed through their generator, not by stamping
the generated copy. `make license-header-gate` runs in both Go and Python lint
jobs, so a new hand-maintained core source file without the notice fails CI.

## Trademarks and legal review

MPL-2.0 does not grant rights to the probectl name, logos, or other trademarks.
The bespoke `ee/` commercial license, reseller terms, DPA/MSA, and commercial
open-data AUP review remain counsel-owned work. Those pending documents do not
make the core license provisional: core is MPL-2.0 now.

This file explains the repository split; it is not a substitute for the license
texts or legal advice.
