# Claim register

`register.json` is the machine-readable inventory of every capability claim
the product makes in a governed surface, bound to the code that implements
the claim and the gate or test that proves it. It exists so that a claim can
never again be added to the docs without anyone deciding whether it is true.

Enforced by `scripts/claims_register_check.py`, driven from
`scripts/check_docs_claims.sh` (locally via `make docs-claims-gate`, inside
`make lint`, and in CI).

## How it works

- **Governed surfaces** (`governed`): README, both PRDs, SECURITY,
  LICENSING, CONTRIBUTING, everything under `docs/`, and the web UI copy
  catalog (`web/src/i18n/messages.ts`).
- **Grammar** (`grammar`): a regex describing claim-shaped language — the
  promise families the product is loudest about (default-egress posture,
  sealed-audit properties, remediation posture, tenancy enforcement layer,
  measured-number honesty, and so on). The grammar may only be *extended*:
  the checker refuses a grammar that loses one of its hardcoded floor
  families, so the detector cannot be quietly narrowed.
- **Claims** (`claims[]`): each entry binds
  - `pattern` — the sanctioned phrasing family,
  - `surfaces` — the files sanctioned to assert it,
  - `code` — paths that must exist for the claim to be about something real,
  - `proof` — one or more of `make:<target>`, `script:<path>`,
    `test:<path>[#Func]`, `selftest-label:<label>`, each of which must
    resolve.

Every grammar-matching line in a governed surface must be covered by some
registered claim (pattern match × surface membership). Every registered
binding must stay real. Both directions are checked on every run, and the
SELFTEST plants each failure shape and proves the gate reports it.

## Adding or changing a claim

1. Write the docs sentence.
2. If the gate reports `REG-UNCOVERED`, you have made a capability claim.
   Decide whether it is true. If it is, add or extend a register entry:
   surface, pattern, the implementing code paths, and the proof that keeps
   it true. If it is not true, do not write the sentence.
3. A line that matches the grammar without making a product claim can carry
   an inline `<!-- claim-exempt: <reason> -->` marker; the reason is
   mandatory and exempt counts are printed on every run.

Entries of kind `legacy-property` are the migrated DOCS-S01..S19 + SEC-004
honest-claim assertions; their proof is the planted-failure selftest in
`check_docs_claims.sh`, and the selftest's label list is read from this
register, so retiring one is visible on both sides.

## Reach limits (deliberate, known)

- Inside a file already sanctioned for a family, a new line reusing that
  family's phrasing rides the existing binding — it is covered by the same
  code+proof the file was reviewed under. New files and new phrasing
  families are always caught.
- The grammar is a floor, not a census of English. A capability claim
  phrased entirely outside the grammar is invisible to direction B until
  the grammar is extended (extension is a data change plus floor entry).
- Bindings prove existence and wiring of the named artifacts, not their
  semantics; semantic proof lives in the bound tests and gates themselves.
