#!/usr/bin/env python3
"""Claim-register checker (Foundation-Loop T-eb2b5d7c).

The docs-claims gate used to assert 19 enumerated honest-claim properties and
could not see a NEW claim that was never true. This checker generalizes it
into a rule over a machine-readable register (docs/claims/register.json):

  Direction A (declared -> real): every registered claim binds to (a) code
    paths that must exist and (b) proofs (a make target, a script, a test
    file, or a legacy selftest label) that must resolve. A binding whose
    target stops existing fails the gate.  Errors: REG-STALE-CODE,
    REG-BAD-PROOF, REG-STALE-SURFACE.

  Direction B (claim-shaped -> declared): every line in a governed surface
    that matches the capability grammar must be covered by a registered
    claim (pattern match x surface membership). A capability-shaped line in
    a new file, or a new claim family, fails until it is consciously
    registered and bound.  Error: REG-UNCOVERED.

  Direction C (register -> alive): every claim pattern must still match at
    least one line in each of its surfaces, so the register cannot rot into
    describing documents that no longer say what it sanctions.
    Errors: REG-STALE-PATTERN, REG-STALE-SURFACE.

  Grammar floor: the grammar lives in the register as data, but may only be
    EXTENDED. This checker refuses a grammar that no longer contains the
    hardcoded floor families, so the detector cannot be silently narrowed.
    Error: REG-GRAMMAR-FLOOR.

Known reach limit (deliberate, documented): inside a file already sanctioned
for a claim family, a new line reusing that family's phrasing rides the
existing binding. New files and new claim families are always caught; new
lines in sanctioned files are covered by the same code+proof binding the
file was reviewed under. docs/claims/README.md states this.

Exit 0 clean; exit 1 with one line per violation, prefixed by the error
class above so the shell selftest can assert exact failure shapes.
"""

import argparse
import glob
import json
import os
import re
import sys

# The grammar floor: removing any of these token classes from the register's
# grammar is refused. Extending the grammar is a data change.
GRAMMAR_FLOOR = [
    r"phone-home",
    r"call-home",
    r"air-gap",
    r"fail[- ]closed",
    r"tamper-evident",
    r"hash-chained",
    r"observe-only",
    r"human-gated",
    r"guarantees?",
    r"FORCE[- ]?RLS",
    r"separately audited",
    r"consent-gated",
]

EXEMPT_RE = re.compile(r"<!--\s*claim-exempt:\s*(\S.*?)\s*-->")


def err(errors, cls, msg):
    errors.append(f"{cls}: {msg}")


def load_register(path, errors):
    try:
        with open(path, encoding="utf-8") as f:
            reg = json.load(f)
    except (OSError, ValueError) as e:
        err(errors, "REG-BAD-REGISTER", f"cannot load {path}: {e}")
        return None
    ids = [c.get("id") for c in reg.get("claims", [])]
    if len(ids) != len(set(ids)):
        err(errors, "REG-BAD-REGISTER", "duplicate claim ids")
    for c in reg.get("claims", []):
        if not c.get("id") or not c.get("statement"):
            err(errors, "REG-BAD-REGISTER", f"claim missing id/statement: {c}")
        if not c.get("proof"):
            err(errors, "REG-BAD-PROOF", f"{c.get('id')}: no proof binding")
    return reg


def governed_files(root, reg):
    out = []
    for pat in reg.get("governed", []):
        out.extend(sorted(glob.glob(os.path.join(root, pat), recursive=True)))
    # de-dup, keep only files
    seen, files = set(), []
    for p in out:
        if os.path.isfile(p) and p not in seen:
            seen.add(p)
            files.append(p)
    return files


def check_grammar_floor(reg, errors):
    grammar = reg.get("grammar", "")
    for tok in GRAMMAR_FLOOR:
        if tok not in grammar:
            err(errors, "REG-GRAMMAR-FLOOR",
                f"grammar no longer contains floor family '{tok}' — the detector may only be extended")
    try:
        return re.compile(grammar, re.IGNORECASE)
    except re.error as e:
        err(errors, "REG-BAD-REGISTER", f"grammar does not compile: {e}")
        return None


def resolve_proof(root, driver, proof, errors, cid):
    kind, _, target = proof.partition(":")
    if kind == "selftest-label":
        if not os.path.isfile(driver):
            err(errors, "REG-BAD-PROOF", f"{cid}: driver script missing for {proof}")
            return
        body = open(driver, encoding="utf-8").read()
        # the label must be a planted-failure case in the driver's selftest
        if not re.search(rf"^\s*{re.escape(target)}\)", body, re.MULTILINE):
            err(errors, "REG-BAD-PROOF",
                f"{cid}: selftest label '{target}' has no planted-failure case in {os.path.basename(driver)}")
    elif kind == "make":
        mk = os.path.join(root, "Makefile")
        if not os.path.isfile(mk) or not re.search(
                rf"^{re.escape(target)}:", open(mk, encoding="utf-8").read(), re.MULTILINE):
            err(errors, "REG-BAD-PROOF", f"{cid}: make target '{target}' not defined")
    elif kind == "script":
        if not os.path.isfile(os.path.join(root, target)):
            err(errors, "REG-BAD-PROOF", f"{cid}: script '{target}' does not exist")
    elif kind == "test":
        path, _, func = target.partition("#")
        full = os.path.join(root, path)
        if not os.path.exists(full):
            err(errors, "REG-BAD-PROOF", f"{cid}: test path '{path}' does not exist")
        elif func:
            body = ""
            if os.path.isfile(full):
                body = open(full, encoding="utf-8", errors="replace").read()
            else:
                for g in glob.glob(os.path.join(full, "*_test.go")):
                    body += open(g, encoding="utf-8", errors="replace").read()
            if f"func {func}" not in body:
                err(errors, "REG-BAD-PROOF", f"{cid}: test func '{func}' not found under '{path}'")
    else:
        err(errors, "REG-BAD-PROOF", f"{cid}: unknown proof kind '{proof}'")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--register", default=None,
                    help="register path (default: <root>/docs/claims/register.json)")
    ap.add_argument("--driver", default=None,
                    help="shell driver whose selftest labels legacy proofs bind to "
                         "(default: <root>/scripts/check_docs_claims.sh)")
    ap.add_argument("--list-legacy", action="store_true",
                    help="print legacy property labels (kind=legacy-property) and exit")
    args = ap.parse_args()

    root = args.root
    register_path = args.register or os.path.join(root, "docs", "claims", "register.json")
    driver = args.driver or os.path.join(root, "scripts", "check_docs_claims.sh")

    errors = []
    reg = load_register(register_path, errors)
    if reg is None:
        print("\n".join(errors))
        return 1

    claims = reg.get("claims", [])

    if args.list_legacy:
        for c in claims:
            if c.get("kind") == "legacy-property":
                print(c["id"])
        return 0

    grammar = check_grammar_floor(reg, errors)

    # ---- Direction A: declared -> real -----------------------------------
    for c in claims:
        cid = c.get("id", "?")
        for p in c.get("code", []):
            if not os.path.exists(os.path.join(root, p)):
                err(errors, "REG-STALE-CODE",
                    f"{cid}: bound code path '{p}' does not exist — the claim lost its implementation")
        for p in c.get("surfaces", []):
            if not os.path.isfile(os.path.join(root, p)):
                err(errors, "REG-STALE-SURFACE", f"{cid}: surface '{p}' does not exist")
        for proof in c.get("proof", []):
            resolve_proof(root, driver, proof, errors, cid)

    # compile claim patterns
    compiled = []
    for c in claims:
        pat = c.get("pattern")
        if not pat:
            continue  # legacy property entries need no prose pattern
        try:
            compiled.append((c, re.compile(pat, re.IGNORECASE)))
        except re.error as e:
            err(errors, "REG-BAD-REGISTER", f"{c.get('id')}: pattern does not compile: {e}")

    # ---- Direction B: claim-shaped -> declared ---------------------------
    exempt_count = 0
    if grammar is not None:
        for path in governed_files(root, reg):
            rel = os.path.relpath(path, root)
            try:
                lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
            except OSError as e:
                err(errors, "REG-BAD-REGISTER", f"cannot read governed file {rel}: {e}")
                continue
            for i, line in enumerate(lines, 1):
                if not grammar.search(line):
                    continue
                m = EXEMPT_RE.search(line)
                if m:
                    exempt_count += 1
                    continue
                covered = any(
                    rel in c.get("surfaces", []) and rx.search(line)
                    for c, rx in compiled
                )
                if not covered:
                    err(errors, "REG-UNCOVERED",
                        f"{rel}:{i}: capability-shaped claim not covered by any registered claim: "
                        f"{line.strip()[:160]}")

    # ---- Direction C: register -> alive ----------------------------------
    for c, rx in compiled:
        cid = c.get("id", "?")
        for s in c.get("surfaces", []):
            full = os.path.join(root, s)
            if not os.path.isfile(full):
                continue  # already reported as REG-STALE-SURFACE
            body = open(full, encoding="utf-8", errors="replace").read()
            if not rx.search(body):
                err(errors, "REG-STALE-SURFACE",
                    f"{cid}: surface '{s}' no longer contains this claim — remove the surface or restore the claim")
        if c.get("surfaces") and not any(
                rx.search(open(os.path.join(root, s), encoding="utf-8", errors="replace").read())
                for s in c.get("surfaces", []) if os.path.isfile(os.path.join(root, s))):
            err(errors, "REG-STALE-PATTERN",
                f"{cid}: pattern matches nothing in any surface — the registered claim is no longer asserted anywhere")

    if errors:
        print("\n".join(errors))
        print(f"docs-claims-register: FAIL ({len(errors)} violation(s))", file=sys.stderr)
        return 1
    n_claims = len(claims)
    print(f"docs-claims-register OK ({n_claims} claims bound; {exempt_count} exempt line(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
