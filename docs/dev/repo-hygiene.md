# Repo hygiene

A few rules about what is allowed to live in the git history. The theme: the
repository holds **source, never build output and never secrets**. Both rules are
enforced by CI, so a violation is caught on push, not at audit time.

## No build artifacts are tracked

`git ls-files` contains no compiled binaries and no coverage files — only source.

[`.gitignore`](../../.gitignore) keeps it that way: it ignores `/bin/` (where
`make build` puts every binary), the stray root-level binaries a manual
`go build` can drop (`/probectl`, `/probectl-control`, `/probectl-agent`,
`/probectl-ebpf-agent`, `/probectl-endpoint`), and coverage output (`*.out`,
`*.test`, `*.coverprofile`, plus the `coverage.txt` / `coverage.out` /
`coverage.html` / `coverage.xml` family).

So if you see a large `./probectl-control` after building, that is a normal,
**untracked** local artifact — not something that got committed. (Tip: send build
output to `/bin/` by using `make build` rather than a bare `go build` at the repo
root.)

Why: shipped binaries are rebuilt reproducibly from source at release time (see
[`../releasing.md`](../releasing.md)); committing them just bloats the clone and
invites "which binary is this, really?" questions. Coverage files are
per-run noise.

## No secrets, ever

This is a hard guardrail: credentials, tokens, and private keys never enter the
repo or its history.

How it's enforced: the `secret-scan` CI job
([`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)) runs
[gitleaks](https://github.com/gitleaks/gitleaks) — a scanner that
pattern-matches text for anything *shaped* like a credential — over every
reachable commit on every push to `main` and every pull request. The checkout is
full-depth, and `scripts/check_secret_scan_history.sh` runs `gitleaks git
--log-opts=--all`, so a key that was committed and then deleted still fails the
gate.

The only strings it tolerates are the *deliberately fake* secrets inside
redaction/encryption tests — allow-listed in
[`.gitleaks.toml`](../../.gitleaks.toml) by the test files' paths — plus named
false positives and exact historical documentation/test-fixture entries that
were already removed or redacted. Nothing real, and never a real credential
path.

There is no real key material anywhere in the tree, including in tests. For
example, the mock OIDC identity provider used in tests **generates its signing
key at test setup** (`internal/crypto.GenerateRSAKeyPEM`) instead of reading a
committed key file. A test that needs a key makes one on the spot; the repo never
has to hold one.

## History

Published history is not rewritten, and a release can only be cut from a
commit that passed CI: the release workflow's `require-green-ci` job looks up
the `ci` run for the exact tagged commit and refuses to build anything if it
isn't green (see [`../releasing.md`](../releasing.md)). If a fresh clone looks
bloated from dangling objects, that is the cloner's `git gc` to run — not a
defect in the repository.
